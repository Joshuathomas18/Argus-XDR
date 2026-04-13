"""
Threat analysis routes for Argus XDR.
Endpoints for querying threat context and analyzing security alerts.
"""

import logging
from typing import Dict, Any, List, Optional

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field

from backend.rag.retriever import retrieve_threat_context, query_security_knowledge
from backend.core.database import get_node_by_id, get_connected_nodes, query_nodes


logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/threats", tags=["threats"])


# ============================================================================
# Pydantic Models
# ============================================================================


class ThreatAnalysisRequest(BaseModel):
    """Request for threat analysis."""

    query: str = Field(..., description="Natural language query about threat")
    include_topological: bool = Field(
        True, description="Whether to include graph topology in analysis"
    )
    top_k: int = Field(5, ge=1, le=20, description="Number of results to return")


class ThreatAnalysisResponse(BaseModel):
    """Response for threat analysis."""

    threat_id: str
    risk_score: float
    description: str
    related_entities: List[Dict[str, Any]]
    recommended_actions: List[str]


class GraphNodeResponse(BaseModel):
    """Response for graph node query."""

    node_id: str
    entity_type: str
    name: str
    value: str
    neighbors: List[Dict[str, Any]]
    frequency: int


class KnowledgeQueryResponse(BaseModel):
    """Response for knowledge base query."""

    entries: List[Dict[str, Any]]
    total: int


# ============================================================================
# Threat Analysis Endpoints
# ============================================================================


@router.post(
    "/analyze",
    response_model=Dict[str, Any],
    status_code=status.HTTP_200_OK,
)
async def analyze_threat(request: ThreatAnalysisRequest) -> Dict[str, Any]:
    """
    Analyze a security alert using hybrid retrieval.

    Process:
    1. Call retriever.retrieve_threat_context() for hybrid search
    2. Query knowledge base for relevant patterns
    3. Return risk assessment and recommended actions

    Args:
        request: Threat analysis request with query

    Returns:
        dict: Threat analysis results including risk score and recommendations
    """
    if not request.query:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Query cannot be empty",
        )

    try:
        # Retrieve threat context using hybrid search
        logger.info(f"Analyzing threat: {request.query}")

        threat_context = retrieve_threat_context(
            query=request.query,
            k=request.top_k,
            include_topological=request.include_topological,
        )

        # Query knowledge base
        knowledge = query_security_knowledge(
            query=request.query,
            k=request.top_k,
        )

        # Calculate risk score based on context and knowledge
        risk_score = calculate_risk_score(threat_context, knowledge)

        # Generate recommendations
        actions = generate_recommended_actions(threat_context, knowledge, risk_score)

        return {
            "threat_id": "threat_" + request.query.replace(" ", "_")[:20],
            "query": request.query,
            "risk_score": risk_score,
            "risk_level": get_risk_level(risk_score),
            "retrieved_context_count": len(threat_context),
            "knowledge_matches": len(knowledge),
            "context": threat_context,
            "related_knowledge": knowledge,
            "recommended_actions": actions,
        }

    except Exception as e:
        logger.error(f"Threat analysis failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Threat analysis failed: {str(e)}",
        )


@router.get(
    "/patterns/{threat_id}",
    response_model=Dict[str, Any],
    status_code=status.HTTP_200_OK,
)
async def get_threat_patterns(threat_id: str) -> Dict[str, Any]:
    """
    Get similar past threats and patterns.

    Args:
        threat_id: ID of threat to find similar patterns for

    Returns:
        dict: Similar threats and patterns
    """
    try:
        # Query knowledge base for patterns
        patterns = query_security_knowledge(threat_id, k=10)

        return {
            "threat_id": threat_id,
            "similar_patterns": patterns,
            "pattern_count": len(patterns),
        }

    except Exception as e:
        logger.error(f"Failed to retrieve threat patterns: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve threat patterns",
        )


@router.get(
    "/graph/{entity_id}",
    response_model=GraphNodeResponse,
    status_code=status.HTTP_200_OK,
)
async def get_threat_graph(entity_id: str) -> Dict[str, Any]:
    """
    Get entity's connected graph for attack path analysis.

    Args:
        entity_id: UUID of entity node

    Returns:
        dict: Entity details and connected neighbors
    """
    try:
        # Get entity node
        node = get_node_by_id(entity_id)

        if not node:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Entity {entity_id} not found",
            )

        # Get connected nodes
        neighbors = get_connected_nodes(entity_id)

        return {
            "node_id": entity_id,
            "entity_type": node.get("entity_type"),
            "name": node.get("name"),
            "value": node.get("value"),
            "attributes": node.get("attributes", {}),
            "neighbors": neighbors,
            "neighbor_count": len(neighbors),
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to retrieve threat graph: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve threat graph",
        )


@router.get(
    "/entities",
    response_model=Dict[str, Any],
    status_code=status.HTTP_200_OK,
)
async def get_threat_entities(
    entity_type: Optional[str] = None,
    limit: int = 100,
) -> Dict[str, Any]:
    """
    Get all threat entities (nodes) in the graph.

    Args:
        entity_type: Filter by entity type (optional)
        limit: Maximum number of entities to return

    Returns:
        dict: List of entities
    """
    try:
        entities = query_nodes(entity_type=entity_type, limit=limit)

        return {
            "entities": entities,
            "total": len(entities),
            "entity_type_filter": entity_type,
        }

    except Exception as e:
        logger.error(f"Failed to retrieve entities: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve entities",
        )


# ============================================================================
# Helper Functions
# ============================================================================


def calculate_risk_score(
    threat_context: List[Dict[str, Any]],
    knowledge: List[Dict[str, Any]],
) -> float:
    """
    Calculate overall risk score based on threat context and knowledge matches.

    Returns score between 0.0 and 1.0
    """
    base_score = 0.5

    # Increase score based on context matches
    if threat_context:
        # Number of relevant entities
        base_score += min(0.2, len(threat_context) * 0.05)

        # Check for high-severity context
        for ctx in threat_context:
            if ctx.get("source") == "topological":
                base_score += 0.1
                break

    # Increase score based on knowledge matches
    if knowledge:
        for entry in knowledge:
            category = entry.get("category", "")
            if category == "attack_pattern":
                base_score += 0.15
            elif category == "detection_rule":
                base_score += 0.1

    return min(1.0, base_score)


def get_risk_level(risk_score: float) -> str:
    """Classify risk score into severity levels."""
    if risk_score >= 0.8:
        return "critical"
    elif risk_score >= 0.6:
        return "high"
    elif risk_score >= 0.4:
        return "medium"
    else:
        return "low"


def generate_recommended_actions(
    threat_context: List[Dict[str, Any]],
    knowledge: List[Dict[str, Any]],
    risk_score: float,
) -> List[str]:
    """
    Generate recommended mitigation actions based on threat analysis.

    Returns list of actionable recommendations
    """
    actions = []

    risk_level = get_risk_level(risk_score)

    # Base actions by risk level
    if risk_level == "critical":
        actions.append("IMMEDIATE: Isolate affected systems from network")
        actions.append("IMMEDIATE: Preserve logs and forensic evidence")
        actions.append("Activate incident response team")

    elif risk_level == "high":
        actions.append("Isolate affected systems")
        actions.append("Enable enhanced monitoring and logging")
        actions.append("Review recent activities of affected entities")

    elif risk_level == "medium":
        actions.append("Increase monitoring of affected entities")
        actions.append("Review access logs")

    else:
        actions.append("Continue standard monitoring")
        actions.append("Document incident for future reference")

    # Add specific actions based on knowledge matches
    for entry in knowledge:
        if entry.get("category") == "mitigation_strategy":
            title = entry.get("title", "")
            if title and title not in actions:
                actions.append(f"Consider: {title}")

    # Add entity-specific actions
    if threat_context:
        for ctx in threat_context:
            if ctx.get("entity_type") == "IP":
                if not any("block" in action.lower() for action in actions):
                    actions.append(f"Consider blocking IP: {ctx.get('value')}")

    return actions[:10]  # Limit to top 10 recommendations
