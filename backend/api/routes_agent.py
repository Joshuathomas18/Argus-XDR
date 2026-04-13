"""
Agent routes for Argus XDR.
Exposes threat mitigation and pathfinding capabilities via API.
"""

import logging
from typing import Dict, Any, Optional, List

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field

from backend.agents.orchestrator import get_orchestrator
from backend.pathfinding.traversal import (
    create_mock_threat_graph,
    find_shortest_path,
    find_all_lateral_paths,
    find_attack_chains,
    get_attack_surface,
    path_to_dict,
)


logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api", tags=["agent"])


# ============================================================================
# Pydantic Models
# ============================================================================


class MitigationRequest(BaseModel):
    """Request for autonomous threat mitigation."""

    query: str = Field(..., description="Description of the threat")
    severity: str = Field("medium", description="Threat severity level")
    source_ip: Optional[str] = Field(None, description="Attacker IP (if known)")
    affected_entities: Optional[List[str]] = Field(None, description="Compromised entities")
    attack_pattern: Optional[str] = Field(None, description="Type of attack")
    confidence: float = Field(0.7, ge=0.0, le=1.0, description="Confidence score")


class MitigationResponse(BaseModel):
    """Response from threat mitigation orchestrator."""

    status: str
    threat_id: str
    severity: str
    confidence: float
    actions_taken: List[str]
    recommendations: List[str]
    timestamp: str


class PathfindingRequest(BaseModel):
    """Request for attack path analysis."""

    start_node_id: str = Field(..., description="Starting entity ID")
    target_node_id: Optional[str] = Field(None, description="Target entity ID")
    max_depth: int = Field(5, description="Maximum path depth")


class PathfindingResponse(BaseModel):
    """Response from pathfinding engine."""

    paths_found: int
    attack_surface: Dict[str, int]
    paths: List[Dict[str, Any]]


# ============================================================================
# Agent Routes
# ============================================================================


@router.post(
    "/agents/mitigate",
    response_model=Dict[str, Any],
    status_code=status.HTTP_200_OK,
)
async def mitigate_threat(request: MitigationRequest) -> Dict[str, Any]:
    """
    Trigger autonomous threat mitigation.

    Submits a threat alert to the agent orchestrator, which runs the ReAct loop
    to analyze the threat and execute mitigation actions.

    Args:
        request: Threat data for mitigation

    Returns:
        dict: Mitigation report with actions and recommendations

    Example:
        ```json
        POST /api/agents/mitigate
        {
            "query": "Suspicious login from external IP",
            "severity": "high",
            "source_ip": "1.1.1.1",
            "confidence": 0.87
        }
        ```
    """
    if not request.query:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Query cannot be empty",
        )

    try:
        logger.info(f"Received mitigation request: {request.query}")

        # Get orchestrator
        orchestrator = get_orchestrator()

        # Prepare threat data
        threat_data = {
            "query": request.query,
            "severity": request.severity,
            "source_ip": request.source_ip,
            "affected_entities": request.affected_entities or [],
            "attack_pattern": request.attack_pattern,
            "confidence": request.confidence,
        }

        # Run mitigation
        mitigation_report = orchestrator.run_mitigation(threat_data)

        logger.info(f"Mitigation completed: {mitigation_report.get('status')}")

        return mitigation_report

    except Exception as e:
        logger.error(f"Mitigation request failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Mitigation failed: {str(e)}",
        )


@router.post(
    "/agents/explain",
    response_model=Dict[str, Any],
    status_code=status.HTTP_200_OK,
)
async def explain_threat(request: MitigationRequest) -> Dict[str, Any]:
    """
    Get AI explanation of a threat (without executing actions).

    Analyzes the threat and provides reasoning but doesn't execute mitigation.

    Args:
        request: Threat data to analyze

    Returns:
        dict: Threat analysis and explanation
    """
    try:
        logger.info(f"Analyzing threat: {request.query}")

        # Get threat intelligence
        from backend.agents.tools import query_threat_intel

        threat_intel = query_threat_intel.run(
            request.attack_pattern or request.query
        )

        return {
            "status": "success",
            "threat_query": request.query,
            "threat_intelligence": threat_intel,
            "severity_level": request.severity.upper(),
            "confidence_score": request.confidence,
            "analysis": {
                "attack_tactic": threat_intel.get("attack_tactic", "unknown"),
                "description": threat_intel.get("description", ""),
                "recommended_mitigations": threat_intel.get("mitigations", []),
                "detection_rules": threat_intel.get("detection_rules", []),
            },
        }

    except Exception as e:
        logger.error(f"Threat explanation failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Analysis failed: {str(e)}",
        )


# ============================================================================
# Pathfinding Routes
# ============================================================================


@router.post(
    "/pathfinding/routes",
    response_model=PathfindingResponse,
    status_code=status.HTTP_200_OK,
)
async def find_attack_routes(request: PathfindingRequest) -> Dict[str, Any]:
    """
    Find all attack paths from a compromised entity.

    Uses graph traversal to identify how an attacker can move through
    the network laterally.

    Args:
        request: Pathfinding request with start node

    Returns:
        dict: Attack routes and attack surface

    Example:
        ```json
        POST /api/pathfinding/routes
        {
            "start_node_id": "ip_10.0.0.5",
            "max_depth": 5
        }
        ```
    """
    try:
        logger.info(f"Finding attack paths from {request.start_node_id}")

        # Get mock graph (will be replaced with real graph from database)
        graph = create_mock_threat_graph()

        # Find all lateral paths
        paths = find_all_lateral_paths(
            graph,
            request.start_node_id,
            max_depth=request.max_depth,
            max_paths=10,
        )

        # Get attack surface
        attack_surface = get_attack_surface(graph, request.start_node_id)

        # Convert paths to serializable format
        paths_dict = [path_to_dict(path) for path in paths]

        logger.info(f"Found {len(paths)} attack paths")

        return {
            "status": "success",
            "start_node_id": request.start_node_id,
            "paths_found": len(paths),
            "attack_surface": attack_surface,
            "paths": paths_dict,
            "risk_assessment": {
                "lateral_movement_possible": len(paths) > 0,
                "entities_at_risk": sum(attack_surface.values()),
                "attack_surface_by_type": attack_surface,
            },
        }

    except Exception as e:
        logger.error(f"Pathfinding failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Pathfinding failed: {str(e)}",
        )


@router.post(
    "/pathfinding/shortest",
    response_model=Dict[str, Any],
    status_code=status.HTTP_200_OK,
)
async def find_shortest_attack_path(request: PathfindingRequest) -> Dict[str, Any]:
    """
    Find the shortest attack path between two entities.

    Identifies the quickest route an attacker would take to get from
    one compromised node to a target.

    Args:
        request: Pathfinding request with start and target nodes

    Returns:
        dict: Shortest attack path
    """
    if not request.target_node_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="target_node_id is required for shortest path",
        )

    try:
        logger.info(
            f"Finding shortest path from {request.start_node_id} to {request.target_node_id}"
        )

        # Get mock graph
        graph = create_mock_threat_graph()

        # Find shortest path using Dijkstra
        path = find_shortest_path(
            graph,
            request.start_node_id,
            request.target_node_id,
        )

        if not path:
            return {
                "status": "success",
                "path_found": False,
                "message": f"No path found from {request.start_node_id} to {request.target_node_id}",
            }

        path_dict = path_to_dict(path)

        return {
            "status": "success",
            "path_found": True,
            "start_node": request.start_node_id,
            "target_node": request.target_node_id,
            "path": path_dict,
            "mitigation": {
                "critical_points": [
                    f"Cut connection between {path.edges[i].source_id} and {path.edges[i].target_id}"
                    for i in range(len(path.edges) - 1)
                ],
                "recommended_action": f"Block traffic or isolate {request.target_node_id}",
            },
        }

    except Exception as e:
        logger.error(f"Shortest path finding failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Shortest path finding failed: {str(e)}",
        )


@router.post(
    "/pathfinding/chains",
    response_model=Dict[str, Any],
    status_code=status.HTTP_200_OK,
)
async def find_attack_chains() -> Dict[str, Any]:
    """
    Find common attack chains in the network.

    Identifies patterns of lateral movement and privilege escalation
    that attackers commonly exploit.

    Returns:
        dict: Common attack chains found in network
    """
    try:
        logger.info("Analyzing network for common attack chains")

        # Get mock graph
        graph = create_mock_threat_graph()

        # Find attack chains
        chains = find_attack_chains(graph)

        chains_dict = [path_to_dict(chain) for chain in chains]

        return {
            "status": "success",
            "chains_found": len(chains),
            "chains": chains_dict,
            "hardening_recommendations": [
                "Implement network segmentation",
                "Enable multi-factor authentication",
                "Disable unnecessary services",
                "Patch all systems regularly",
                "Monitor for lateral movement indicators",
            ],
        }

    except Exception as e:
        logger.error(f"Attack chain analysis failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Attack chain analysis failed: {str(e)}",
        )


@router.get(
    "/pathfinding/graph-stats",
    response_model=Dict[str, Any],
    status_code=status.HTTP_200_OK,
)
async def get_graph_statistics() -> Dict[str, Any]:
    """
    Get statistics about the threat graph.

    Returns:
        dict: Graph statistics including node/edge counts and entity types
    """
    try:
        graph = create_mock_threat_graph()

        entity_types = {}
        for node in graph.nodes.values():
            entity_types[node.entity_type] = entity_types.get(node.entity_type, 0) + 1

        relationship_types = {}
        for edge in graph.edges:
            rel_type = edge.relationship_type
            relationship_types[rel_type] = relationship_types.get(rel_type, 0) + 1

        return {
            "status": "success",
            "graph_statistics": {
                "total_nodes": len(graph.nodes),
                "total_edges": len(graph.edges),
                "node_types": entity_types,
                "relationship_types": relationship_types,
                "connectivity_ratio": len(graph.edges) / max(len(graph.nodes), 1),
            },
        }

    except Exception as e:
        logger.error(f"Graph statistics failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get graph statistics: {str(e)}",
        )
