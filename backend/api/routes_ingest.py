"""
Ingest routes for Argus XDR.
Endpoints for receiving and processing security logs.
"""

import logging
from typing import List, Dict, Any, Optional

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field

from backend.pipeline.parser import normalize_event
from backend.pipeline.graph_builder import build_graph, persist_graph
from backend.core.database import insert_log, batch_insert_logs


logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/ingest", tags=["ingest"])


# ============================================================================
# Pydantic Models for Request/Response Validation
# ============================================================================


class LogEntry(BaseModel):
    """Single security log entry."""

    timestamp: str
    event_type: str
    severity: str = "info"
    source_ip: Optional[str] = None
    source_user: Optional[str] = None
    target_resource: Optional[str] = None
    action: str
    metadata: Optional[Dict[str, Any]] = None


class BatchIngestRequest(BaseModel):
    """Batch log ingestion request."""

    logs: List[Dict[str, Any]] = Field(..., description="List of log entries")
    source_type: str = Field("custom_json", description="Type of logs being ingested")


class IngestResponse(BaseModel):
    """Response for ingest operations."""

    success: bool
    ingested: int
    entities: int
    edges: int
    errors: int
    message: str


class CloudAuditIngestRequest(BaseModel):
    """Cloud audit log ingestion request."""

    audit_logs: List[Dict[str, Any]]
    cloud_provider: Optional[str] = None


# ============================================================================
# Ingest Endpoints
# ============================================================================


@router.post(
    "/logs",
    response_model=IngestResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
async def ingest_logs(request: BatchIngestRequest) -> IngestResponse:
    """
    Ingest batch security logs.

    Process:
    1. Parse and normalize logs
    2. Extract entities and build graph
    3. Store in database

    Args:
        request: Batch ingest request with logs and source_type

    Returns:
        IngestResponse: Summary of ingestion results

    Raises:
        HTTPException: If validation or processing fails
    """
    if not request.logs:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No logs provided",
        )

    if len(request.logs) > 10000:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="Batch size exceeds maximum of 10,000 logs",
        )

    try:
        # Normalize logs
        normalized_events = []
        errors = 0

        for i, log in enumerate(request.logs):
            try:
                normalized = normalize_event(log, source_type=request.source_type)
                if normalized:
                    normalized_events.append(normalized)
                else:
                    errors += 1
            except Exception as e:
                logger.warning(f"Failed to normalize log {i}: {e}")
                errors += 1

        logger.info(f"Normalized {len(normalized_events)} logs (errors: {errors})")

        # Store logs
        if normalized_events:
            try:
                batch_insert_logs(normalized_events)
                logger.info(f"Stored {len(normalized_events)} logs")
            except Exception as e:
                logger.error(f"Failed to store logs: {e}")
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Failed to store logs",
                )

        # Build graph
        entities_count = 0
        edges_count = 0

        try:
            nodes, edges = build_graph(normalized_events)
            result = persist_graph(nodes, edges)
            entities_count = result["nodes_persisted"]
            edges_count = result["edges_persisted"]
            logger.info(f"Built graph with {entities_count} entities and {edges_count} edges")
        except Exception as e:
            logger.error(f"Failed to build graph: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to build threat graph",
            )

        return IngestResponse(
            success=True,
            ingested=len(normalized_events),
            entities=entities_count,
            edges=edges_count,
            errors=errors,
            message=f"Successfully ingested {len(normalized_events)} logs",
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Unexpected error during log ingestion: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Unexpected error: {str(e)}",
        )


@router.post(
    "/cloud-audit",
    response_model=IngestResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
async def ingest_cloud_audit(request: CloudAuditIngestRequest) -> IngestResponse:
    """
    Ingest cloud provider audit logs (AWS CloudTrail, Azure Activity, GCP Audit).

    Args:
        request: Cloud audit logs and provider info

    Returns:
        IngestResponse: Summary of ingestion results
    """
    if not request.audit_logs:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No audit logs provided",
        )

    try:
        # Normalize logs with cloud_audit source type
        normalized_events = []
        errors = 0

        for i, log in enumerate(request.audit_logs):
            try:
                normalized = normalize_event(log, source_type="cloud_audit")
                if normalized:
                    normalized_events.append(normalized)
                else:
                    errors += 1
            except Exception as e:
                logger.warning(f"Failed to normalize cloud audit log {i}: {e}")
                errors += 1

        logger.info(f"Normalized {len(normalized_events)} cloud audit logs (errors: {errors})")

        # Store logs
        if normalized_events:
            try:
                batch_insert_logs(normalized_events)
            except Exception as e:
                logger.error(f"Failed to store cloud audit logs: {e}")
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Failed to store audit logs",
                )

        # Build graph
        entities_count = 0
        edges_count = 0

        try:
            nodes, edges = build_graph(normalized_events)
            result = persist_graph(nodes, edges)
            entities_count = result["nodes_persisted"]
            edges_count = result["edges_persisted"]
        except Exception as e:
            logger.error(f"Failed to build graph from cloud audit logs: {e}")

        return IngestResponse(
            success=True,
            ingested=len(normalized_events),
            entities=entities_count,
            edges=edges_count,
            errors=errors,
            message=f"Successfully ingested {len(normalized_events)} cloud audit logs",
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Unexpected error during cloud audit ingestion: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Unexpected error: {str(e)}",
        )


@router.get(
    "/status",
    status_code=status.HTTP_200_OK,
)
async def get_ingest_status() -> Dict[str, Any]:
    """
    Get ingestion pipeline status.

    Returns:
        dict: Status information
    """
    return {
        "status": "operational",
        "message": "Ingestion pipeline is ready",
    }
