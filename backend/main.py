"""
Main FastAPI application for Argus XDR.
Multi-stage AI-driven XDR (Extended Detection and Response) pipeline.
"""

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware

from backend.core.config import get_settings
from backend.core.database import close_connection
from backend.rag.knowledge import build_knowledge_base
from backend.api import routes_ingest, routes_threats, routes_agent


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


# ============================================================================
# Lifecycle Management
# ============================================================================


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Manage application startup and shutdown.

    Startup: Initialize database, load models, build knowledge base
    Shutdown: Clean up connections
    """
    # Startup
    logger.info("=" * 80)
    logger.info("Argus XDR Security Pipeline Starting")
    logger.info("=" * 80)

    try:
        settings = get_settings()
        logger.info(f"Environment: {settings.APP_ENV}")
        logger.info(f"Debug mode: {settings.DEBUG}")

        # Initialize database connection (lazy-loaded)
        from backend.core.database import _get_supabase_client

        logger.info("Initializing Supabase connection...")
        client = _get_supabase_client()
        logger.info("✓ Supabase connected")

        # Initialize embedder (lazy-loaded)
        from backend.rag.embedder import _get_minilm

        logger.info("Loading embedding model...")
        model = _get_minilm()
        logger.info("✓ Embedding model loaded")

        # Build knowledge base
        logger.info("Building knowledge base...")
        kb_entries = build_knowledge_base(force_rebuild=False)
        logger.info(f"✓ Knowledge base built with {len(kb_entries)} entries")

        logger.info("=" * 80)
        logger.info("Argus XDR Ready")
        logger.info("=" * 80)

    except Exception as e:
        logger.error(f"Failed to initialize Argus XDR: {e}")
        raise

    yield

    # Shutdown
    logger.info("Shutting down Argus XDR...")
    try:
        close_connection()
        logger.info("✓ Database connection closed")
    except Exception as e:
        logger.error(f"Error during shutdown: {e}")


# ============================================================================
# Application Creation
# ============================================================================


app = FastAPI(
    title="Argus XDR",
    description="Multi-stage AI-driven XDR (Extended Detection and Response) Pipeline",
    version="0.1.0",
    lifespan=lifespan,
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, restrict to specific origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================================
# Health Check Endpoints
# ============================================================================


@app.get("/health", status_code=status.HTTP_200_OK)
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "service": "argus-xdr",
        "version": "0.1.0",
    }


@app.get("/ready", status_code=status.HTTP_200_OK)
async def readiness_check():
    """Readiness check - verifies all components are initialized."""
    try:
        # Check database connection
        from backend.core.database import query_nodes

        _ = query_nodes(limit=1)

        # Check embedder
        from backend.rag.embedder import embed_text

        _ = embed_text("test")

        return {
            "ready": True,
            "message": "All components initialized",
        }

    except Exception as e:
        logger.error(f"Readiness check failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Service not ready: {str(e)}",
        )


# ============================================================================
# Router Inclusion
# ============================================================================


app.include_router(routes_ingest.router)
app.include_router(routes_threats.router)
app.include_router(routes_agent.router)


# ============================================================================
# Error Handlers
# ============================================================================


@app.exception_handler(HTTPException)
async def http_exception_handler(request, exc):
    """Handle HTTP exceptions."""
    logger.warning(f"HTTP exception: {exc.status_code} - {exc.detail}")
    return {
        "error": True,
        "status_code": exc.status_code,
        "detail": exc.detail,
    }


@app.exception_handler(Exception)
async def general_exception_handler(request, exc):
    """Handle unexpected exceptions."""
    logger.error(f"Unexpected exception: {exc}", exc_info=True)
    return {
        "error": True,
        "status_code": 500,
        "detail": "Internal server error",
    }


# ============================================================================
# API Documentation
# ============================================================================


@app.get("/", status_code=status.HTTP_200_OK)
async def root():
    """Root endpoint - provides API overview."""
    return {
        "name": "Argus XDR",
        "description": "Multi-stage AI-driven XDR Pipeline",
        "version": "0.1.0",
        "endpoints": {
            "health": "/health",
            "readiness": "/ready",
            "docs": "/docs",
            "openapi": "/openapi.json",
            "ingest": {
                "logs": "POST /api/ingest/logs",
                "cloud_audit": "POST /api/ingest/cloud-audit",
                "status": "GET /api/ingest/status",
            },
            "threats": {
                "analyze": "POST /api/threats/analyze",
                "patterns": "GET /api/threats/patterns/{threat_id}",
                "graph": "GET /api/threats/graph/{entity_id}",
                "entities": "GET /api/threats/entities",
            },
            "agent": {
                "mitigate": "POST /api/agents/mitigate",
                "explain": "POST /api/agents/explain",
            },
            "pathfinding": {
                "routes": "POST /api/pathfinding/routes",
                "shortest": "POST /api/pathfinding/shortest",
                "chains": "POST /api/pathfinding/chains",
                "stats": "GET /api/pathfinding/graph-stats",
            },
        },
    }


if __name__ == "__main__":
    import uvicorn

    settings = get_settings()
    uvicorn.run(
        "backend.main:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=settings.DEBUG,
        log_level=settings.LOG_LEVEL.lower(),
    )
