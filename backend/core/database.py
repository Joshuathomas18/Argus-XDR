"""
Database client for Argus XDR.
Handles Supabase connection and provides wrapper functions for database operations.
Reuses lazy-loading singleton pattern from RV32I project.
"""

import logging
from typing import Any, Optional
from functools import lru_cache

try:
    from supabase import create_client, Client
except ImportError:
    raise ImportError("supabase library is required. Install with: pip install supabase")

from backend.core.config import get_settings


logger = logging.getLogger(__name__)

# Global singleton client
_supabase_client: Optional[Client] = None


def _get_supabase_client() -> Client:
    """
    Get or create Supabase client (lazy-loaded singleton).
    Reuses pattern from RV32I's pipeline.py.

    Returns:
        Client: Supabase client instance

    Raises:
        ValueError: If Supabase credentials are missing
    """
    global _supabase_client

    if _supabase_client is None:
        settings = get_settings()

        if not settings.SUPABASE_URL or not settings.SUPABASE_KEY:
            raise ValueError(
                "Supabase credentials not configured. "
                "Set SUPABASE_URL and SUPABASE_KEY environment variables."
            )

        try:
            logger.info("Initializing Supabase client...")
            _supabase_client = create_client(
                supabase_url=settings.SUPABASE_URL,
                supabase_key=settings.SUPABASE_KEY,
            )
            logger.info("Supabase client initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize Supabase client: {e}")
            raise

    return _supabase_client


def close_connection() -> None:
    """Close Supabase connection."""
    global _supabase_client
    if _supabase_client is not None:
        # Supabase client doesn't have explicit close, but we reset the reference
        _supabase_client = None
        logger.info("Supabase connection closed")


# ============================================================================
# Log Operations
# ============================================================================


def insert_log(event: dict) -> dict:
    """
    Insert a security event log into the database.

    Args:
        event: Dictionary containing log data with keys:
            - timestamp (str, ISO format)
            - source_type (str): 'syslog', 'cloud_audit', 'windows_event', 'custom_json'
            - source_ip (str, optional)
            - source_user (str, optional)
            - target_resource (str, optional)
            - action (str)
            - severity (str): 'critical', 'high', 'medium', 'low', 'info'
            - event_type (str, optional)
            - raw_data (dict): Original log payload
            - normalized_data (dict, optional): Parsed fields
            - metadata (dict, optional): Additional context

    Returns:
        dict: Inserted log record with generated ID

    Raises:
        Exception: If database operation fails
    """
    client = _get_supabase_client()

    try:
        response = client.table("logs").insert(event).execute()
        logger.debug(f"Inserted log: {response.data}")
        return response.data
    except Exception as e:
        logger.error(f"Failed to insert log: {e}")
        raise


def batch_insert_logs(events: list[dict], batch_size: int = 100) -> list[dict]:
    """
    Insert multiple security events in batches.

    Args:
        events: List of log dictionaries
        batch_size: Number of events per batch

    Returns:
        list: List of inserted log records
    """
    client = _get_supabase_client()
    inserted = []

    for i in range(0, len(events), batch_size):
        batch = events[i : i + batch_size]
        try:
            response = client.table("logs").insert(batch).execute()
            inserted.extend(response.data)
            logger.info(f"Inserted batch of {len(batch)} logs")
        except Exception as e:
            logger.error(f"Failed to insert batch: {e}")
            continue

    return inserted


# ============================================================================
# Node Operations
# ============================================================================


def insert_node(
    entity_type: str,
    name: str,
    value: str,
    embedding: list[float],
    attributes: Optional[dict] = None,
) -> dict:
    """
    Insert or update a node (entity) in the graph.

    Args:
        entity_type: Type of entity ('IP', 'User', 'Host', 'File', 'Process', 'Domain', 'URL')
        name: Human-readable name
        value: Canonical value (e.g., IP address, username)
        embedding: Vector embedding (384-dimensional for MiniLM)
        attributes: Optional metadata dictionary

    Returns:
        dict: Inserted/updated node record
    """
    client = _get_supabase_client()

    node_data = {
        "entity_type": entity_type,
        "name": name,
        "value": value,
        "embedding": embedding,
        "attributes": attributes or {},
    }

    try:
        # Try to insert; if unique constraint fails, update instead
        response = client.table("nodes").upsert(node_data).execute()
        logger.debug(f"Upserted node: {entity_type}/{value}")
        return response.data
    except Exception as e:
        logger.error(f"Failed to insert/update node: {e}")
        raise


def query_nodes(entity_type: Optional[str] = None, limit: int = 100) -> list[dict]:
    """
    Query nodes from the database.

    Args:
        entity_type: Filter by entity type (optional)
        limit: Maximum number of results

    Returns:
        list: List of node records
    """
    client = _get_supabase_client()

    try:
        query = client.table("nodes").select("*").limit(limit)
        if entity_type:
            query = query.eq("entity_type", entity_type)
        response = query.execute()
        return response.data
    except Exception as e:
        logger.error(f"Failed to query nodes: {e}")
        raise


def get_node_by_id(node_id: str) -> Optional[dict]:
    """Get a single node by ID."""
    client = _get_supabase_client()

    try:
        response = client.table("nodes").select("*").eq("id", node_id).execute()
        return response.data[0] if response.data else None
    except Exception as e:
        logger.error(f"Failed to get node {node_id}: {e}")
        raise


# ============================================================================
# Edge Operations
# ============================================================================


def insert_edge(
    source_node_id: str,
    target_node_id: str,
    relationship_type: str,
    confidence: float = 0.5,
    metadata: Optional[dict] = None,
) -> dict:
    """
    Insert or update an edge (relationship) between nodes.

    Args:
        source_node_id: UUID of source node
        target_node_id: UUID of target node
        relationship_type: Type of relationship ('CONNECTED_TO', 'EXECUTED_BY', 'ACCESSED', 'LOGGED_IN_TO')
        confidence: Confidence score (0.0 to 1.0)
        metadata: Optional edge metadata

    Returns:
        dict: Inserted/updated edge record
    """
    client = _get_supabase_client()

    edge_data = {
        "source_node_id": source_node_id,
        "target_node_id": target_node_id,
        "relationship_type": relationship_type,
        "confidence": confidence,
        "metadata": metadata or {},
    }

    try:
        response = client.table("edges").upsert(edge_data).execute()
        logger.debug(f"Upserted edge: {source_node_id} --{relationship_type}--> {target_node_id}")
        return response.data
    except Exception as e:
        logger.error(f"Failed to insert/update edge: {e}")
        raise


def get_connected_nodes(node_id: str) -> list[dict]:
    """
    Get all nodes connected to a given node (1-hop neighbors).

    Args:
        node_id: UUID of the center node

    Returns:
        list: List of connected node records with relationship details
    """
    client = _get_supabase_client()

    try:
        # Query edges where this node is the source or target
        response = (
            client.table("edges")
            .select(
                "id, source_node_id, target_node_id, relationship_type, confidence, metadata"
            )
            .or_(f"source_node_id.eq.{node_id},target_node_id.eq.{node_id}")
            .execute()
        )

        edges = response.data
        connected_node_ids = set()

        for edge in edges:
            if edge["source_node_id"] == node_id:
                connected_node_ids.add(edge["target_node_id"])
            else:
                connected_node_ids.add(edge["source_node_id"])

        # Fetch node details
        nodes = []
        for connected_id in connected_node_ids:
            node = get_node_by_id(connected_id)
            if node:
                nodes.append(node)

        return nodes
    except Exception as e:
        logger.error(f"Failed to get connected nodes for {node_id}: {e}")
        raise


# ============================================================================
# Embedding Operations
# ============================================================================


def insert_embedding(
    content: str,
    embedding: list[float],
    content_type: str = "log_event",
    log_id: Optional[int] = None,
    metadata: Optional[dict] = None,
) -> dict:
    """
    Insert an embedding into the embeddings table.

    Args:
        content: Original text that was embedded
        embedding: Vector embedding (384-dimensional for MiniLM)
        content_type: Type of content ('log_event', 'threat_summary', 'knowledge_entry')
        log_id: Associated log ID (optional)
        metadata: Optional metadata

    Returns:
        dict: Inserted embedding record
    """
    client = _get_supabase_client()

    embedding_data = {
        "content": content,
        "embedding": embedding,
        "content_type": content_type,
        "log_id": log_id,
        "metadata": metadata or {},
    }

    try:
        response = client.table("embeddings").insert(embedding_data).execute()
        return response.data
    except Exception as e:
        logger.error(f"Failed to insert embedding: {e}")
        raise


def semantic_search(
    query_embedding: list[float],
    content_type: Optional[str] = None,
    limit: int = 10,
) -> list[dict]:
    """
    Perform semantic search using vector similarity.

    Args:
        query_embedding: Query vector (384-dimensional for MiniLM)
        content_type: Filter by content type (optional)
        limit: Maximum number of results

    Returns:
        list: List of matching embeddings sorted by similarity
    """
    client = _get_supabase_client()

    try:
        # Use Supabase's vector similarity search
        query = client.rpc(
            "search_embeddings",
            {
                "query_embedding": query_embedding,
                "match_count": limit,
                "filter": {"content_type": content_type} if content_type else None,
            },
        ).execute()

        return query.data
    except Exception as e:
        # Fallback to manual vector similarity if RPC not available
        logger.warning(f"Vector search RPC failed, falling back to manual search: {e}")
        return fallback_vector_search(query_embedding, content_type, limit)


def fallback_vector_search(
    query_embedding: list[float],
    content_type: Optional[str] = None,
    limit: int = 10,
) -> list[dict]:
    """
    Fallback semantic search using manual similarity calculation.
    Useful when Supabase RPC functions aren't available.

    Args:
        query_embedding: Query vector
        content_type: Filter by content type (optional)
        limit: Maximum number of results

    Returns:
        list: List of matching embeddings sorted by similarity
    """
    import numpy as np

    client = _get_supabase_client()

    try:
        query = client.table("embeddings").select("*")
        if content_type:
            query = query.eq("content_type", content_type)
        response = query.execute()

        embeddings = response.data
        query_vec = np.array(query_embedding)

        # Calculate cosine similarity
        similarities = []
        for emb in embeddings:
            if emb.get("embedding"):
                emb_vec = np.array(emb["embedding"])
                # Cosine similarity
                similarity = np.dot(query_vec, emb_vec) / (
                    np.linalg.norm(query_vec) * np.linalg.norm(emb_vec)
                )
                similarities.append((emb, similarity))

        # Sort by similarity descending
        similarities.sort(key=lambda x: x[1], reverse=True)
        return [emb for emb, _ in similarities[:limit]]

    except Exception as e:
        logger.error(f"Fallback vector search failed: {e}")
        raise


# ============================================================================
# Knowledge Base Operations
# ============================================================================


def insert_knowledge_entry(
    category: str,
    title: str,
    content: str,
    embedding: list[float],
    description: Optional[str] = None,
    metadata: Optional[dict] = None,
) -> dict:
    """
    Insert a knowledge entry into the knowledge base.

    Args:
        category: Category ('attack_pattern', 'detection_rule', 'mitigation_strategy')
        title: Entry title
        content: Full content
        embedding: Vector embedding
        description: Optional short description
        metadata: Optional metadata (tags, references, etc.)

    Returns:
        dict: Inserted knowledge entry
    """
    client = _get_supabase_client()

    entry_data = {
        "category": category,
        "title": title,
        "description": description,
        "content": content,
        "embedding": embedding,
        "metadata": metadata or {},
    }

    try:
        response = client.table("knowledge_entries").upsert(entry_data).execute()
        logger.debug(f"Inserted knowledge entry: {category}/{title}")
        return response.data
    except Exception as e:
        logger.error(f"Failed to insert knowledge entry: {e}")
        raise


def query_knowledge(
    category: Optional[str] = None,
    limit: int = 10,
) -> list[dict]:
    """
    Query knowledge entries.

    Args:
        category: Filter by category (optional)
        limit: Maximum number of results

    Returns:
        list: List of knowledge entries
    """
    client = _get_supabase_client()

    try:
        query = client.table("knowledge_entries").select("*").limit(limit)
        if category:
            query = query.eq("category", category)
        response = query.execute()
        return response.data
    except Exception as e:
        logger.error(f"Failed to query knowledge entries: {e}")
        raise


# ============================================================================
# Raw Query Execution
# ============================================================================


def execute_query(sql: str, params: Optional[list] = None) -> Any:
    """
    Execute a raw SQL query (use with caution).

    Args:
        sql: SQL query string
        params: Optional parameter list for prepared statements

    Returns:
        Query result

    Raises:
        Exception: If query execution fails
    """
    client = _get_supabase_client()

    try:
        response = client.postgrest.auth(client.auth.session().access_token).execute(
            f"SELECT sql_exec('{sql}')"
        )
        return response.data
    except Exception as e:
        logger.warning(f"Raw query execution not supported, use standard operations instead: {e}")
        raise
