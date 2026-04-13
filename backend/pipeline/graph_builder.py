"""
Graph builder for Argus XDR.
Extracts entities and builds relationship graph for attack path detection.
"""

import logging
import re
import uuid
from typing import List, Tuple, Optional, Dict, Any
from dataclasses import dataclass
from datetime import datetime, timedelta

from backend.core.database import (
    insert_node,
    insert_edge,
    get_node_by_id,
)
from backend.rag.embedder import embed_entity_context


logger = logging.getLogger(__name__)


@dataclass
class Node:
    """Graph node representing an entity."""

    id: str
    entity_type: str
    name: str
    value: str
    attributes: Dict[str, Any]


@dataclass
class Edge:
    """Graph edge representing a relationship."""

    source_node_id: str
    target_node_id: str
    relationship_type: str
    confidence: float
    metadata: Dict[str, Any]


def extract_entities(event: Dict[str, Any]) -> List[Node]:
    """
    Extract entities from a normalized security event.

    Entity types: IP, User, Host, File, Process, Domain, URL

    Args:
        event: Normalized security event

    Returns:
        list: List of extracted Node objects
    """
    entities = []

    # Extract IP addresses
    if event.get("source_ip"):
        node = Node(
            id=str(uuid.uuid4()),
            entity_type="IP",
            name=event["source_ip"],
            value=event["source_ip"],
            attributes={
                "type": "source_ip",
                "event_type": event.get("event_type"),
            },
        )
        entities.append(node)

    # Extract User
    if event.get("source_user"):
        node = Node(
            id=str(uuid.uuid4()),
            entity_type="User",
            name=event["source_user"],
            value=event["source_user"].lower(),
            attributes={
                "event_type": event.get("event_type"),
                "severity": event.get("severity"),
            },
        )
        entities.append(node)

    # Extract Resource/Host
    if event.get("target_resource"):
        resource = event["target_resource"]
        # Try to determine if it's a hostname or file path
        if "/" in resource or "\\" in resource:
            entity_type = "File"
        else:
            entity_type = "Host"

        node = Node(
            id=str(uuid.uuid4()),
            entity_type=entity_type,
            name=resource,
            value=resource.lower(),
            attributes={
                "action": event.get("action"),
                "event_type": event.get("event_type"),
            },
        )
        entities.append(node)

    # Extract domains from URLs or hostnames
    domain = extract_domain_from_event(event)
    if domain:
        node = Node(
            id=str(uuid.uuid4()),
            entity_type="Domain",
            name=domain,
            value=domain.lower(),
            attributes={
                "extracted_from": "target_resource",
            },
        )
        entities.append(node)

    # Extract event type as Process (if relevant)
    if event.get("event_type") and "process" in event["event_type"].lower():
        node = Node(
            id=str(uuid.uuid4()),
            entity_type="Process",
            name=event["event_type"],
            value=event["event_type"].lower(),
            attributes={
                "severity": event.get("severity"),
            },
        )
        entities.append(node)

    logger.debug(f"Extracted {len(entities)} entities from event")
    return entities


def build_graph(events: List[Dict[str, Any]]) -> Tuple[List[Node], List[Edge]]:
    """
    Build entity-relationship graph from a batch of events.

    Implements:
    - Entity deduplication
    - Temporal clustering (5-minute windows)
    - Relationship detection
    - Confidence scoring

    Args:
        events: List of normalized events

    Returns:
        tuple: (list of nodes, list of edges)
    """
    nodes_dict: Dict[Tuple[str, str], Node] = {}  # (entity_type, value) -> Node
    edges_dict: Dict[Tuple[str, str, str], Edge] = {}  # (src_id, tgt_id, rel_type) -> Edge

    # Extract all entities from events
    for event in events:
        entities = extract_entities(event)

        for entity in entities:
            key = (entity.entity_type, entity.value)

            if key not in nodes_dict:
                nodes_dict[key] = entity
            else:
                # Update frequency
                existing = nodes_dict[key]
                existing.attributes["frequency"] = existing.attributes.get("frequency", 1) + 1

    logger.info(f"Extracted {len(nodes_dict)} unique entities")

    # Build relationships
    for i, event in enumerate(events):
        entities = extract_entities(event)

        # Temporal clustering: group events within 5-minute windows
        window_id = datetime.fromisoformat(
            event["timestamp"].replace("Z", "+00:00")
        ).replace(minute=int(datetime.fromisoformat(
            event["timestamp"].replace("Z", "+00:00")
        ).minute / 5) * 5)

        # Create edges based on event relationships
        for entity_a in entities:
            for entity_b in entities:
                if entity_a.id == entity_b.id:
                    continue

                # Define relationships based on entity types
                rel_type = determine_relationship_type(
                    entity_a.entity_type,
                    entity_b.entity_type,
                    event,
                )

                if rel_type:
                    key = (entity_a.id, entity_b.id, rel_type)

                    if key not in edges_dict:
                        edges_dict[key] = Edge(
                            source_node_id=entity_a.id,
                            target_node_id=entity_b.id,
                            relationship_type=rel_type,
                            confidence=calculate_confidence(event),
                            metadata={
                                "event_type": event.get("event_type"),
                                "action": event.get("action"),
                                "timestamp": event.get("timestamp"),
                                "severity": event.get("severity"),
                                "window_id": window_id.isoformat(),
                            },
                        )
                    else:
                        # Increment count and update confidence
                        edge = edges_dict[key]
                        edge.metadata["count"] = edge.metadata.get("count", 1) + 1
                        edge.confidence = min(1.0, edge.confidence + 0.1)

    logger.info(f"Built {len(edges_dict)} relationships")

    nodes = list(nodes_dict.values())
    edges = list(edges_dict.values())

    return nodes, edges


def persist_graph(nodes: List[Node], edges: List[Edge]) -> Dict[str, Any]:
    """
    Persist nodes and edges to database.

    Args:
        nodes: List of nodes to store
        edges: List of edges to store

    Returns:
        dict: Summary of stored entities
    """
    node_mapping = {}  # original_id -> db_id

    # Store nodes
    for node in nodes:
        try:
            # Generate embedding for node
            embedding = embed_entity_context(
                node.entity_type,
                node.name,
                node.value,
                node.attributes,
            )

            # Insert into database
            db_node = insert_node(
                entity_type=node.entity_type,
                name=node.name,
                value=node.value,
                embedding=embedding,
                attributes=node.attributes,
            )

            # Store mapping for edge creation
            if isinstance(db_node, list) and db_node:
                node_mapping[node.id] = db_node[0]["id"]
            elif isinstance(db_node, dict):
                node_mapping[node.id] = db_node["id"]

        except Exception as e:
            logger.error(f"Failed to persist node {node.value}: {e}")

    logger.info(f"Persisted {len(node_mapping)} nodes to database")

    # Store edges
    edges_persisted = 0
    for edge in edges:
        try:
            # Look up actual node IDs
            src_id = node_mapping.get(edge.source_node_id)
            tgt_id = node_mapping.get(edge.target_node_id)

            if src_id and tgt_id:
                insert_edge(
                    source_node_id=src_id,
                    target_node_id=tgt_id,
                    relationship_type=edge.relationship_type,
                    confidence=edge.confidence,
                    metadata=edge.metadata,
                )
                edges_persisted += 1

        except Exception as e:
            logger.error(
                f"Failed to persist edge {edge.source_node_id} -> {edge.target_node_id}: {e}"
            )

    logger.info(f"Persisted {edges_persisted} edges to database")

    return {
        "nodes_persisted": len(node_mapping),
        "edges_persisted": edges_persisted,
        "node_mapping": node_mapping,
    }


# ============================================================================
# Helper Functions
# ============================================================================


def determine_relationship_type(
    entity_type_a: str,
    entity_type_b: str,
    event: Dict[str, Any],
) -> Optional[str]:
    """
    Determine relationship type between two entities.

    Returns relationship type or None if no relationship applies.
    """
    action = event.get("action", "").lower()

    # User -> Host relationships
    if entity_type_a == "User" and entity_type_b == "Host":
        if "login" in action or "logon" in action:
            return "LOGGED_IN_TO"
        return "CONNECTED_TO"

    # User -> Process relationships
    if entity_type_a == "User" and entity_type_b == "Process":
        return "EXECUTED_BY"

    # Process -> File relationships
    if entity_type_a == "Process" and entity_type_b == "File":
        if "delete" in action:
            return "DELETED"
        if "modify" in action or "write" in action:
            return "MODIFIED"
        return "ACCESSED"

    # IP -> Host relationships
    if entity_type_a == "IP" and entity_type_b == "Host":
        return "CONNECTED_TO"

    # Host -> Domain relationships
    if entity_type_a == "Host" and entity_type_b == "Domain":
        return "RESOLVED_TO"

    return None


def calculate_confidence(event: Dict[str, Any]) -> float:
    """
    Calculate confidence score for an event-based relationship.

    Based on severity and event type reliability.
    """
    base_confidence = 0.5

    severity = event.get("severity", "info").lower()
    if severity == "critical":
        base_confidence += 0.4
    elif severity == "high":
        base_confidence += 0.3
    elif severity == "medium":
        base_confidence += 0.1

    # Increase confidence for action-specific events
    action = event.get("action", "").lower()
    if action in ["login", "logout", "failed", "blocked", "allowed"]:
        base_confidence += 0.1

    return min(1.0, base_confidence)


def extract_domain_from_event(event: Dict[str, Any]) -> Optional[str]:
    """Extract domain name from event."""
    target = event.get("target_resource", "")

    # Simple domain extraction from FQDN or URL
    if "://" in target:
        # URL format
        try:
            from urllib.parse import urlparse

            parsed = urlparse(target)
            return parsed.netloc
        except Exception:
            pass

    # Check if it looks like a hostname
    if "." in target and not "/" in target:
        parts = target.split(".")
        if len(parts) >= 2:
            return ".".join(parts[-2:])

    return None
