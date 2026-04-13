"""
Pathfinding engine for Argus XDR.
Implements deterministic attack path detection using graph traversal algorithms.
Finds how attackers move through the network using DFS and Dijkstra's algorithm.
"""

import logging
from typing import List, Dict, Tuple, Optional, Set
from dataclasses import dataclass, field
from collections import deque
import heapq


logger = logging.getLogger(__name__)


# ============================================================================
# Data Structures
# ============================================================================


@dataclass
class GraphNode:
    """Represents a node in the threat graph."""

    id: str
    entity_type: str  # IP, User, Host, File, Process, Domain, URL
    name: str
    value: str
    attributes: Dict = field(default_factory=dict)


@dataclass
class GraphEdge:
    """Represents a relationship between nodes."""

    source_id: str
    target_id: str
    relationship_type: str  # CONNECTED_TO, EXECUTED_BY, ACCESSED, LOGGED_IN_TO
    confidence: float  # 0.0 to 1.0
    weight: float = 1.0  # For pathfinding (lower weight = preferred path)
    metadata: Dict = field(default_factory=dict)


@dataclass
class Path:
    """Represents a path through the graph (attack chain)."""

    nodes: List[GraphNode]
    edges: List[GraphEdge]
    total_distance: float
    confidence: float  # Minimum confidence along path


@dataclass
class GraphData:
    """Mock graph data for testing without Supabase."""

    nodes: Dict[str, GraphNode] = field(default_factory=dict)
    edges: List[GraphEdge] = field(default_factory=list)
    adjacency: Dict[str, List[Tuple[str, GraphEdge]]] = field(default_factory=dict)

    def add_node(self, node: GraphNode) -> None:
        """Add a node to the graph."""
        self.nodes[node.id] = node
        if node.id not in self.adjacency:
            self.adjacency[node.id] = []

    def add_edge(self, edge: GraphEdge) -> None:
        """Add an edge to the graph."""
        self.edges.append(edge)

        # Update adjacency list
        if edge.source_id not in self.adjacency:
            self.adjacency[edge.source_id] = []

        self.adjacency[edge.source_id].append((edge.target_id, edge))

    def get_neighbors(self, node_id: str) -> List[Tuple[str, GraphEdge]]:
        """Get all neighbors of a node."""
        return self.adjacency.get(node_id, [])

    def get_node(self, node_id: str) -> Optional[GraphNode]:
        """Get a node by ID."""
        return self.nodes.get(node_id)


# ============================================================================
# Pathfinding Algorithms
# ============================================================================


def find_shortest_path(
    graph: GraphData,
    start_node_id: str,
    target_node_id: str,
) -> Optional[Path]:
    """
    Find the shortest path from start to target using Dijkstra's algorithm.

    The weight is based on relationship confidence (lower confidence = higher weight = avoided).

    Args:
        graph: GraphData object containing nodes and edges
        start_node_id: ID of starting node (compromised entity)
        target_node_id: ID of target node (objective)

    Returns:
        Path object if found, None if no path exists
    """
    if start_node_id not in graph.nodes or target_node_id not in graph.nodes:
        logger.warning(f"Start or target node not found in graph")
        return None

    # Priority queue: (distance, node_id, path_edges)
    pq = [(0.0, start_node_id, [])]
    visited = set()
    distances = {node_id: float("inf") for node_id in graph.nodes}
    distances[start_node_id] = 0.0
    parent_edges = {}

    while pq:
        current_distance, current_node_id, path_edges = heapq.heappop(pq)

        if current_node_id in visited:
            continue

        visited.add(current_node_id)

        # Target reached
        if current_node_id == target_node_id:
            nodes = [graph.get_node(start_node_id)]

            # Reconstruct path
            node_id = current_node_id
            edges_in_path = path_edges.copy()

            for edge in edges_in_path:
                nodes.append(graph.get_node(edge.target_id))

            # Calculate confidence (minimum along path)
            min_confidence = min([edge.confidence for edge in edges_in_path], default=0.5)

            return Path(
                nodes=nodes,
                edges=edges_in_path,
                total_distance=current_distance,
                confidence=min_confidence,
            )

        # Explore neighbors
        for neighbor_id, edge in graph.get_neighbors(current_node_id):
            if neighbor_id not in visited:
                # Weight inversely proportional to confidence
                edge_weight = 1.0 / max(edge.confidence, 0.1)
                new_distance = current_distance + edge_weight

                if new_distance < distances.get(neighbor_id, float("inf")):
                    distances[neighbor_id] = new_distance
                    new_edges = path_edges + [edge]
                    heapq.heappush(pq, (new_distance, neighbor_id, new_edges))

    logger.warning(f"No path found from {start_node_id} to {target_node_id}")
    return None


def find_all_lateral_paths(
    graph: GraphData,
    compromised_node_id: str,
    max_depth: int = 5,
    max_paths: int = 10,
) -> List[Path]:
    """
    Find all lateral movement paths from a compromised node using DFS.

    Discovers everywhere a compromised machine can reach.

    Args:
        graph: GraphData object containing nodes and edges
        compromised_node_id: ID of the compromised node
        max_depth: Maximum path length to explore
        max_paths: Maximum number of paths to return

    Returns:
        List of Path objects representing lateral movement possibilities
    """
    if compromised_node_id not in graph.nodes:
        logger.warning(f"Compromised node {compromised_node_id} not found in graph")
        return []

    paths = []
    visited_global: Set[str] = set()

    def dfs(
        current_node_id: str,
        target_node_id: str,
        path_nodes: List[GraphNode],
        path_edges: List[GraphEdge],
        visited_local: Set[str],
        depth: int,
    ) -> None:
        """DFS helper function."""
        if depth > max_depth or len(paths) >= max_paths:
            return

        if target_node_id != compromised_node_id and target_node_id not in visited_global:
            # Found a new reachable node
            min_confidence = min([e.confidence for e in path_edges], default=0.5)
            total_distance = sum([1.0 / max(e.confidence, 0.1) for e in path_edges], default=0.0)

            paths.append(
                Path(
                    nodes=path_nodes.copy(),
                    edges=path_edges.copy(),
                    total_distance=total_distance,
                    confidence=min_confidence,
                )
            )
            visited_global.add(target_node_id)

        # Explore neighbors
        for neighbor_id, edge in graph.get_neighbors(current_node_id):
            if neighbor_id not in visited_local and len(paths) < max_paths:
                visited_local.add(neighbor_id)
                neighbor_node = graph.get_node(neighbor_id)

                dfs(
                    current_node_id=neighbor_id,
                    target_node_id=neighbor_id,
                    path_nodes=path_nodes + [neighbor_node],
                    path_edges=path_edges + [edge],
                    visited_local=visited_local,
                    depth=depth + 1,
                )

                visited_local.remove(neighbor_id)

    # Start DFS from compromised node
    start_node = graph.get_node(compromised_node_id)
    dfs(
        current_node_id=compromised_node_id,
        target_node_id=compromised_node_id,
        path_nodes=[start_node],
        path_edges=[],
        visited_local={compromised_node_id},
        depth=0,
    )

    # Sort by confidence (highest first) and distance (shortest first)
    paths.sort(key=lambda p: (-p.confidence, p.total_distance))

    logger.info(f"Found {len(paths)} lateral movement paths from {compromised_node_id}")
    return paths[:max_paths]


def find_attack_chains(
    graph: GraphData,
    source_entity_type: str = "IP",
) -> List[Path]:
    """
    Find high-confidence attack chains (common attack paths).

    Identifies patterns of lateral movement and privilege escalation.

    Args:
        graph: GraphData object containing nodes and edges
        source_entity_type: Entity type to start search from (default: IP)

    Returns:
        List of identified attack chains
    """
    chains = []

    # Find all nodes of the source type (e.g., all IPs)
    source_nodes = [n for n in graph.nodes.values() if n.entity_type == source_entity_type]

    for source_node in source_nodes:
        lateral_paths = find_all_lateral_paths(graph, source_node.id, max_depth=4, max_paths=3)
        chains.extend(lateral_paths)

    # Sort by confidence and deduplicate
    chains.sort(key=lambda p: -p.confidence)

    # Remove duplicate chains
    unique_chains = []
    seen_chains = set()

    for chain in chains:
        chain_signature = tuple(n.id for n in chain.nodes)
        if chain_signature not in seen_chains:
            seen_chains.add(chain_signature)
            unique_chains.append(chain)

    return unique_chains


def get_attack_surface(
    graph: GraphData,
    compromised_node_id: str,
) -> Dict[str, int]:
    """
    Get the attack surface from a compromised node.

    Counts reachable nodes by type.

    Args:
        graph: GraphData object containing nodes and edges
        compromised_node_id: ID of compromised node

    Returns:
        Dictionary mapping entity type to count of reachable nodes
    """
    reachable = set()
    visited = set()
    queue = deque([compromised_node_id])

    while queue:
        current = queue.popleft()

        if current in visited:
            continue

        visited.add(current)
        reachable.add(current)

        for neighbor_id, _ in graph.get_neighbors(current):
            if neighbor_id not in visited:
                queue.append(neighbor_id)

    # Count by entity type
    attack_surface = {}
    for node_id in reachable:
        node = graph.get_node(node_id)
        if node:
            entity_type = node.entity_type
            attack_surface[entity_type] = attack_surface.get(entity_type, 0) + 1

    return attack_surface


# ============================================================================
# Mock Data Builder (For Testing)
# ============================================================================


def create_mock_threat_graph() -> GraphData:
    """
    Create a mock threat graph for testing without Supabase.

    Simulates a realistic network with multiple lateral movement paths.

    Returns:
        GraphData with sample nodes and edges
    """
    graph = GraphData()

    # Create nodes
    nodes_data = [
        GraphNode("ip_1.1.1.1", "IP", "Attacker IP", "1.1.1.1", {"country": "Unknown"}),
        GraphNode("ip_10.0.0.5", "IP", "Internal IP", "10.0.0.5", {"network": "DMZ"}),
        GraphNode("host_web1", "Host", "Web Server 1", "web1.corp.local", {"os": "Linux"}),
        GraphNode("host_db1", "Host", "Database Server 1", "db1.corp.local", {"os": "Windows"}),
        GraphNode("user_admin", "User", "Admin User", "admin", {"group": "Admins"}),
        GraphNode("user_dev", "User", "Dev User", "developer", {"group": "Developers"}),
        GraphNode("file_credentials", "File", "Credentials File", "/etc/shadow", {"sensitivity": "critical"}),
        GraphNode("process_sshd", "Process", "SSH Daemon", "sshd", {"privilege": "root"}),
        GraphNode("domain_corp", "Domain", "Corporate Domain", "corp.local", {}),
    ]

    for node in nodes_data:
        graph.add_node(node)

    # Create edges (relationships)
    edges_data = [
        # Attacker reaches internal network
        GraphEdge("ip_1.1.1.1", "ip_10.0.0.5", "CONNECTED_TO", 0.95, weight=0.1),
        # Internal IP reaches web server
        GraphEdge("ip_10.0.0.5", "host_web1", "CONNECTED_TO", 0.92, weight=0.15),
        # Web server has vulnerable service
        GraphEdge("host_web1", "user_dev", "EXECUTED_BY", 0.88, weight=0.2),
        # Dev user can access DB server
        GraphEdge("user_dev", "host_db1", "CONNECTED_TO", 0.85, weight=0.25),
        # DB server contains credentials
        GraphEdge("host_db1", "file_credentials", "ACCESSED", 0.90, weight=0.1),
        # Credentials allow admin access
        GraphEdge("file_credentials", "user_admin", "LOGGED_IN_TO", 0.93, weight=0.1),
        # Admin user can execute processes
        GraphEdge("user_admin", "process_sshd", "EXECUTED_BY", 0.95, weight=0.05),
        # Web server connects to domain
        GraphEdge("host_web1", "domain_corp", "CONNECTED_TO", 0.80, weight=0.3),
        # Another path: internal IP to DB directly
        GraphEdge("ip_10.0.0.5", "host_db1", "CONNECTED_TO", 0.70, weight=0.4),
    ]

    for edge in edges_data:
        graph.add_edge(edge)

    logger.info(f"Created mock threat graph with {len(nodes_data)} nodes and {len(edges_data)} edges")
    return graph


# ============================================================================
# Path Serialization (For API Response)
# ============================================================================


def path_to_dict(path: Path) -> Dict:
    """Convert a Path object to dictionary for JSON serialization."""
    return {
        "nodes": [
            {
                "id": node.id,
                "entity_type": node.entity_type,
                "name": node.name,
                "value": node.value,
                "attributes": node.attributes,
            }
            for node in path.nodes
        ],
        "edges": [
            {
                "source_id": edge.source_id,
                "target_id": edge.target_id,
                "relationship_type": edge.relationship_type,
                "confidence": edge.confidence,
                "weight": edge.weight,
                "metadata": edge.metadata,
            }
            for edge in path.edges
        ],
        "total_distance": path.total_distance,
        "confidence": path.confidence,
        "path_length": len(path.nodes),
    }
