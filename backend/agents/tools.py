"""
Agent tools for Argus XDR.
LangChain-compatible tools that the LLM can use for threat mitigation.
These are the "weapons" the agent has access to.
"""

import logging
from typing import Optional, Dict, List, Any

try:
    from langchain.tools import tool
except ImportError:
    raise ImportError("langchain library required. Install with: pip install langchain")


logger = logging.getLogger(__name__)

# In-memory state for mock data (will be replaced by database calls)
_firewall_rules = {}
_isolated_hosts = set()
_threat_intelligence_cache = {}


# ============================================================================
# Tool 1: Block IP Address
# ============================================================================


@tool
def block_ip(ip_address: str) -> Dict[str, Any]:
    """
    Block an IP address at the firewall.

    Creates a firewall rule to deny all traffic from the specified IP.
    In production, this would update the actual firewall system.

    Args:
        ip_address: IP address to block (e.g., "192.168.1.100")

    Returns:
        dict: Status of the blocking operation

    Example:
        >>> block_ip("1.1.1.1")
        {'status': 'success', 'ip': '1.1.1.1', 'action': 'blocked', ...}
    """
    logger.info(f"Attempting to block IP: {ip_address}")

    try:
        # Validate IP format (simple check)
        parts = ip_address.split(".")
        if len(parts) != 4 or not all(0 <= int(p) <= 255 for p in parts):
            return {
                "status": "error",
                "ip": ip_address,
                "message": "Invalid IP address format",
            }

        # Check if already blocked
        if ip_address in _firewall_rules:
            return {
                "status": "already_blocked",
                "ip": ip_address,
                "message": f"IP {ip_address} already blocked",
                "block_time": _firewall_rules[ip_address].get("timestamp"),
            }

        # Mock: Add to firewall rules
        _firewall_rules[ip_address] = {
            "action": "DENY",
            "protocol": "ALL",
            "timestamp": "2024-04-13T10:00:00Z",
            "reason": "Argus XDR Threat Mitigation",
        }

        logger.info(f"Successfully blocked IP: {ip_address}")

        return {
            "status": "success",
            "ip": ip_address,
            "action": "blocked",
            "rule": "DENY ALL from " + ip_address,
            "timestamp": "2024-04-13T10:00:00Z",
            "message": f"Firewall rule created to block {ip_address}",
        }

    except Exception as e:
        logger.error(f"Failed to block IP {ip_address}: {e}")
        return {
            "status": "error",
            "ip": ip_address,
            "message": f"Failed to block IP: {str(e)}",
        }


# ============================================================================
# Tool 2: Isolate Host
# ============================================================================


@tool
def isolate_host(host_id: str, duration_minutes: int = 60) -> Dict[str, Any]:
    """
    Isolate a host from the network (network segmentation).

    Temporarily cuts off network access for a suspicious host to prevent
    lateral movement while investigation proceeds.

    Args:
        host_id: Identifier of host to isolate (hostname, IP, or UUID)
        duration_minutes: How long to isolate (default: 60 minutes)

    Returns:
        dict: Status of isolation operation

    Example:
        >>> isolate_host("web1.corp.local", duration_minutes=120)
        {'status': 'success', 'host_id': 'web1.corp.local', 'isolated': True, ...}
    """
    logger.info(f"Attempting to isolate host: {host_id} for {duration_minutes} minutes")

    try:
        # Check if already isolated
        if host_id in _isolated_hosts:
            return {
                "status": "already_isolated",
                "host_id": host_id,
                "message": f"Host {host_id} is already isolated",
            }

        # Mock: Add to isolated hosts
        _isolated_hosts.add(host_id)

        logger.info(f"Successfully isolated host: {host_id}")

        return {
            "status": "success",
            "host_id": host_id,
            "isolated": True,
            "duration_minutes": duration_minutes,
            "network_access": "denied",
            "timestamp": "2024-04-13T10:00:00Z",
            "message": f"Host {host_id} isolated from network for {duration_minutes} minutes",
            "mitigation_steps": [
                "Network access blocked",
                "Forensic tools queued for execution",
                "Alert notifications sent to security team",
            ],
        }

    except Exception as e:
        logger.error(f"Failed to isolate host {host_id}: {e}")
        return {
            "status": "error",
            "host_id": host_id,
            "message": f"Failed to isolate host: {str(e)}",
        }


# ============================================================================
# Tool 3: Query Threat Intelligence
# ============================================================================


@tool
def query_threat_intel(indicator: str) -> Dict[str, Any]:
    """
    Query threat intelligence from the knowledge base.

    Searches for known attack patterns, detection rules, and mitigation
    strategies related to the indicator.

    Args:
        indicator: Threat indicator to search for
                  (IP, domain, attack technique, process name, etc.)

    Returns:
        dict: Threat intelligence results

    Example:
        >>> query_threat_intel("Pass-the-Hash")
        {'matches': [...], 'attack_pattern': 'lateral_movement', ...}
    """
    logger.info(f"Querying threat intelligence for: {indicator}")

    try:
        # Check cache first
        if indicator in _threat_intelligence_cache:
            return _threat_intelligence_cache[indicator]

        # Mock threat intelligence knowledge base
        threat_db = {
            "pass-the-hash": {
                "status": "found",
                "indicator": "pass-the-hash",
                "attack_tactic": "lateral_movement",
                "description": "Attacker reuses NTLM hash without plaintext password",
                "severity": "high",
                "iocs": ["SMB traffic with stolen NTLM hashes", "Unexpected account logons"],
                "mitigations": [
                    "Enforce NTLMv2 only",
                    "Disable NTLM where possible",
                    "Implement multi-factor authentication",
                ],
                "detection_rules": [
                    "Monitor for unusual NTLM authentication",
                    "Alert on failed authentication attempts with stolen credentials",
                ],
            },
            "dns-tunneling": {
                "status": "found",
                "indicator": "dns-tunneling",
                "attack_tactic": "exfiltration",
                "description": "Attacker uses DNS queries to covertly transmit data",
                "severity": "high",
                "iocs": [
                    "Excessive DNS queries",
                    "Queries with abnormally long subdomains",
                    "Queries to newly registered domains",
                ],
                "mitigations": [
                    "Monitor DNS queries for anomalies",
                    "Implement DNS filtering",
                    "Restrict DNS to authorized servers",
                    "Log all DNS traffic",
                ],
                "detection_rules": [
                    "Alert on unusual DNS query patterns",
                    "Detect beaconing behavior",
                ],
            },
            "scheduled-task-persistence": {
                "status": "found",
                "indicator": "scheduled-task-persistence",
                "attack_tactic": "persistence",
                "description": "Attacker creates scheduled tasks to maintain access",
                "severity": "high",
                "iocs": [
                    "Unusual scheduled task creation",
                    "Tasks with suspicious command lines",
                    "Tasks scheduled at system startup",
                ],
                "mitigations": [
                    "Monitor scheduled task creation",
                    "Restrict task creation permissions",
                    "Audit task execution",
                    "Use Group Policy for task controls",
                ],
                "detection_rules": [
                    "Alert on new scheduled task creation",
                    "Monitor for modification of existing system tasks",
                ],
            },
        }

        # Search for indicator (case-insensitive)
        indicator_lower = indicator.lower()

        result = None
        for key, intel in threat_db.items():
            if indicator_lower in key or key in indicator_lower:
                result = intel
                break

        if not result:
            # No match found
            result = {
                "status": "not_found",
                "indicator": indicator,
                "message": f"No threat intelligence found for '{indicator}'",
                "suggestion": "Indicator may be new or unrecognized. Escalate to threat intelligence team.",
            }

        # Cache result
        _threat_intelligence_cache[indicator] = result

        logger.info(f"Found threat intel for {indicator}")
        return result

    except Exception as e:
        logger.error(f"Failed to query threat intelligence for {indicator}: {e}")
        return {
            "status": "error",
            "indicator": indicator,
            "message": f"Failed to query threat intelligence: {str(e)}",
        }


# ============================================================================
# Tool 4: Analyze Attack Path
# ============================================================================


@tool
def analyze_attack_path(start_node: str, end_node: str) -> Dict[str, Any]:
    """
    Analyze potential attack paths between two entities.

    Uses graph pathfinding to identify how an attacker could move from
    one compromised node to another target.

    Args:
        start_node: ID of compromised/source entity
        end_node: ID of target entity

    Returns:
        dict: Attack path analysis

    Example:
        >>> analyze_attack_path("10.0.0.5", "db1.corp.local")
        {'path_found': True, 'hops': 3, 'risk': 'high', ...}
    """
    logger.info(f"Analyzing attack path from {start_node} to {end_node}")

    try:
        # Mock attack path analysis
        # In production, this would call backend/pathfinding/traversal.py

        return {
            "status": "success",
            "start_node": start_node,
            "end_node": end_node,
            "path_found": True,
            "hops": 3,
            "confidence": 0.87,
            "risk_level": "high",
            "path": [
                start_node,
                "host_web1",
                "user_dev",
                end_node,
            ],
            "path_details": [
                {
                    "from": start_node,
                    "to": "host_web1",
                    "relationship": "CONNECTED_TO",
                    "confidence": 0.92,
                },
                {
                    "from": "host_web1",
                    "to": "user_dev",
                    "relationship": "EXECUTED_BY",
                    "confidence": 0.88,
                },
                {
                    "from": "user_dev",
                    "to": end_node,
                    "relationship": "CONNECTED_TO",
                    "confidence": 0.85,
                },
            ],
            "mitigation_points": [
                "Block connections from compromised node",
                "Monitor and restrict user activity",
                "Isolate target database server",
            ],
        }

    except Exception as e:
        logger.error(f"Failed to analyze attack path: {e}")
        return {
            "status": "error",
            "message": f"Failed to analyze attack path: {str(e)}",
        }


# ============================================================================
# Tool 5: Get Host Information
# ============================================================================


@tool
def get_host_info(host_id: str) -> Dict[str, Any]:
    """
    Get detailed information about a host.

    Retrieves information about a host including OS, services, recent activity,
    and network connections.

    Args:
        host_id: Identifier of host (hostname, IP, or UUID)

    Returns:
        dict: Host information

    Example:
        >>> get_host_info("web1.corp.local")
        {'hostname': 'web1.corp.local', 'os': 'Linux', ...}
    """
    logger.info(f"Retrieving information for host: {host_id}")

    try:
        # Mock host information
        host_info_db = {
            "web1.corp.local": {
                "hostname": "web1.corp.local",
                "ip_address": "10.0.0.10",
                "os": "Linux",
                "os_version": "Ubuntu 20.04",
                "services": ["Apache", "OpenSSH", "MySQL"],
                "last_activity": "2024-04-13T09:45:00Z",
                "network_connections": 142,
                "open_ports": [22, 80, 443, 3306],
                "security_status": "vulnerable",
                "vulnerabilities": ["CVE-2023-1234", "CVE-2023-5678"],
                "isolation_status": "connected",
            },
            "db1.corp.local": {
                "hostname": "db1.corp.local",
                "ip_address": "10.0.0.20",
                "os": "Windows",
                "os_version": "Windows Server 2019",
                "services": ["SQL Server", "Windows Defender", "Event Log Service"],
                "last_activity": "2024-04-13T09:50:00Z",
                "network_connections": 89,
                "open_ports": [1433, 3389],
                "security_status": "patched",
                "vulnerabilities": [],
                "isolation_status": "connected",
            },
        }

        if host_id in host_info_db:
            return {
                "status": "success",
                **host_info_db[host_id],
            }
        else:
            return {
                "status": "not_found",
                "host_id": host_id,
                "message": f"Host {host_id} not found in inventory",
            }

    except Exception as e:
        logger.error(f"Failed to get host info for {host_id}: {e}")
        return {
            "status": "error",
            "host_id": host_id,
            "message": f"Failed to get host information: {str(e)}",
        }


# ============================================================================
# Tool Registry
# ============================================================================


# List of all available tools
AGENT_TOOLS = [
    block_ip,
    isolate_host,
    query_threat_intel,
    analyze_attack_path,
    get_host_info,
]


def get_tools_description() -> str:
    """Get formatted description of all available tools."""
    descriptions = []
    for tool_func in AGENT_TOOLS:
        descriptions.append(f"- {tool_func.name}: {tool_func.description}")
    return "\n".join(descriptions)
