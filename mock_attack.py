#!/usr/bin/env python3
"""
Attack Simulator for Argus XDR Demo.

Generates a realistic multi-hop lateral movement attack with perfectly formatted
JSON logs that feed directly into the /api/ingest/logs endpoint.

Attack Scenario:
1. External attacker compromises DMZ IP
2. Lateral movement through web server
3. Privilege escalation via developer user
4. Database server compromise
5. Credential theft and exfiltration

This is the DEMO KILLER - shows the entire pipeline working end-to-end.
"""

import json
import requests
import time
from datetime import datetime, timedelta
from typing import List, Dict, Any
import argparse
import sys


# ============================================================================
# Configuration
# ============================================================================

API_BASE_URL = "http://localhost:8000"
INGEST_ENDPOINT = f"{API_BASE_URL}/api/ingest/logs"
MITIGATE_ENDPOINT = f"{API_BASE_URL}/api/agents/mitigate"
PATHFINDING_ENDPOINT = f"{API_BASE_URL}/api/pathfinding/routes"

# Attack timeline (in seconds from start)
ATTACK_TIMELINE = {
    "stage_1_initial_compromise": 0,       # T+0s: Initial compromise
    "stage_2_reconnaissance": 5,            # T+5s: Reconnaissance
    "stage_3_lateral_movement": 10,         # T+10s: Lateral movement
    "stage_4_privilege_escalation": 20,     # T+20s: Privilege escalation
    "stage_5_database_access": 30,          # T+30s: Database access
    "stage_6_credential_theft": 40,         # T+40s: Credential theft
    "stage_7_exfiltration": 50,             # T+50s: Exfiltration
}

# Entity IPs and hostnames
ATTACKER_IP = "1.1.1.1"
INTERNAL_IP = "10.0.0.5"
WEB_SERVER = "web1.corp.local"
WEB_SERVER_IP = "10.0.0.10"
DB_SERVER = "db1.corp.local"
DB_SERVER_IP = "10.0.0.20"
FILE_SERVER = "fileserver.corp.local"
FILE_SERVER_IP = "10.0.0.30"

USERS = {
    "dev": "developer@corp.local",
    "admin": "admin@corp.local",
    "service": "svc_db@corp.local",
}


# ============================================================================
# Log Generation Functions
# ============================================================================


def create_base_event(timestamp: datetime, event_type: str, severity: str) -> Dict[str, Any]:
    """Create a base event with common fields."""
    return {
        "timestamp": timestamp.isoformat() + "Z",
        "event_type": event_type,
        "severity": severity,
        "source_ip": None,
        "source_user": None,
        "target_resource": None,
        "action": None,
        "metadata": {
            "simulation": True,
            "attack_phase": "unknown",
        },
    }


def stage_1_initial_compromise(base_time: datetime) -> List[Dict[str, Any]]:
    """
    STAGE 1: Initial Compromise
    External attacker probes DMZ firewall and gains initial foothold.
    """
    events = []

    # Failed SSH attempts (reconnaissance)
    for i in range(3):
        event = create_base_event(
            base_time + timedelta(seconds=ATTACK_TIMELINE["stage_1_initial_compromise"] + i),
            "ssh_attempt",
            "high",
        )
        event.update({
            "source_ip": ATTACKER_IP,
            "target_resource": WEB_SERVER,
            "action": "failed_login",
            "metadata": {
                "simulation": True,
                "attack_phase": "initial_compromise",
                "attempt": i + 1,
                "username": "admin",
                "port": 22,
            },
        })
        events.append(event)

    # Successful exploitation
    event = create_base_event(
        base_time + timedelta(seconds=ATTACK_TIMELINE["stage_1_initial_compromise"] + 3),
        "rce_exploit",
        "critical",
    )
    event.update({
        "source_ip": ATTACKER_IP,
        "target_resource": WEB_SERVER,
        "action": "code_execution",
        "metadata": {
            "simulation": True,
            "attack_phase": "initial_compromise",
            "vulnerability": "CVE-2023-1234",
            "technique": "Remote Code Execution via HTTP request",
            "payload": "Base64-encoded shell command",
        },
    })
    events.append(event)

    return events


def stage_2_reconnaissance(base_time: datetime) -> List[Dict[str, Any]]:
    """
    STAGE 2: Reconnaissance
    Attacker enumerates network from web server.
    """
    events = []

    # DNS queries to discover internal hosts
    targets = [DB_SERVER, FILE_SERVER, "dc.corp.local"]
    for target in targets:
        event = create_base_event(
            base_time + timedelta(seconds=ATTACK_TIMELINE["stage_2_reconnaissance"]),
            "dns_query",
            "medium",
        )
        event.update({
            "source_ip": WEB_SERVER_IP,
            "target_resource": target,
            "action": "dns_resolution",
            "metadata": {
                "simulation": True,
                "attack_phase": "reconnaissance",
                "dns_server": "10.0.0.1",
            },
        })
        events.append(event)

    # Port scanning (connection attempts)
    for port in [3306, 1433, 445, 139]:
        event = create_base_event(
            base_time + timedelta(seconds=ATTACK_TIMELINE["stage_2_reconnaissance"] + 2),
            "port_scan",
            "high",
        )
        event.update({
            "source_ip": WEB_SERVER_IP,
            "target_resource": DB_SERVER,
            "action": "connection_attempt",
            "metadata": {
                "simulation": True,
                "attack_phase": "reconnaissance",
                "port": port,
                "status": "open",
            },
        })
        events.append(event)

    return events


def stage_3_lateral_movement(base_time: datetime) -> List[Dict[str, Any]]:
    """
    STAGE 3: Lateral Movement
    Attacker moves from web server to internal network.
    """
    events = []

    # Network traffic to internal subnet
    event = create_base_event(
        base_time + timedelta(seconds=ATTACK_TIMELINE["stage_3_lateral_movement"]),
        "network_connection",
        "high",
    )
    event.update({
        "source_ip": WEB_SERVER_IP,
        "target_resource": f"{DB_SERVER}:3306",
        "action": "connection_established",
        "metadata": {
            "simulation": True,
            "attack_phase": "lateral_movement",
            "protocol": "MySQL",
            "bytes_transferred": 2048,
            "duration_seconds": 30,
        },
    })
    events.append(event)

    # SMB enumeration
    event = create_base_event(
        base_time + timedelta(seconds=ATTACK_TIMELINE["stage_3_lateral_movement"] + 2),
        "smb_enumeration",
        "high",
    )
    event.update({
        "source_ip": WEB_SERVER_IP,
        "target_resource": FILE_SERVER,
        "action": "share_enumeration",
        "metadata": {
            "simulation": True,
            "attack_phase": "lateral_movement",
            "shares_discovered": ["C$", "ADMIN$", "Documents"],
        },
    })
    events.append(event)

    return events


def stage_4_privilege_escalation(base_time: datetime) -> List[Dict[str, Any]]:
    """
    STAGE 4: Privilege Escalation
    Attacker escalates privileges via developer user.
    """
    events = []

    # Process execution as developer
    event = create_base_event(
        base_time + timedelta(seconds=ATTACK_TIMELINE["stage_4_privilege_escalation"]),
        "process_creation",
        "high",
    )
    event.update({
        "source_ip": WEB_SERVER_IP,
        "source_user": USERS["dev"],
        "target_resource": "powershell.exe",
        "action": "process_spawned",
        "metadata": {
            "simulation": True,
            "attack_phase": "privilege_escalation",
            "process_name": "powershell.exe",
            "parent_process": "apache2.exe",
            "command_line": "powershell -NoProfile -WindowStyle Hidden -Command Get-ADUser",
            "privileges": "medium",
        },
    })
    events.append(event)

    # UAC bypass attempt
    event = create_base_event(
        base_time + timedelta(seconds=ATTACK_TIMELINE["stage_4_privilege_escalation"] + 2),
        "uac_bypass",
        "critical",
    )
    event.update({
        "source_ip": WEB_SERVER_IP,
        "source_user": USERS["dev"],
        "target_resource": "eventvwr.exe",
        "action": "privilege_escalation_attempted",
        "metadata": {
            "simulation": True,
            "attack_phase": "privilege_escalation",
            "technique": "Event Viewer Bypass",
            "target_privilege": "SYSTEM",
            "success": True,
        },
    })
    events.append(event)

    # Successful elevation
    event = create_base_event(
        base_time + timedelta(seconds=ATTACK_TIMELINE["stage_4_privilege_escalation"] + 3),
        "privilege_elevation",
        "critical",
    )
    event.update({
        "source_ip": WEB_SERVER_IP,
        "source_user": USERS["admin"],
        "target_resource": "system_shell",
        "action": "admin_shell_spawned",
        "metadata": {
            "simulation": True,
            "attack_phase": "privilege_escalation",
            "new_privilege_level": "SYSTEM",
            "token_elevation": True,
        },
    })
    events.append(event)

    return events


def stage_5_database_access(base_time: datetime) -> List[Dict[str, Any]]:
    """
    STAGE 5: Database Access
    Attacker connects to database server with stolen credentials.
    """
    events = []

    # SQL Server connection attempt
    event = create_base_event(
        base_time + timedelta(seconds=ATTACK_TIMELINE["stage_5_database_access"]),
        "sql_login",
        "critical",
    )
    event.update({
        "source_ip": WEB_SERVER_IP,
        "source_user": USERS["service"],
        "target_resource": DB_SERVER,
        "action": "database_login",
        "metadata": {
            "simulation": True,
            "attack_phase": "database_access",
            "database": "production_db",
            "query_count": 47,
            "unusual_queries": ["SELECT * FROM users", "SELECT * FROM credit_cards"],
        },
    })
    events.append(event)

    # Suspicious database queries
    for i, query in enumerate(["SELECT COUNT(*) FROM users", "SELECT * FROM users WHERE role='admin'"]):
        event = create_base_event(
            base_time + timedelta(seconds=ATTACK_TIMELINE["stage_5_database_access"] + 2 + i),
            "sql_query",
            "high",
        )
        event.update({
            "source_ip": WEB_SERVER_IP,
            "source_user": USERS["service"],
            "target_resource": DB_SERVER,
            "action": "database_query",
            "metadata": {
                "simulation": True,
                "attack_phase": "database_access",
                "query": query,
                "rows_returned": 1000 * (i + 1),
            },
        })
        events.append(event)

    return events


def stage_6_credential_theft(base_time: datetime) -> List[Dict[str, Any]]:
    """
    STAGE 6: Credential Theft
    Attacker extracts credentials and sensitive data.
    """
    events = []

    # Credential extraction
    event = create_base_event(
        base_time + timedelta(seconds=ATTACK_TIMELINE["stage_6_credential_theft"]),
        "credential_access",
        "critical",
    )
    event.update({
        "source_ip": WEB_SERVER_IP,
        "source_user": USERS["admin"],
        "target_resource": "credential_store",
        "action": "credentials_dumped",
        "metadata": {
            "simulation": True,
            "attack_phase": "credential_theft",
            "tool": "Mimikatz",
            "credentials_extracted": 23,
            "includes_domain_admin": True,
        },
    })
    events.append(event)

    # NTLM hash extraction
    event = create_base_event(
        base_time + timedelta(seconds=ATTACK_TIMELINE["stage_6_credential_theft"] + 2),
        "ntlm_capture",
        "critical",
    )
    event.update({
        "source_ip": WEB_SERVER_IP,
        "source_user": USERS["admin"],
        "target_resource": "lsass.exe",
        "action": "process_memory_dumped",
        "metadata": {
            "simulation": True,
            "attack_phase": "credential_theft",
            "process": "lsass.exe (Local Security Authority Subsystem Service)",
            "hashes_extracted": 15,
        },
    })
    events.append(event)

    return events


def stage_7_exfiltration(base_time: datetime) -> List[Dict[str, Any]]:
    """
    STAGE 7: Exfiltration
    Attacker exfiltrates sensitive data via DNS tunneling and HTTPS.
    """
    events = []

    # DNS tunneling for data exfiltration
    event = create_base_event(
        base_time + timedelta(seconds=ATTACK_TIMELINE["stage_7_exfiltration"]),
        "dns_tunneling",
        "critical",
    )
    event.update({
        "source_ip": WEB_SERVER_IP,
        "target_resource": "attacker-c2.com",
        "action": "dns_exfiltration",
        "metadata": {
            "simulation": True,
            "attack_phase": "exfiltration",
            "subdomain_pattern": "base64-encoded-data.attacker-c2.com",
            "query_count": 342,
            "data_size_mb": 245,
            "domains_contacted": ["attacker-c2.com", "backup-c2.com"],
        },
    })
    events.append(event)

    # HTTPS beaconing
    event = create_base_event(
        base_time + timedelta(seconds=ATTACK_TIMELINE["stage_7_exfiltration"] + 3),
        "https_exfiltration",
        "critical",
    )
    event.update({
        "source_ip": WEB_SERVER_IP,
        "target_resource": "https://attacker-c2.com/api/upload",
        "action": "data_exfiltration",
        "metadata": {
            "simulation": True,
            "attack_phase": "exfiltration",
            "protocol": "HTTPS",
            "bytes_uploaded": 257280,
            "content": "user_database_dump.sql.gz",
            "certificate_issuer": "Let's Encrypt",
        },
    })
    events.append(event)

    # Beaconing pattern
    for i in range(3):
        event = create_base_event(
            base_time + timedelta(seconds=ATTACK_TIMELINE["stage_7_exfiltration"] + 5 + (i * 60)),
            "c2_beacon",
            "critical",
        )
        event.update({
            "source_ip": WEB_SERVER_IP,
            "target_resource": "attacker-c2.com",
            "action": "c2_communication",
            "metadata": {
                "simulation": True,
                "attack_phase": "exfiltration",
                "interval_seconds": 60,
                "beacon_count": i + 1,
                "response_size_bytes": 512,
            },
        })
        events.append(event)

    return events


# ============================================================================
# Main Attack Simulation
# ============================================================================


def generate_attack_logs(base_time: datetime = None) -> List[Dict[str, Any]]:
    """Generate complete attack log sequence."""
    if base_time is None:
        base_time = datetime.utcnow() - timedelta(seconds=60)

    all_logs = []

    print("\n" + "=" * 80)
    print("ARGUS XDR ATTACK SIMULATOR - LOG GENERATION")
    print("=" * 80)

    # Generate logs for each stage
    stages = [
        ("Stage 1: Initial Compromise", stage_1_initial_compromise),
        ("Stage 2: Reconnaissance", stage_2_reconnaissance),
        ("Stage 3: Lateral Movement", stage_3_lateral_movement),
        ("Stage 4: Privilege Escalation", stage_4_privilege_escalation),
        ("Stage 5: Database Access", stage_5_database_access),
        ("Stage 6: Credential Theft", stage_6_credential_theft),
        ("Stage 7: Exfiltration", stage_7_exfiltration),
    ]

    for stage_name, stage_func in stages:
        logs = stage_func(base_time)
        all_logs.extend(logs)
        print(f"✓ {stage_name}: {len(logs)} logs generated")

    print(f"\n📊 Total logs generated: {len(all_logs)}")
    print("=" * 80 + "\n")

    return all_logs


def send_logs_to_api(logs: List[Dict[str, Any]], delay: float = 0.5, verbose: bool = True) -> Dict[str, Any]:
    """Send logs to Argus XDR API."""
    print("\n" + "=" * 80)
    print("SENDING LOGS TO ARGUS XDR API")
    print("=" * 80)
    print(f"Endpoint: {INGEST_ENDPOINT}\n")

    try:
        payload = {
            "logs": logs,
            "source_type": "custom_json",
        }

        if verbose:
            print(f"Sending {len(logs)} logs...")

        response = requests.post(
            INGEST_ENDPOINT,
            json=payload,
            timeout=30,
        )

        if response.status_code == 202:
            result = response.json()
            print(f"✓ Ingestion accepted (HTTP {response.status_code})")
            print(f"  - Logs ingested: {result.get('ingested', 0)}")
            print(f"  - Entities extracted: {result.get('entities', 0)}")
            print(f"  - Relationships built: {result.get('edges', 0)}")
            print(f"  - Errors: {result.get('errors', 0)}")
            return result

        elif response.status_code in [200, 201]:
            result = response.json()
            print(f"✓ Ingestion successful (HTTP {response.status_code})")
            return result

        else:
            print(f"✗ Error: HTTP {response.status_code}")
            print(f"Response: {response.text}")
            return {"status": "error", "http_code": response.status_code}

    except requests.exceptions.ConnectionError:
        print("✗ ERROR: Could not connect to Argus XDR API")
        print(f"  Make sure the server is running at {API_BASE_URL}")
        print(f"  Run: python -m uvicorn backend.main:app --reload")
        return {"status": "error", "message": "Connection refused"}

    except Exception as e:
        print(f"✗ ERROR: {e}")
        return {"status": "error", "message": str(e)}


def trigger_mitigation(threat_query: str) -> Dict[str, Any]:
    """Trigger agent mitigation."""
    print("\n" + "=" * 80)
    print("TRIGGERING AUTONOMOUS THREAT MITIGATION")
    print("=" * 80)
    print(f"Query: {threat_query}\n")

    try:
        payload = {
            "query": threat_query,
            "severity": "critical",
            "source_ip": ATTACKER_IP,
            "affected_entities": [WEB_SERVER, DB_SERVER],
            "attack_pattern": "multi-stage lateral movement with data exfiltration",
            "confidence": 0.92,
        }

        response = requests.post(
            MITIGATE_ENDPOINT,
            json=payload,
            timeout=30,
        )

        if response.status_code == 200:
            result = response.json()
            print(f"✓ Mitigation orchestrated (HTTP {response.status_code})")
            print(f"  - Status: {result.get('status')}")
            print(f"  - Severity: {result.get('severity')}")
            print(f"  - Confidence: {result.get('confidence')}")
            print(f"  - Actions taken: {len(result.get('actions_taken', []))}")
            for action in result.get("actions_taken", []):
                print(f"    • {action}")
            print(f"\n  - Recommendations:")
            for rec in result.get("recommendations", [])[:3]:
                print(f"    • {rec}")
            return result

        else:
            print(f"✗ Error: HTTP {response.status_code}")
            print(f"Response: {response.text}")
            return {"status": "error", "http_code": response.status_code}

    except requests.exceptions.ConnectionError:
        print("✗ ERROR: Could not connect to Argus XDR API")
        return {"status": "error", "message": "Connection refused"}

    except Exception as e:
        print(f"✗ ERROR: {e}")
        return {"status": "error", "message": str(e)}


def query_pathfinding() -> Dict[str, Any]:
    """Query pathfinding engine."""
    print("\n" + "=" * 80)
    print("QUERYING PATHFINDING ENGINE")
    print("=" * 80)
    print(f"Finding attack paths from {WEB_SERVER_IP}...\n")

    try:
        payload = {
            "start_node_id": f"ip_{WEB_SERVER_IP}",
            "max_depth": 5,
        }

        response = requests.post(
            PATHFINDING_ENDPOINT,
            json=payload,
            timeout=30,
        )

        if response.status_code == 200:
            result = response.json()
            print(f"✓ Pathfinding complete (HTTP {response.status_code})")
            print(f"  - Paths found: {result.get('paths_found', 0)}")
            print(f"  - Attack surface:")
            for entity_type, count in result.get("attack_surface", {}).items():
                print(f"    • {entity_type}: {count} nodes")
            return result

        else:
            print(f"✗ Error: HTTP {response.status_code}")
            return {"status": "error", "http_code": response.status_code}

    except Exception as e:
        print(f"✗ ERROR: {e}")
        return {"status": "error", "message": str(e)}


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Argus XDR Attack Simulator - Demo attack scenario generator"
    )
    parser.add_argument(
        "--no-ingest",
        action="store_true",
        help="Don't send logs to API (just generate and print)",
    )
    parser.add_argument(
        "--no-mitigate",
        action="store_true",
        help="Don't trigger mitigation (just ingest logs)",
    )
    parser.add_argument(
        "--no-pathfinding",
        action="store_true",
        help="Don't query pathfinding engine",
    )
    parser.add_argument(
        "--url",
        default=API_BASE_URL,
        help="Argus XDR API base URL",
    )
    parser.add_argument(
        "--output",
        type=str,
        help="Save logs to JSON file instead of sending",
    )

    args = parser.parse_args()

    # Update API URL if provided
    if args.url != API_BASE_URL:
        global INGEST_ENDPOINT, MITIGATE_ENDPOINT, PATHFINDING_ENDPOINT
        INGEST_ENDPOINT = f"{args.url}/api/ingest/logs"
        MITIGATE_ENDPOINT = f"{args.url}/api/agents/mitigate"
        PATHFINDING_ENDPOINT = f"{args.url}/api/pathfinding/routes"

    # Generate attack logs
    logs = generate_attack_logs()

    # Save to file if requested
    if args.output:
        with open(args.output, "w") as f:
            json.dump(logs, f, indent=2)
        print(f"✓ Logs saved to {args.output}")
        return

    # Send to API
    if not args.no_ingest:
        ingestion_result = send_logs_to_api(logs)

        # Query pathfinding
        if not args.no_pathfinding:
            time.sleep(1)  # Wait for logs to be processed
            pathfinding_result = query_pathfinding()

        # Trigger mitigation
        if not args.no_mitigate:
            time.sleep(1)
            mitigation_result = trigger_mitigation(
                "CRITICAL: Multi-stage attack detected with lateral movement and data exfiltration"
            )

    print("\n" + "=" * 80)
    print("ATTACK SIMULATION COMPLETE")
    print("=" * 80)
    print("The attack scenario has been processed through the Argus XDR pipeline:")
    print("  1. ✓ Logs ingested and parsed")
    print("  2. ✓ Entities extracted and relationships built")
    print("  3. ✓ Attack paths discovered via pathfinding")
    print("  4. ✓ Threat analyzed by knowledge base")
    print("  5. ✓ Autonomous mitigation executed by agent")
    print("\nView results in the API responses above.")
    print("=" * 80 + "\n")


if __name__ == "__main__":
    main()
