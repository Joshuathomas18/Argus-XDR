"""
Knowledge base module for Argus XDR.
Manages curated threat intelligence and attack patterns.
Reuses structure from RV32I's knowledge.py.
"""

import logging
from dataclasses import dataclass
from typing import Literal, Optional

from backend.core.database import insert_knowledge_entry, query_knowledge
from backend.rag.embedder import embed_text
from backend.core.config import get_settings


logger = logging.getLogger(__name__)


@dataclass
class KnowledgeEntry:
    """
    Knowledge base entry structure.
    Reuses pattern from RV32I's knowledge.py lines 25-31.
    """

    id: str
    category: Literal["attack_pattern", "detection_rule", "mitigation_strategy"]
    title: str
    description: Optional[str]
    content: str
    metadata: Optional[dict] = None


# Curated threat intelligence knowledge base
THREAT_INTELLIGENCE = [
    # Lateral Movement
    KnowledgeEntry(
        id="attack_lateral_movement_pth",
        category="attack_pattern",
        title="Pass-the-Hash (PtH) Attack",
        description="Attacker reuses NTLM hash without knowing plaintext password",
        content="""
        Pass-the-Hash (PtH) is a lateral movement technique where an attacker captures
        NTLM password hashes and uses them directly for authentication without needing
        the plaintext password. This is possible because NTLM authentication relies on
        the hash rather than the plaintext password.

        IOCs: Unusual account logons from compromised systems, failed authentication
        attempts with stolen credentials, unexpected lateral movement to critical systems.

        Mitigation: Enforce NTLMv2 only, disable NTLM where possible, implement
        multifactor authentication, use Kerberos over NTLM.
        """,
        metadata={"severity": "high", "tactic": "lateral_movement"},
    ),
    KnowledgeEntry(
        id="attack_lateral_movement_kerberoasting",
        category="attack_pattern",
        title="Kerberoasting Attack",
        description="Attacker requests service tickets for accounts with weak passwords",
        content="""
        Kerberoasting is a technique where an attacker requests Kerberos TGS tickets
        for service accounts and attempts to crack them offline. Service accounts often
        have weaker passwords than user accounts, making them vulnerable.

        IOCs: Unusual spike in TGS-REQ requests, accounts requesting multiple service
        tickets for different services, ticket requests for service accounts.

        Mitigation: Use strong passwords for service accounts, enable MFA, monitor for
        unusual ticket requests, implement ticket encryption.
        """,
        metadata={"severity": "high", "tactic": "lateral_movement"},
    ),
    # Data Exfiltration
    KnowledgeEntry(
        id="attack_exfil_dns_tunneling",
        category="attack_pattern",
        title="DNS Tunneling Data Exfiltration",
        description="Attacker uses DNS queries to covertly transmit data out of network",
        content="""
        DNS tunneling encodes data in DNS queries and responses to exfiltrate information
        from networks that are otherwise isolated. DNS is often allowed through firewalls,
        making it attractive for data exfiltration.

        IOCs: Excessive DNS queries to unusual domains, queries with abnormally long
        subdomains, unusual query-to-response ratio, queries to newly registered domains.

        Mitigation: Monitor DNS queries for anomalies, implement DNS filtering, restrict
        DNS to authorized servers only, log all DNS traffic.
        """,
        metadata={"severity": "high", "tactic": "exfiltration"},
    ),
    KnowledgeEntry(
        id="attack_exfil_https_beaconing",
        category="attack_pattern",
        title="HTTPS C2 Beaconing",
        description="Malware uses HTTPS for command and control and data exfiltration",
        content="""
        Attackers establish command and control (C2) channels over HTTPS to avoid detection.
        This technique encrypts command and data traffic, making it difficult for network
        monitoring tools to detect without SSL/TLS inspection.

        IOCs: Unusual HTTPS traffic to external IPs, consistent beacon intervals,
        traffic to known C2 domains, SSL certificates from suspicious CAs.

        Mitigation: Implement SSL/TLS inspection, maintain TLS certificate whitelist,
        monitor for suspicious certificate usage, implement network segmentation.
        """,
        metadata={"severity": "critical", "tactic": "exfiltration"},
    ),
    # Privilege Escalation
    KnowledgeEntry(
        id="attack_privesc_uac_bypass",
        category="attack_pattern",
        title="Windows UAC Bypass",
        description="Attacker bypasses User Account Control to gain elevated privileges",
        content="""
        Windows User Account Control (UAC) is a security mechanism that restricts
        administrative privileges. Attackers use UAC bypass techniques to elevate
        their privileges without user interaction or detection.

        IOCs: Unusual process spawning with elevated privileges, DLL injection into
        system processes, registry modifications related to UAC, unexpected administrative
        actions.

        Mitigation: Keep Windows updated, enforce UAC settings, restrict local admin
        accounts, disable remote UAC bypass vectors, monitor process creation.
        """,
        metadata={"severity": "high", "tactic": "privilege_escalation"},
    ),
    # Persistence
    KnowledgeEntry(
        id="attack_persistence_scheduled_task",
        category="attack_pattern",
        title="Persistence via Scheduled Tasks",
        description="Attacker creates scheduled tasks to maintain persistent access",
        content="""
        Attackers create Windows scheduled tasks to maintain persistent access and
        achieve code execution at specified intervals or system events. Scheduled tasks
        can be configured to run with SYSTEM privileges.

        IOCs: Creation of unusual scheduled tasks, tasks with suspicious command lines,
        tasks scheduled to run at system startup, modifications to existing system tasks.

        Mitigation: Monitor scheduled task creation and modification, restrict task
        creation permissions, audit task execution, use Group Policy to control tasks.
        """,
        metadata={"severity": "high", "tactic": "persistence"},
    ),
    KnowledgeEntry(
        id="attack_persistence_registry_modification",
        category="attack_pattern",
        title="Windows Registry Persistence",
        description="Attacker modifies registry to achieve persistence",
        content="""
        Windows registry modifications can establish persistence through run keys,
        auto-start locations, and other registry entries that execute code at startup
        or logon.

        IOCs: Creation of run keys, modifications to startup locations, suspicious
        shell extensions, unexpected registry modifications in security-relevant locations.

        Mitigation: Monitor registry modifications in critical locations, implement
        registry write restrictions, use AppLocker to control execution, audit registry
        access.
        """,
        metadata={"severity": "high", "tactic": "persistence"},
    ),
    # Defense Evasion
    KnowledgeEntry(
        id="attack_evasion_log_clearing",
        category="attack_pattern",
        title="Event Log Clearing",
        description="Attacker clears Windows event logs to remove traces",
        content="""
        Attackers clear Windows event logs to remove evidence of their activities.
        This is often one of the last steps in an attack to eliminate the audit trail.

        IOCs: Sudden drop in event log entries, missing logs during incident window,
        clearing of security event log, unusual use of log clearing utilities.

        Mitigation: Implement centralized logging, forward logs to immutable storage,
        monitor for log clearing events, restrict log clearing permissions, use SIEM
        for alerting on log gaps.
        """,
        metadata={"severity": "critical", "tactic": "defense_evasion"},
    ),
    # Detection Rules
    KnowledgeEntry(
        id="detection_suspicious_process_creation",
        category="detection_rule",
        title="Suspicious Process Creation",
        description="Detect processes spawned from unusual parent processes",
        content="""
        Detects potentially suspicious process creation patterns that may indicate
        malware execution, privilege escalation, or other attacks.

        Rules:
        - cmd.exe or PowerShell spawned from Office applications
        - System processes (lsass, svchost) spawning uncommon children
        - Network utilities (curl, wget) spawned from Office or browsers
        - Script interpreters (python, node) spawned from system processes

        False positives: Legitimate automation, administrative scripts, valid updates.
        """,
        metadata={"severity": "medium", "tactic": "detection"},
    ),
    KnowledgeEntry(
        id="detection_network_anomaly",
        category="detection_rule",
        title="Network Anomaly Detection",
        description="Detect unusual network traffic patterns",
        content="""
        Identifies network traffic that deviates from baseline behavior, which may
        indicate malware communication, lateral movement, or data exfiltration.

        Indicators:
        - Connections to new external IPs during off-hours
        - Unusually large data transfers to external networks
        - Beaconing patterns (regular intervals)
        - Connections to known malicious IPs
        - Unusual DNS queries

        Analysis: Compare against baseline traffic patterns, identify new connections,
        correlate with other security events.
        """,
        metadata={"severity": "medium", "tactic": "detection"},
    ),
    # Mitigation Strategies
    KnowledgeEntry(
        id="mitigation_network_segmentation",
        category="mitigation_strategy",
        title="Network Segmentation and Isolation",
        description="Implement network controls to contain threats",
        content="""
        Network segmentation divides the network into isolated zones with controlled
        access between them. This limits lateral movement and reduces the blast radius
        of breaches.

        Implementation:
        - Create security zones (DMZ, internal, critical assets)
        - Implement firewall rules between zones
        - Use VLANs to isolate workgroups
        - Monitor inter-zone traffic
        - Restrict service account access

        Benefits: Limits lateral movement, reduces blast radius, improves monitoring,
        controls privilege escalation.
        """,
        metadata={"severity": "critical", "tactic": "mitigation"},
    ),
    KnowledgeEntry(
        id="mitigation_endpoint_hardening",
        category="mitigation_strategy",
        title="Endpoint Hardening",
        description="Secure individual endpoints to resist attacks",
        content="""
        Endpoint hardening reduces the attack surface and makes systems more resistant
        to exploitation and malware.

        Controls:
        - Disable unnecessary services and protocols
        - Enable Windows Firewall with strict rules
        - Enforce strong password policies and MFA
        - Keep systems patched and updated
        - Restrict administrative privileges (principle of least privilege)
        - Enable audit logging and monitoring

        Tools: AppLocker, Device Guard, Windows Defender, EDR solutions.
        """,
        metadata={"severity": "high", "tactic": "mitigation"},
    ),
]


def build_knowledge_base(force_rebuild: bool = False) -> list[KnowledgeEntry]:
    """
    Build and store the knowledge base.
    Reuses pattern from RV32I's knowledge.py lines 496-546.

    Args:
        force_rebuild: If True, rebuild even if KB already exists

    Returns:
        list: List of KnowledgeEntry objects that were stored
    """
    settings = get_settings()

    # Check if KB already built (optional optimization)
    existing_entries = query_knowledge(limit=1)
    if existing_entries and not force_rebuild:
        logger.info("Knowledge base already built, skipping rebuild (use force_rebuild=True to force)")
        return THREAT_INTELLIGENCE

    logger.info(f"Building knowledge base with {len(THREAT_INTELLIGENCE)} entries...")

    stored_entries = []
    for i, entry in enumerate(THREAT_INTELLIGENCE):
        try:
            # Generate embedding for this entry
            embedding = embed_text(entry.content)

            # Store in database
            insert_knowledge_entry(
                category=entry.category,
                title=entry.title,
                content=entry.content,
                embedding=embedding,
                description=entry.description,
                metadata=entry.metadata,
            )

            stored_entries.append(entry)

            if (i + 1) % 5 == 0:
                logger.info(f"Stored {i + 1}/{len(THREAT_INTELLIGENCE)} knowledge entries")

        except Exception as e:
            logger.error(f"Failed to store knowledge entry {entry.title}: {e}")
            continue

    logger.info(f"Knowledge base built with {len(stored_entries)} entries")
    return stored_entries


def get_knowledge_entries() -> list[KnowledgeEntry]:
    """Get the curated knowledge entries."""
    return THREAT_INTELLIGENCE


def get_knowledge_by_category(category: str) -> list[KnowledgeEntry]:
    """Get knowledge entries by category."""
    return [entry for entry in THREAT_INTELLIGENCE if entry.category == category]
