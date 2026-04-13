"""
Log parser for Argus XDR.
Normalizes security events from multiple sources (syslog, cloud audit, Windows events).
"""

import logging
import json
from datetime import datetime
from typing import Optional, Dict, Any

from backend.core.config import get_settings


logger = logging.getLogger(__name__)


def parse_custom_json(json_log: Dict[str, Any]) -> Dict[str, Any]:
    """
    Parse custom JSON log format.

    Expected fields:
    - timestamp (ISO format string or Unix timestamp)
    - event_type (string)
    - severity (string)
    - source_ip (string, optional)
    - source_user (string, optional)
    - target_resource (string, optional)
    - action (string)
    - metadata (dict, optional)

    Args:
        json_log: Dictionary containing the custom JSON log

    Returns:
        dict: Normalized event
    """
    try:
        # Handle timestamp
        timestamp = json_log.get("timestamp")
        if isinstance(timestamp, int):
            # Unix timestamp
            timestamp = datetime.fromtimestamp(timestamp).isoformat()
        elif isinstance(timestamp, str):
            # Already ISO format or will be parsed
            try:
                # Validate ISO format
                datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
            except ValueError:
                timestamp = datetime.now().isoformat()
        else:
            timestamp = datetime.now().isoformat()

        normalized = {
            "timestamp": timestamp,
            "source_type": "custom_json",
            "event_type": json_log.get("event_type", "unknown"),
            "severity": json_log.get("severity", "info").lower(),
            "source_ip": json_log.get("source_ip"),
            "source_user": json_log.get("source_user"),
            "target_resource": json_log.get("target_resource"),
            "action": json_log.get("action", "unknown"),
            "raw_data": json_log,
            "normalized_data": {
                "original_fields": json_log,
            },
            "metadata": json_log.get("metadata", {}),
        }

        return normalized

    except Exception as e:
        logger.error(f"Error parsing custom JSON log: {e}")
        return None


def parse_syslog(raw_log: str) -> Optional[Dict[str, Any]]:
    """
    Parse syslog format.

    Expected format:
    Month Day HH:MM:SS hostname process[PID]: message

    Args:
        raw_log: Raw syslog line

    Returns:
        dict: Normalized event or None if parsing fails
    """
    try:
        # For MVP, treat syslog as raw text and extract basic fields
        # In production, use syslog parsing library

        normalized = {
            "timestamp": datetime.now().isoformat(),
            "source_type": "syslog",
            "event_type": "system_event",
            "severity": extract_severity_from_text(raw_log),
            "source_ip": extract_ip_from_text(raw_log),
            "source_user": None,
            "target_resource": None,
            "action": extract_action_from_text(raw_log),
            "raw_data": {"raw_log": raw_log},
            "normalized_data": {
                "raw_text": raw_log,
            },
            "metadata": {},
        }

        return normalized

    except Exception as e:
        logger.error(f"Error parsing syslog: {e}")
        return None


def parse_cloud_audit(json_log: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Parse cloud provider audit log (AWS CloudTrail, Azure Activity Log, GCP Audit).

    Expected fields:
    - eventTime / timestamp (ISO format)
    - eventName / operationName (string)
    - sourceIPAddress / sourceIPaddress (string)
    - userIdentity.principalId / caller (string)
    - resources[0].ARN / resource (string)

    Args:
        json_log: Dictionary containing cloud audit log

    Returns:
        dict: Normalized event or None if parsing fails
    """
    try:
        # Handle different cloud provider formats
        timestamp = (
            json_log.get("eventTime")
            or json_log.get("timestamp")
            or json_log.get("createdDateTime")
        )

        event_name = (
            json_log.get("eventName")
            or json_log.get("operationName")
            or "unknown"
        )

        source_ip = (
            json_log.get("sourceIPAddress")
            or json_log.get("sourceIPaddress")
            or json_log.get("callerIpAddress")
        )

        # Extract principal/user
        principal_id = None
        if "userIdentity" in json_log:
            principal_id = json_log["userIdentity"].get("principalId")
        if not principal_id:
            principal_id = json_log.get("caller")

        # Extract resource
        resource = None
        if "resources" in json_log and json_log["resources"]:
            resource = json_log["resources"][0].get("ARN") or json_log["resources"][0].get("id")
        if not resource:
            resource = json_log.get("resource")

        normalized = {
            "timestamp": timestamp or datetime.now().isoformat(),
            "source_type": "cloud_audit",
            "event_type": event_name,
            "severity": determine_severity(json_log.get("errorCode")),
            "source_ip": source_ip,
            "source_user": principal_id,
            "target_resource": resource,
            "action": event_name,
            "raw_data": json_log,
            "normalized_data": {
                "event_name": event_name,
                "error_code": json_log.get("errorCode"),
                "error_message": json_log.get("errorMessage"),
            },
            "metadata": {
                "cloud_provider": identify_cloud_provider(json_log),
            },
        }

        return normalized

    except Exception as e:
        logger.error(f"Error parsing cloud audit log: {e}")
        return None


def normalize_event(
    raw: Dict[str, Any],
    source_type: str = "custom_json",
) -> Optional[Dict[str, Any]]:
    """
    Normalize a security event based on its source type.

    Args:
        raw: Raw event dictionary
        source_type: Type of event source ('custom_json', 'syslog', 'cloud_audit', 'windows_event')

    Returns:
        dict: Normalized event or None if normalization fails
    """
    if source_type == "custom_json":
        return parse_custom_json(raw)
    elif source_type == "cloud_audit":
        return parse_cloud_audit(raw)
    elif source_type == "syslog":
        # Convert to string if needed
        if isinstance(raw, dict):
            raw = json.dumps(raw)
        return parse_syslog(raw)
    else:
        # Default to custom JSON parsing
        return parse_custom_json(raw)


# ============================================================================
# Helper Functions
# ============================================================================


def extract_severity_from_text(text: str) -> str:
    """Extract severity level from text."""
    text_lower = text.lower()

    if any(word in text_lower for word in ["critical", "error", "fatal", "panic"]):
        return "critical"
    elif any(word in text_lower for word in ["warning", "warn"]):
        return "high"
    elif any(word in text_lower for word in ["info", "notice"]):
        return "medium"
    else:
        return "low"


def extract_ip_from_text(text: str) -> Optional[str]:
    """Extract IP address from text using simple pattern matching."""
    import re

    # Simple IPv4 pattern
    ipv4_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
    match = re.search(ipv4_pattern, text)

    return match.group(0) if match else None


def extract_action_from_text(text: str) -> str:
    """Extract action/event type from text."""
    text_lower = text.lower()

    if "failed" in text_lower or "failure" in text_lower:
        return "failed"
    elif "denied" in text_lower or "reject" in text_lower:
        return "blocked"
    elif "allowed" in text_lower or "accept" in text_lower:
        return "allowed"
    elif "login" in text_lower or "authentication" in text_lower:
        return "login"
    elif "logout" in text_lower:
        return "logout"
    else:
        return "unknown"


def determine_severity(error_code: Optional[str]) -> str:
    """Determine severity from error code."""
    if not error_code:
        return "info"

    error_lower = error_code.lower()

    if "unauthorized" in error_lower or "forbidden" in error_lower:
        return "high"
    elif "notfound" in error_lower or "404" in error_lower:
        return "low"
    elif "error" in error_lower or "fail" in error_lower:
        return "medium"
    else:
        return "info"


def identify_cloud_provider(log: Dict[str, Any]) -> str:
    """Identify cloud provider from log structure."""
    # AWS CloudTrail
    if "userIdentity" in log or "eventSource" in log:
        return "aws"
    # Azure Activity Log
    elif "operationName" in log or "resourceId" in log:
        return "azure"
    # GCP Audit
    elif "logName" in log or "protoPayload" in log:
        return "gcp"
    else:
        return "unknown"
