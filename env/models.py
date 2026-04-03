"""Pydantic models for the SOC OpenEnv environment."""

from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AlertType(str, Enum):
    PHISHING = "phishing"
    MALWARE = "malware"
    CREDENTIAL_ACCESS = "credential_access"
    LATERAL_MOVEMENT = "lateral_movement"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DATA_EXFILTRATION = "data_exfiltration"
    INTRUSION = "intrusion"
    RECONNAISSANCE = "reconnaissance"


class ActionType(str, Enum):
    # Investigation actions
    ANALYZE_EMAIL = "analyze_email"
    ANALYZE_ATTACHMENT = "analyze_attachment"
    CHECK_SENDER_REPUTATION = "check_sender_reputation"
    SCAN_URL = "scan_url"
    QUERY_THREAT_INTEL = "query_threat_intel"
    CORRELATE_ALERTS = "correlate_alerts"
    CHECK_LOGS = "check_logs"
    ANALYZE_NETWORK_TRAFFIC = "analyze_network_traffic"

    # Containment actions
    BLOCK_IP = "block_ip"
    BLOCK_DOMAIN = "block_domain"
    ISOLATE_HOST = "isolate_host"
    DISABLE_ACCOUNT = "disable_account"
    QUARANTINE_FILE = "quarantine_file"
    REVOKE_CREDENTIALS = "revoke_credentials"

    # Response actions
    ESCALATE_INCIDENT = "escalate_incident"
    CREATE_TICKET = "create_ticket"
    NOTIFY_USER = "notify_user"
    UPDATE_RULES = "update_rules"
    CLOSE_ALERT = "close_alert"

    # Incorrect / wasteful
    IGNORE = "ignore"
    NO_ACTION = "no_action"


# ---------------------------------------------------------------------------
# Alert model
# ---------------------------------------------------------------------------

class Alert(BaseModel):
    """Represents a single SOC alert."""
    alert_id: str
    alert_type: AlertType
    severity: Severity
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    description: str
    indicators: Dict[str, Any] = Field(default_factory=dict)
    mitre_technique_id: Optional[str] = None
    mitre_technique_name: Optional[str] = None
    timestamp: int = 0  # relative step when the alert appeared


# ---------------------------------------------------------------------------
# Core Pydantic models required by OpenEnv
# ---------------------------------------------------------------------------

class Observation(BaseModel):
    """Observation returned by the environment after every step / reset."""
    task_name: str
    current_alert: Alert
    pending_alerts: int = 0
    risk_score: float = Field(ge=0.0, le=10.0)
    action_history: List[str] = Field(default_factory=list)
    step_count: int = 0
    max_steps: int = 20
    mitre_technique: Optional[str] = None
    available_actions: List[str] = Field(default_factory=list)
    context: Dict[str, Any] = Field(default_factory=dict)
    done: bool = False


class Action(BaseModel):
    """Action submitted by the agent."""
    action_type: ActionType
    parameters: Dict[str, Any] = Field(default_factory=dict)


class Reward(BaseModel):
    """Reward returned after each step."""
    value: float
    breakdown: Dict[str, float] = Field(default_factory=dict)
    message: str = ""
