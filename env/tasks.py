"""Task definitions for the SOC OpenEnv environment.

Each task defines:
  - A sequence of alerts the agent must handle.
  - The expected (optimal) action sequence.
  - Difficulty metadata.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from env.models import ActionType, Alert, AlertType, Severity


@dataclass
class TaskDefinition:
    """Encapsulates a single SOC task."""
    name: str
    difficulty: str  # easy | medium | hard
    description: str
    max_steps: int
    alerts: List[Alert]
    optimal_actions: List[ActionType]
    partial_credit_actions: Dict[int, List[ActionType]] = field(default_factory=dict)
    context: Dict[str, Any] = field(default_factory=dict)


# ============================================================
#  EASY — Phishing Detection
# ============================================================

_PHISHING_ALERTS = [
    Alert(
        alert_id="ALERT-PHI-001",
        alert_type=AlertType.PHISHING,
        severity=Severity.MEDIUM,
        source_ip="203.0.113.42",
        destination_ip="10.0.1.15",
        description=(
            "Suspicious email detected from external address noreply@secure-banklogin.com "
            "targeting user jdoe@corp.local. Subject: 'Urgent: Verify your account'. "
            "Contains embedded URL https://secure-banklogin.com/verify and an attachment "
            "'invoice_Q4.pdf'. SPF check: FAIL. DKIM: FAIL."
        ),
        indicators={
            "sender": "noreply@secure-banklogin.com",
            "subject": "Urgent: Verify your account",
            "url": "https://secure-banklogin.com/verify",
            "attachment": "invoice_Q4.pdf",
            "spf": "fail",
            "dkim": "fail",
            "recipient": "jdoe@corp.local",
        },
        mitre_technique_id="T1566",
        mitre_technique_name="Phishing",
        timestamp=0,
    ),
]

_PHISHING_OPTIMAL = [
    ActionType.ANALYZE_EMAIL,
    ActionType.CHECK_SENDER_REPUTATION,
    ActionType.SCAN_URL,
    ActionType.BLOCK_DOMAIN,
    ActionType.NOTIFY_USER,
    ActionType.CREATE_TICKET,
    ActionType.CLOSE_ALERT,
]

_PHISHING_PARTIAL: Dict[int, List[ActionType]] = {
    0: [ActionType.ANALYZE_EMAIL, ActionType.CHECK_SENDER_REPUTATION, ActionType.QUERY_THREAT_INTEL],
    1: [ActionType.CHECK_SENDER_REPUTATION, ActionType.SCAN_URL, ActionType.ANALYZE_ATTACHMENT],
    2: [ActionType.SCAN_URL, ActionType.ANALYZE_ATTACHMENT, ActionType.QUERY_THREAT_INTEL],
    3: [ActionType.BLOCK_DOMAIN, ActionType.BLOCK_IP, ActionType.QUARANTINE_FILE],
    4: [ActionType.NOTIFY_USER, ActionType.CREATE_TICKET, ActionType.ESCALATE_INCIDENT],
    5: [ActionType.CREATE_TICKET, ActionType.NOTIFY_USER, ActionType.ESCALATE_INCIDENT],
    6: [ActionType.CLOSE_ALERT],
}


# ============================================================
#  MEDIUM — Malware Investigation
# ============================================================

_MALWARE_ALERTS = [
    Alert(
        alert_id="ALERT-MAL-001",
        alert_type=AlertType.MALWARE,
        severity=Severity.HIGH,
        source_ip="10.0.2.34",
        destination_ip="198.51.100.77",
        description=(
            "Endpoint Detection and Response (EDR) flagged suspicious process 'svchost_update.exe' "
            "on workstation WS-FINANCE-07 (10.0.2.34). The process is making outbound connections "
            "to 198.51.100.77:443 every 30 seconds (possible C2 beaconing). File hash: "
            "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6. VirusTotal: 48/72 detections."
        ),
        indicators={
            "process": "svchost_update.exe",
            "hash": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6",
            "c2_ip": "198.51.100.77",
            "c2_port": 443,
            "beacon_interval": "30s",
            "workstation": "WS-FINANCE-07",
            "vt_score": "48/72",
        },
        mitre_technique_id="T1059",
        mitre_technique_name="Command and Scripting Interpreter",
        timestamp=0,
    ),
    Alert(
        alert_id="ALERT-MAL-002",
        alert_type=AlertType.DATA_EXFILTRATION,
        severity=Severity.CRITICAL,
        source_ip="10.0.2.34",
        destination_ip="198.51.100.77",
        description=(
            "Anomalous data transfer detected from WS-FINANCE-07. 2.3 GB of data transferred "
            "to external IP 198.51.100.77 over DNS tunnelling. Destination is a known bad IP "
            "associated with APT group 'DarkSerpent'."
        ),
        indicators={
            "data_volume": "2.3GB",
            "protocol": "DNS tunnelling",
            "threat_actor": "DarkSerpent",
            "destination": "198.51.100.77",
        },
        mitre_technique_id="T1048",
        mitre_technique_name="Exfiltration Over Alternative Protocol",
        timestamp=3,
    ),
]

_MALWARE_OPTIMAL = [
    ActionType.QUERY_THREAT_INTEL,
    ActionType.ANALYZE_NETWORK_TRAFFIC,
    ActionType.ISOLATE_HOST,
    ActionType.QUARANTINE_FILE,
    ActionType.BLOCK_IP,
    ActionType.CHECK_LOGS,
    ActionType.CORRELATE_ALERTS,
    ActionType.ESCALATE_INCIDENT,
    ActionType.CREATE_TICKET,
    ActionType.CLOSE_ALERT,
]

_MALWARE_PARTIAL: Dict[int, List[ActionType]] = {
    0: [ActionType.QUERY_THREAT_INTEL, ActionType.ANALYZE_NETWORK_TRAFFIC, ActionType.CHECK_LOGS],
    1: [ActionType.ANALYZE_NETWORK_TRAFFIC, ActionType.QUERY_THREAT_INTEL, ActionType.CHECK_LOGS],
    2: [ActionType.ISOLATE_HOST, ActionType.BLOCK_IP],
    3: [ActionType.QUARANTINE_FILE, ActionType.ISOLATE_HOST],
    4: [ActionType.BLOCK_IP, ActionType.BLOCK_DOMAIN, ActionType.UPDATE_RULES],
    5: [ActionType.CHECK_LOGS, ActionType.CORRELATE_ALERTS],
    6: [ActionType.CORRELATE_ALERTS, ActionType.CHECK_LOGS, ActionType.ESCALATE_INCIDENT],
    7: [ActionType.ESCALATE_INCIDENT, ActionType.CREATE_TICKET],
    8: [ActionType.CREATE_TICKET, ActionType.ESCALATE_INCIDENT],
    9: [ActionType.CLOSE_ALERT],
}


# ============================================================
#  HARD — Multi-Stage Attack Chain
# ============================================================

_ATTACK_CHAIN_ALERTS = [
    # Stage 1: Initial phishing email
    Alert(
        alert_id="ALERT-APT-001",
        alert_type=AlertType.PHISHING,
        severity=Severity.MEDIUM,
        source_ip="192.0.2.88",
        destination_ip="10.0.1.50",
        description=(
            "Spearphishing email detected targeting CFO m.chen@corp.local from "
            "'ceo@c0rp-local.com' (typo-squatted domain). Subject: 'Board Meeting Docs – "
            "CONFIDENTIAL'. Attachment: 'Board_Agenda_2025.docm' (macro-enabled). "
            "SPF: FAIL, DKIM: NONE."
        ),
        indicators={
            "sender": "ceo@c0rp-local.com",
            "recipient": "m.chen@corp.local",
            "subject": "Board Meeting Docs – CONFIDENTIAL",
            "attachment": "Board_Agenda_2025.docm",
            "spf": "fail",
            "dkim": "none",
            "typosquat_domain": "c0rp-local.com",
        },
        mitre_technique_id="T1566.001",
        mitre_technique_name="Spearphishing Attachment",
        timestamp=0,
    ),
    # Stage 2: Credential harvesting
    Alert(
        alert_id="ALERT-APT-002",
        alert_type=AlertType.CREDENTIAL_ACCESS,
        severity=Severity.HIGH,
        source_ip="10.0.1.50",
        destination_ip="10.0.0.5",
        description=(
            "Anomalous authentication activity detected. Account 'm.chen' successfully "
            "authenticated to Domain Controller DC-01 (10.0.0.5) from workstation WS-EXEC-03 "
            "(10.0.1.50) at 02:47 UTC — outside normal business hours. Multiple failed logins "
            "to service accounts preceding event."
        ),
        indicators={
            "account": "m.chen",
            "source_host": "WS-EXEC-03",
            "target_host": "DC-01",
            "time": "02:47 UTC",
            "failed_logins_prior": 14,
            "service_accounts_targeted": ["svc_backup", "svc_sql", "admin_deploy"],
        },
        mitre_technique_id="T1078",
        mitre_technique_name="Valid Accounts",
        timestamp=4,
    ),
    # Stage 3: Lateral movement
    Alert(
        alert_id="ALERT-APT-003",
        alert_type=AlertType.LATERAL_MOVEMENT,
        severity=Severity.HIGH,
        source_ip="10.0.1.50",
        destination_ip="10.0.3.10",
        description=(
            "RDP session initiated from WS-EXEC-03 (10.0.1.50) to database server DB-PROD-01 "
            "(10.0.3.10) using 'svc_backup' credentials. This service account has never "
            "initiated RDP sessions before. PSExec usage also detected."
        ),
        indicators={
            "protocol": "RDP",
            "source": "WS-EXEC-03",
            "target": "DB-PROD-01",
            "account_used": "svc_backup",
            "psexec_detected": True,
            "first_time_rdp": True,
        },
        mitre_technique_id="T1021",
        mitre_technique_name="Remote Services",
        timestamp=7,
    ),
    # Stage 4: Privilege escalation
    Alert(
        alert_id="ALERT-APT-004",
        alert_type=AlertType.PRIVILEGE_ESCALATION,
        severity=Severity.CRITICAL,
        source_ip="10.0.3.10",
        destination_ip="10.0.0.5",
        description=(
            "Privilege escalation detected on DB-PROD-01. Process 'cmd.exe' spawned with "
            "SYSTEM privileges via exploitation of CVE-2024-21338. New local admin account "
            "'helpdeskadmin' created. Credential dumping tool 'mimikatz.exe' executed."
        ),
        indicators={
            "exploit_cve": "CVE-2024-21338",
            "new_account": "helpdeskadmin",
            "tools_used": ["mimikatz.exe", "cmd.exe"],
            "privileges": "SYSTEM",
            "host": "DB-PROD-01",
        },
        mitre_technique_id="T1068",
        mitre_technique_name="Exploitation for Privilege Escalation",
        timestamp=10,
    ),
    # Stage 5: Data exfiltration
    Alert(
        alert_id="ALERT-APT-005",
        alert_type=AlertType.DATA_EXFILTRATION,
        severity=Severity.CRITICAL,
        source_ip="10.0.3.10",
        destination_ip="203.0.113.99",
        description=(
            "Large outbound data transfer from DB-PROD-01 to external IP 203.0.113.99. "
            "4.7 GB transferred via HTTPS to a newly registered domain 'cdn-sync-update.com'. "
            "Database export utility 'bcp.exe' was used prior to transfer."
        ),
        indicators={
            "data_volume": "4.7GB",
            "external_ip": "203.0.113.99",
            "domain": "cdn-sync-update.com",
            "domain_age": "2 days",
            "tool_used": "bcp.exe",
            "protocol": "HTTPS",
        },
        mitre_technique_id="T1048",
        mitre_technique_name="Exfiltration Over Alternative Protocol",
        timestamp=13,
    ),
]

_ATTACK_CHAIN_OPTIMAL = [
    # Stage 1 response
    ActionType.ANALYZE_EMAIL,
    ActionType.ANALYZE_ATTACHMENT,
    ActionType.CHECK_SENDER_REPUTATION,
    ActionType.QUARANTINE_FILE,
    # Stage 2 response
    ActionType.CHECK_LOGS,
    ActionType.DISABLE_ACCOUNT,
    ActionType.REVOKE_CREDENTIALS,
    # Stage 3 response
    ActionType.CORRELATE_ALERTS,
    ActionType.ISOLATE_HOST,
    ActionType.BLOCK_IP,
    # Stage 4 response
    ActionType.ISOLATE_HOST,
    ActionType.REVOKE_CREDENTIALS,
    ActionType.QUERY_THREAT_INTEL,
    # Stage 5 response
    ActionType.BLOCK_DOMAIN,
    ActionType.BLOCK_IP,
    ActionType.ESCALATE_INCIDENT,
    ActionType.UPDATE_RULES,
    ActionType.CREATE_TICKET,
    ActionType.CLOSE_ALERT,
]

_ATTACK_CHAIN_PARTIAL: Dict[int, List[ActionType]] = {
    # Stage 1
    0: [ActionType.ANALYZE_EMAIL, ActionType.CHECK_SENDER_REPUTATION, ActionType.QUERY_THREAT_INTEL],
    1: [ActionType.ANALYZE_ATTACHMENT, ActionType.SCAN_URL, ActionType.QUERY_THREAT_INTEL],
    2: [ActionType.CHECK_SENDER_REPUTATION, ActionType.SCAN_URL, ActionType.ANALYZE_EMAIL],
    3: [ActionType.QUARANTINE_FILE, ActionType.BLOCK_DOMAIN, ActionType.NOTIFY_USER],
    # Stage 2
    4: [ActionType.CHECK_LOGS, ActionType.CORRELATE_ALERTS, ActionType.QUERY_THREAT_INTEL],
    5: [ActionType.DISABLE_ACCOUNT, ActionType.REVOKE_CREDENTIALS, ActionType.ISOLATE_HOST],
    6: [ActionType.REVOKE_CREDENTIALS, ActionType.DISABLE_ACCOUNT],
    # Stage 3
    7: [ActionType.CORRELATE_ALERTS, ActionType.CHECK_LOGS, ActionType.ANALYZE_NETWORK_TRAFFIC],
    8: [ActionType.ISOLATE_HOST, ActionType.BLOCK_IP],
    9: [ActionType.BLOCK_IP, ActionType.BLOCK_DOMAIN, ActionType.UPDATE_RULES],
    # Stage 4
    10: [ActionType.ISOLATE_HOST, ActionType.BLOCK_IP, ActionType.DISABLE_ACCOUNT],
    11: [ActionType.REVOKE_CREDENTIALS, ActionType.DISABLE_ACCOUNT],
    12: [ActionType.QUERY_THREAT_INTEL, ActionType.CHECK_LOGS, ActionType.CORRELATE_ALERTS],
    # Stage 5
    13: [ActionType.BLOCK_DOMAIN, ActionType.BLOCK_IP],
    14: [ActionType.BLOCK_IP, ActionType.BLOCK_DOMAIN, ActionType.UPDATE_RULES],
    15: [ActionType.ESCALATE_INCIDENT, ActionType.CREATE_TICKET],
    16: [ActionType.UPDATE_RULES, ActionType.ESCALATE_INCIDENT],
    17: [ActionType.CREATE_TICKET, ActionType.ESCALATE_INCIDENT],
    18: [ActionType.CLOSE_ALERT],
}


# ============================================================
#  Registry
# ============================================================

class TaskRegistry:
    """Central registry of all available tasks."""

    _TASKS: Dict[str, TaskDefinition] = {
        "phishing_detection": TaskDefinition(
            name="phishing_detection",
            difficulty="easy",
            description=(
                "Detect and respond to a phishing email targeting a corporate user. "
                "Analyse the email, verify sender legitimacy, block malicious domains, "
                "and notify the affected user."
            ),
            max_steps=12,
            alerts=_PHISHING_ALERTS,
            optimal_actions=_PHISHING_OPTIMAL,
            partial_credit_actions=_PHISHING_PARTIAL,
            context={
                "target_user": "jdoe@corp.local",
                "suspicious_domain": "secure-banklogin.com",
            },
        ),
        "malware_investigation": TaskDefinition(
            name="malware_investigation",
            difficulty="medium",
            description=(
                "Investigate a malware infection on a finance workstation. The endpoint "
                "shows C2 beaconing and data exfiltration via DNS tunnelling. Contain the "
                "threat, isolate the host, and correlate related alerts."
            ),
            max_steps=16,
            alerts=_MALWARE_ALERTS,
            optimal_actions=_MALWARE_OPTIMAL,
            partial_credit_actions=_MALWARE_PARTIAL,
            context={
                "affected_host": "WS-FINANCE-07",
                "c2_server": "198.51.100.77",
                "threat_actor": "DarkSerpent",
            },
        ),
        "attack_chain_response": TaskDefinition(
            name="attack_chain_response",
            difficulty="hard",
            description=(
                "Respond to a multi-stage APT attack chain: spearphishing → credential "
                "access → lateral movement → privilege escalation → data exfiltration. "
                "Handle sequential alerts, correlate the attack lifecycle, contain hosts, "
                "revoke credentials, and escalate the incident."
            ),
            max_steps=25,
            alerts=_ATTACK_CHAIN_ALERTS,
            optimal_actions=_ATTACK_CHAIN_OPTIMAL,
            partial_credit_actions=_ATTACK_CHAIN_PARTIAL,
            context={
                "attack_stages": [
                    "initial_access",
                    "credential_access",
                    "lateral_movement",
                    "privilege_escalation",
                    "data_exfiltration",
                ],
                "affected_hosts": [
                    "WS-EXEC-03",
                    "DC-01",
                    "DB-PROD-01",
                ],
                "compromised_accounts": ["m.chen", "svc_backup", "helpdeskadmin"],
            },
        ),
    }

    @classmethod
    def get(cls, task_name: str) -> TaskDefinition:
        """Return a task definition by name. Raises KeyError if not found."""
        if task_name not in cls._TASKS:
            available = ", ".join(cls._TASKS.keys())
            raise KeyError(f"Unknown task '{task_name}'. Available tasks: {available}")
        return cls._TASKS[task_name]

    @classmethod
    def list_tasks(cls) -> List[str]:
        """Return list of available task names."""
        return list(cls._TASKS.keys())

    @classmethod
    def list_definitions(cls) -> List[TaskDefinition]:
        """Return all task definitions."""
        return list(cls._TASKS.values())
