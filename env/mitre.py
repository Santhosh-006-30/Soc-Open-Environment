"""MITRE ATT&CK technique mapping for the SOC environment."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class MITRETechnique:
    """Represents one MITRE ATT&CK technique."""
    technique_id: str
    name: str
    tactic: str
    description: str
    severity_weight: float = 1.0


# ---------------------------------------------------------------------------
# Static catalogue of techniques used in the simulation
# ---------------------------------------------------------------------------

_TECHNIQUE_DB: Dict[str, MITRETechnique] = {
    "T1566": MITRETechnique(
        technique_id="T1566",
        name="Phishing",
        tactic="Initial Access",
        description="Adversaries send phishing messages to gain access to victim systems.",
        severity_weight=0.6,
    ),
    "T1566.001": MITRETechnique(
        technique_id="T1566.001",
        name="Spearphishing Attachment",
        tactic="Initial Access",
        description="Adversaries send spearphishing emails with a malicious attachment.",
        severity_weight=0.7,
    ),
    "T1204": MITRETechnique(
        technique_id="T1204",
        name="User Execution",
        tactic="Execution",
        description="An adversary relies upon specific actions by a user to gain execution.",
        severity_weight=0.5,
    ),
    "T1078": MITRETechnique(
        technique_id="T1078",
        name="Valid Accounts",
        tactic="Credential Access",
        description="Adversaries obtain and abuse existing account credentials.",
        severity_weight=0.8,
    ),
    "T1021": MITRETechnique(
        technique_id="T1021",
        name="Remote Services",
        tactic="Lateral Movement",
        description="Adversaries use valid accounts to log into remote services.",
        severity_weight=0.8,
    ),
    "T1068": MITRETechnique(
        technique_id="T1068",
        name="Exploitation for Privilege Escalation",
        tactic="Privilege Escalation",
        description="Adversaries exploit software vulnerabilities to escalate privileges.",
        severity_weight=0.9,
    ),
    "T1059": MITRETechnique(
        technique_id="T1059",
        name="Command and Scripting Interpreter",
        tactic="Execution",
        description="Adversaries abuse command and script interpreters to execute commands.",
        severity_weight=0.7,
    ),
    "T1048": MITRETechnique(
        technique_id="T1048",
        name="Exfiltration Over Alternative Protocol",
        tactic="Exfiltration",
        description="Adversaries steal data by exfiltrating it over a different protocol.",
        severity_weight=1.0,
    ),
    "T1071": MITRETechnique(
        technique_id="T1071",
        name="Application Layer Protocol",
        tactic="Command and Control",
        description="Adversaries communicate using application layer protocols to avoid detection.",
        severity_weight=0.6,
    ),
    "T1595": MITRETechnique(
        technique_id="T1595",
        name="Active Scanning",
        tactic="Reconnaissance",
        description="Adversaries scan victim infrastructure to gather information.",
        severity_weight=0.4,
    ),
}

# Map alert types to their primary MITRE technique
_ALERT_TYPE_TO_TECHNIQUE: Dict[str, str] = {
    "phishing": "T1566",
    "malware": "T1059",
    "credential_access": "T1078",
    "lateral_movement": "T1021",
    "privilege_escalation": "T1068",
    "data_exfiltration": "T1048",
    "intrusion": "T1068",
    "reconnaissance": "T1595",
}


class MITREMapper:
    """Utility class for looking up MITRE ATT&CK techniques."""

    def __init__(self) -> None:
        self._db = dict(_TECHNIQUE_DB)
        self._alert_map = dict(_ALERT_TYPE_TO_TECHNIQUE)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get_technique(self, technique_id: str) -> Optional[MITRETechnique]:
        """Return a MITRETechnique by its ID, or None."""
        return self._db.get(technique_id)

    def technique_for_alert_type(self, alert_type: str) -> Optional[MITRETechnique]:
        """Map an alert-type string to its primary MITRE technique."""
        tid = self._alert_map.get(alert_type)
        if tid is None:
            return None
        return self._db.get(tid)

    def get_severity_weight(self, technique_id: str) -> float:
        """Return the severity weight (0..1) for a technique."""
        t = self._db.get(technique_id)
        return t.severity_weight if t else 0.5

    def list_techniques(self) -> List[MITRETechnique]:
        """Return all known techniques."""
        return list(self._db.values())

    def get_attack_chain(self, technique_ids: List[str]) -> List[MITRETechnique]:
        """Return ordered list of techniques for a given chain."""
        return [self._db[tid] for tid in technique_ids if tid in self._db]
