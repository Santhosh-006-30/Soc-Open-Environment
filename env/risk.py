"""Dynamic risk scoring system for the SOC environment."""

from __future__ import annotations

from typing import List

from env.models import Alert, Severity


# Severity → base risk contribution
_SEVERITY_BASE: dict[Severity, float] = {
    Severity.LOW: 1.0,
    Severity.MEDIUM: 2.5,
    Severity.HIGH: 4.0,
    Severity.CRITICAL: 6.0,
}


class RiskScorer:
    """Computes a dynamic risk score in the range [1, 10].

    The score increases with:
      - alert severity
      - elapsed time (step count)
      - number of unresolved alerts
      - MITRE technique severity weight
    """

    def __init__(self, base: float = 1.0) -> None:
        self._base = base
        self._resolved_count: int = 0

    def compute(
        self,
        current_alert: Alert,
        pending_alerts: int,
        step_count: int,
        max_steps: int,
        mitre_weight: float = 0.5,
        resolved_count: int = 0,
    ) -> float:
        """Return a risk score in [1.0, 10.0]."""
        # 1. Severity contribution
        severity_score = _SEVERITY_BASE.get(current_alert.severity, 2.0)

        # 2. Time pressure – monotonically increases
        time_ratio = min(step_count / max(max_steps, 1), 1.0)
        time_penalty = time_ratio * 2.5  # up to +2.5

        # 3. Pending-alert pressure
        pending_pressure = min(pending_alerts * 0.5, 2.0)

        # 4. MITRE severity
        mitre_contribution = mitre_weight * 1.5  # up to +1.5

        # 5. Resolution discount
        resolution_discount = min(resolved_count * 0.3, 2.0)

        raw = (
            self._base
            + severity_score
            + time_penalty
            + pending_pressure
            + mitre_contribution
            - resolution_discount
        )

        # Clamp to [1, 10]
        return round(max(1.0, min(10.0, raw)), 2)
