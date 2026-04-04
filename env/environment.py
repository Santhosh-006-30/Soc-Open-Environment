"""SOC OpenEnv — core environment implementing step / reset / state."""

from __future__ import annotations

import copy
from typing import Any, Dict, List, Optional, Tuple

from env.graders import SOCGrader
from env.mitre import MITREMapper
from env.models import (
    Action,
    ActionType,
    Alert,
    AlertType,
    Observation,
    Reward,
    Severity,
)
from env.risk import RiskScorer
from env.tasks import TaskDefinition, TaskRegistry


class SOCEnvironment:
    """OpenEnv-compatible Security Operations Center environment.

    Public API
    ----------
    reset(task_name)  → Observation
    step(action)      → (Observation, Reward, bool, dict)
    state()           → dict
    """

    def __init__(self) -> None:
        self._mitre = MITREMapper()
        self._risk = RiskScorer()
        self._grader: Optional[SOCGrader] = None

        # Internal state (populated on reset)
        self._task: Optional[TaskDefinition] = None
        self._alerts: List[Alert] = []
        self._current_alert_idx: int = 0
        self._step_count: int = 0
        self._action_history: List[ActionType] = []
        self._resolved_alerts: int = 0
        self._done: bool = True
        self._total_reward: float = 0.0
        self._context: Dict[str, Any] = {}
        self.timeline: List[str] = []

    # ------------------------------------------------------------------
    # reset
    # ------------------------------------------------------------------

    def reset(self, task_name: str = "phishing_detection") -> Observation:
        """Reset the environment to the beginning of *task_name*."""
        self._task = TaskRegistry.get(task_name)
        self._grader = SOCGrader(self._task)
        self._alerts = copy.deepcopy(self._task.alerts)
        self._current_alert_idx = 0
        self._step_count = 0
        self._action_history = []
        self._resolved_alerts = 0
        self._done = False
        self._total_reward = 0.0
        self._context = dict(self._task.context)
        self.timeline = []

        return self._build_observation()

    # ------------------------------------------------------------------
    # step
    # ------------------------------------------------------------------

    def step(self, action: Action) -> Tuple[Observation, Reward, bool, Dict[str, Any]]:
        """Execute one action and return (observation, reward, done, info)."""
        if self._done:
            raise RuntimeError("Environment is done. Call reset() first.")
        if self._task is None:
            raise RuntimeError("No task loaded. Call reset() first.")

        self._step_count += 1
        self._action_history.append(action.action_type)

        # Track the incident lifecycle in a timeline for richer observation.
        alert_label = self._alerts[self._current_alert_idx].alert_type.value
        self.timeline.append(f"Step {self._step_count}: {alert_label} detected")

        # Compute reward
        reward = self._compute_reward(action)
        self._total_reward += reward.value

        # Advance alert pointer when a containment/response action resolves it
        if self._is_resolution_action(action.action_type):
            self._resolved_alerts += 1
            if self._current_alert_idx < len(self._alerts) - 1:
                self._current_alert_idx += 1

        # Check for new alerts that should fire based on step count
        self._maybe_surface_alert()

        # Terminal conditions
        if self._step_count >= self._task.max_steps:
            self._done = True
        if (
            self._resolved_alerts >= len(self._alerts)
            and action.action_type == ActionType.CLOSE_ALERT
        ):
            self._done = True

        observation = self._build_observation()
        info = self._build_info()

        return observation, reward, self._done, info

    # ------------------------------------------------------------------
    # state
    # ------------------------------------------------------------------

    def state(self) -> Dict[str, Any]:
        """Return a serialisable snapshot of the environment state."""
        return {
            "task": self._task.name if self._task else None,
            "difficulty": self._task.difficulty if self._task else None,
            "step_count": self._step_count,
            "max_steps": self._task.max_steps if self._task else 0,
            "action_history": [a.value for a in self._action_history],
            "current_alert_idx": self._current_alert_idx,
            "total_alerts": len(self._alerts),
            "resolved_alerts": self._resolved_alerts,
            "done": self._done,
            "total_reward": round(self._total_reward, 4),
            "grade": self._grader.grade(self._action_history) if self._grader else None,
        }

    # ------------------------------------------------------------------
    # Reward computation
    # ------------------------------------------------------------------

    def _compute_reward(self, action: Action) -> Reward:
        """Dense reward with partial credit, time penalty, and harmful-action penalty."""
        breakdown: Dict[str, float] = {}
        optimal = self._task.optimal_actions
        partial_map = self._task.partial_credit_actions
        idx = self._step_count - 1  # 0-based position

        # 1. Base reward and alignment
        base_reward = 0.1
        breakdown["base"] = round(base_reward, 4)

        mitigation_actions = {
            ActionType.ISOLATE_HOST,
            ActionType.BLOCK_IP,
            ActionType.BLOCK_DOMAIN,
            ActionType.QUARANTINE_FILE,
            ActionType.REVOKE_CREDENTIALS,
            ActionType.DISABLE_ACCOUNT,
        }
        mitigation_bonus = 0.3 if action.action_type in mitigation_actions else 0.0
        breakdown["mitigation_bonus"] = round(mitigation_bonus, 4)

        if action.action_type == ActionType.IGNORE:
            ignore_penalty = -0.5
            breakdown["ignore_penalty"] = round(ignore_penalty, 4)
        else:
            ignore_penalty = 0.0
            breakdown["ignore_penalty"] = 0.0

        if idx < len(optimal) and action.action_type == optimal[idx]:
            alignment = 1.0
            msg = "Optimal action"
        elif idx in partial_map and action.action_type in partial_map[idx]:
            alignment = 0.6
            msg = "Acceptable action (partial credit)"
        elif action.action_type in {ActionType.IGNORE, ActionType.NO_ACTION}:
            alignment = -0.5
            msg = "Harmful: threat ignored"
        else:
            alignment = 0.1 if action.action_type in set(optimal) else -0.1
            msg = "Sub-optimal action"
        breakdown["alignment"] = round(alignment, 4)

        # 2. Time penalty — only after the first few steps
        time_penalty = -0.05 if self._step_count > 2 else 0.0
        breakdown["time_penalty"] = round(time_penalty, 4)

        # 3. Severity bonus — higher for critical-alert actions
        current_alert = self._alerts[self._current_alert_idx]
        sev_bonus = {
            Severity.LOW: 0.0,
            Severity.MEDIUM: 0.05,
            Severity.HIGH: 0.10,
            Severity.CRITICAL: 0.15,
        }.get(current_alert.severity, 0.0)
        if alignment > 0:
            breakdown["severity_bonus"] = round(sev_bonus, 4)
        else:
            sev_bonus = 0.0
            breakdown["severity_bonus"] = 0.0

        # 4. Risk-aware penalty
        risk_penalty = 0.0
        risk_score = self._risk.compute(
            current_alert=current_alert,
            pending_alerts=len(self._alerts) - self._current_alert_idx - 1,
            step_count=self._step_count,
            max_steps=self._task.max_steps if self._task else 20,
            mitre_weight=self._mitre.technique_for_alert_type(current_alert.alert_type.value).severity_weight
            if self._mitre.technique_for_alert_type(current_alert.alert_type.value)
            else 0.5,
            resolved_count=self._resolved_alerts,
        )
        if risk_score > 7 and action.action_type not in mitigation_actions:
            risk_penalty = -0.4
        breakdown["risk_penalty"] = round(risk_penalty, 4)

        # 5. Chain-completion bonus when done
        chain_bonus = 0.0
        if self._done or (
            self._resolved_alerts >= len(self._alerts)
            and action.action_type == ActionType.CLOSE_ALERT
        ):
            grade = self._grader.grade(self._action_history) if self._grader else {"total": 0}
            chain_bonus = grade.get("total", 0.0) * 2.0  # up to +2.0
            breakdown["chain_completion"] = round(chain_bonus, 4)

        total = base_reward + mitigation_bonus + ignore_penalty + alignment + time_penalty + sev_bonus + risk_penalty + chain_bonus

        return Reward(
            value=round(total, 4),
            breakdown=breakdown,
            message=msg,
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _build_observation(self) -> Observation:
        current_alert = self._alerts[self._current_alert_idx]
        mitre = self._mitre.technique_for_alert_type(current_alert.alert_type.value)
        mitre_weight = mitre.severity_weight if mitre else 0.5

        risk = self._risk.compute(
            current_alert=current_alert,
            pending_alerts=len(self._alerts) - self._current_alert_idx - 1,
            step_count=self._step_count,
            max_steps=self._task.max_steps if self._task else 20,
            mitre_weight=mitre_weight,
            resolved_count=self._resolved_alerts,
        )

        return Observation(
            task_name=self._task.name if self._task else "",
            current_alert=current_alert,
            pending_alerts=max(len(self._alerts) - self._current_alert_idx - 1, 0),
            risk_score=risk,
            action_history=[a.value for a in self._action_history],
            step_count=self._step_count,
            max_steps=self._task.max_steps if self._task else 20,
            mitre_technique=current_alert.mitre_technique_id,
            available_actions=[a.value for a in ActionType],
            context=self._context,
            timeline=list(self.timeline),
            done=self._done,
        )

    def _build_info(self) -> Dict[str, Any]:
        info: Dict[str, Any] = {
            "total_reward": round(self._total_reward, 4),
            "resolved_alerts": self._resolved_alerts,
            "total_alerts": len(self._alerts),
        }
        if self._done and self._grader:
            info["grade"] = self._grader.grade(self._action_history)
        return info

    def _is_resolution_action(self, action_type: ActionType) -> bool:
        """Actions that count as resolving the current alert."""
        return action_type in {
            ActionType.BLOCK_IP,
            ActionType.BLOCK_DOMAIN,
            ActionType.ISOLATE_HOST,
            ActionType.DISABLE_ACCOUNT,
            ActionType.QUARANTINE_FILE,
            ActionType.REVOKE_CREDENTIALS,
            ActionType.CLOSE_ALERT,
        }

    def _maybe_surface_alert(self) -> None:
        """Advance to the next alert if the current step triggers one."""
        for i, alert in enumerate(self._alerts):
            if i > self._current_alert_idx and alert.timestamp <= self._step_count:
                self._current_alert_idx = i
                break
