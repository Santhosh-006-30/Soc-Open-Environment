"""Deterministic grading system for the SOC environment."""

from __future__ import annotations

from typing import Dict, List, Optional

from env.models import ActionType
from env.tasks import TaskDefinition


class SOCGrader:
    """Rule-based grader — produces a score in [0.0, 1.0].

    Scoring axes
    -------------
    1. **Correctness** (40 %) — step-level exact and partial credit.
    2. **Sequence**    (30 %) — attack-chain ordering and full-sequence bonus.
    3. **Completeness** (20 %) — whether the expected chain was covered.
    4. **Efficiency**  (10 %) — penalty for wrong, harmful, or excess actions.

    All evaluation is deterministic and designed for SOC lifecycle reasoning.
    """

    WEIGHT_CORRECTNESS = 0.40
    WEIGHT_SEQUENCE = 0.30
    WEIGHT_COMPLETENESS = 0.20
    WEIGHT_EFFICIENCY = 0.10

    # Actions that are always penalised
    _HARMFUL_ACTIONS = {ActionType.IGNORE, ActionType.NO_ACTION}

    def __init__(self, task: TaskDefinition) -> None:
        self._task = task

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def grade(self, action_history: List[ActionType]) -> Dict[str, float]:
        """Grade an action sequence. Returns dict with component scores + total."""
        correctness = self._score_correctness(action_history)
        sequence = self._score_sequence(action_history)
        completeness = self._score_completeness(action_history)
        efficiency = self._score_efficiency(action_history)

        total = (
            self.WEIGHT_CORRECTNESS * correctness
            + self.WEIGHT_SEQUENCE * sequence
            + self.WEIGHT_COMPLETENESS * completeness
            + self.WEIGHT_EFFICIENCY * efficiency
        )

        return {
            "correctness": round(correctness, 4),
            "sequence": round(sequence, 4),
            "completeness": round(completeness, 4),
            "efficiency": round(efficiency, 4),
            "total": round(min(max(total, 0.001), 0.999), 4),
        }

    # ------------------------------------------------------------------
    # Private scoring methods
    # ------------------------------------------------------------------

    def _score_correctness(self, actions: List[ActionType]) -> float:
        """Exact matches get full credit, partial matches get partial credit."""
        if not actions:
            return 0.0

        optimal = self._task.optimal_actions
        partial = self._task.partial_credit_actions
        score = 0.0

        for idx, action in enumerate(actions):
            if idx < len(optimal) and action == optimal[idx]:
                score += 0.4
            elif idx in partial and action in partial[idx]:
                score += 0.2
            elif action in optimal:
                score += 0.1
            elif action in self._HARMFUL_ACTIONS:
                score -= 0.3
            else:
                score += 0.0

        max_score = max(len(optimal) * 0.4, 1.0)
        return min(max(score / max_score, 0.0), 1.0)

    def _score_sequence(self, actions: List[ActionType]) -> float:
        """Measure ordering alignment with optimal sequence using LCS + bonus."""
        optimal = self._task.optimal_actions
        if not actions or not optimal:
            return 0.0

        lcs_len = self._lcs_length(actions, optimal)
        ratio = lcs_len / len(optimal)
        if lcs_len == len(optimal) and len(actions) >= len(optimal):
            ratio += 0.5
        return min(ratio, 1.0)

    def _score_completeness(self, actions: List[ActionType]) -> float:
        """Fraction of optimal actions that the agent performed at least once."""
        optimal_set = set(self._task.optimal_actions)
        if not optimal_set:
            return 1.0

        covered = optimal_set.intersection(set(actions))
        return min(len(covered) / len(optimal_set), 1.0)

    def _score_efficiency(self, actions: List[ActionType]) -> float:
        """Penalise wrong, harmful, and excess actions to keep chains tight."""
        if not actions:
            return 0.0

        harmful_count = sum(1 for a in actions if a in self._HARMFUL_ACTIONS)
        wrong_count = sum(
            1
            for idx, action in enumerate(actions)
            if action not in self._task.optimal_actions
            and idx not in self._task.partial_credit_actions
            and action not in self._HARMFUL_ACTIONS
        )
        excess = max(len(actions) - len(self._task.optimal_actions), 0)
        penalty = harmful_count * 0.3 + wrong_count * 0.1 + excess * 0.1
        return max(1.0 - penalty, 0.0)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _lcs_length(a: List, b: List) -> int:
        """Longest common subsequence length (standard DP)."""
        m, n = len(a), len(b)
        dp = [[0] * (n + 1) for _ in range(m + 1)]
        for i in range(1, m + 1):
            for j in range(1, n + 1):
                if a[i - 1] == b[j - 1]:
                    dp[i][j] = dp[i - 1][j - 1] + 1
                else:
                    dp[i][j] = max(dp[i - 1][j], dp[i][j - 1])
        return dp[m][n]
