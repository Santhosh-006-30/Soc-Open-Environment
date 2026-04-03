"""Deterministic grading system for the SOC environment."""

from __future__ import annotations

from typing import Dict, List, Optional

from env.models import ActionType
from env.tasks import TaskDefinition


class SOCGrader:
    """Rule-based grader — produces a score in [0.0, 1.0].

    Scoring axes
    -------------
    1. **Correctness** (40 %) — how many actions match the optimal / partial-credit set.
    2. **Sequence**    (30 %) — how well the agent followed the expected ordering.
    3. **Completeness** (20 %) — fraction of the optimal chain that was covered.
    4. **Efficiency**  (10 %) — penalty for superfluous or harmful actions.

    All evaluation is deterministic — no randomness.
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
            "total": round(min(max(total, 0.0), 1.0), 4),
        }

    # ------------------------------------------------------------------
    # Private scoring methods
    # ------------------------------------------------------------------

    def _score_correctness(self, actions: List[ActionType]) -> float:
        """Fraction of agent actions that appear in optimal or partial-credit sets."""
        if not actions:
            return 0.0

        optimal_set = set(self._task.optimal_actions)
        partial_sets = self._task.partial_credit_actions

        correct = 0
        for idx, action in enumerate(actions):
            if action in optimal_set:
                correct += 1.0
            elif idx in partial_sets and action in partial_sets[idx]:
                correct += 0.7  # partial credit
            elif action not in self._HARMFUL_ACTIONS:
                correct += 0.1  # small credit for reasonable but suboptimal

        return min(correct / max(len(self._task.optimal_actions), 1), 1.0)

    def _score_sequence(self, actions: List[ActionType]) -> float:
        """Measure ordering alignment with optimal sequence using LCS ratio."""
        optimal = self._task.optimal_actions
        if not actions or not optimal:
            return 0.0

        lcs_len = self._lcs_length(actions, optimal)
        return lcs_len / len(optimal)

    def _score_completeness(self, actions: List[ActionType]) -> float:
        """Fraction of optimal actions that the agent performed at least once."""
        if not self._task.optimal_actions:
            return 1.0

        optimal_set = set(self._task.optimal_actions)
        covered = optimal_set.intersection(set(actions))
        return len(covered) / len(optimal_set)

    def _score_efficiency(self, actions: List[ActionType]) -> float:
        """Penalise wasted or harmful actions. 1.0 = perfectly efficient."""
        if not actions:
            return 0.0

        harmful_count = sum(1 for a in actions if a in self._HARMFUL_ACTIONS)
        optimal_len = len(self._task.optimal_actions)
        excess = max(len(actions) - optimal_len, 0)

        penalty = harmful_count * 0.15 + excess * 0.05
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
