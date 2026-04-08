"""Inference script for SOC OpenEnv.

Runs the agent through all tasks, using rule-based reasoning with LLM fallback.

Required environment variables:
  API_BASE_URL   – OpenAI-compatible API base URL (LiteLLM proxy)
  API_KEY        – API key for LiteLLM proxy
  MODEL_NAME     – model identifier
"""

from __future__ import annotations

import json
import os
import re
import sys
from typing import Any, Dict, List, Optional

from openai import OpenAI

# Ensure project root is on the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from env.environment import SOCEnvironment
from env.models import Action, ActionType, Observation
from env.tasks import TaskRegistry


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Use injected environment variables for LiteLLM proxy
API_BASE_URL = os.environ["API_BASE_URL"]
API_KEY = os.environ["API_KEY"]
MODEL_NAME = os.getenv("MODEL_NAME", "mistralai/Mistral-7B-Instruct-v0.3")

# Initialize OpenAI client with LiteLLM proxy credentials
client = OpenAI(api_key=API_KEY, base_url=API_BASE_URL)


# ---------------------------------------------------------------------------
# Rule-based agent
# ---------------------------------------------------------------------------

# Keyword → action mapping for rule-based reasoning
_KEYWORD_RULES: Dict[str, List[ActionType]] = {
    # Phishing indicators
    "phishing": [
        ActionType.ANALYZE_EMAIL,
        ActionType.CHECK_SENDER_REPUTATION,
        ActionType.SCAN_URL,
        ActionType.BLOCK_DOMAIN,
        ActionType.NOTIFY_USER,
        ActionType.CREATE_TICKET,
        ActionType.CLOSE_ALERT,
    ],
    "spf": [ActionType.ANALYZE_EMAIL, ActionType.CHECK_SENDER_REPUTATION],
    "dkim": [ActionType.ANALYZE_EMAIL, ActionType.CHECK_SENDER_REPUTATION],
    "spearphishing": [
        ActionType.ANALYZE_EMAIL,
        ActionType.ANALYZE_ATTACHMENT,
        ActionType.CHECK_SENDER_REPUTATION,
        ActionType.QUARANTINE_FILE,
    ],
    # Malware indicators
    "malware": [
        ActionType.QUERY_THREAT_INTEL,
        ActionType.ANALYZE_NETWORK_TRAFFIC,
        ActionType.ISOLATE_HOST,
        ActionType.QUARANTINE_FILE,
    ],
    "c2": [ActionType.ANALYZE_NETWORK_TRAFFIC, ActionType.BLOCK_IP, ActionType.ISOLATE_HOST],
    "beacon": [ActionType.ANALYZE_NETWORK_TRAFFIC, ActionType.BLOCK_IP],
    "virustotal": [ActionType.QUERY_THREAT_INTEL, ActionType.QUARANTINE_FILE],
    # Credential / account
    "credential": [ActionType.CHECK_LOGS, ActionType.DISABLE_ACCOUNT, ActionType.REVOKE_CREDENTIALS],
    "authentication": [ActionType.CHECK_LOGS, ActionType.DISABLE_ACCOUNT],
    "failed login": [ActionType.CHECK_LOGS, ActionType.DISABLE_ACCOUNT],
    "mimikatz": [ActionType.ISOLATE_HOST, ActionType.REVOKE_CREDENTIALS, ActionType.ESCALATE_INCIDENT],
    # Lateral movement
    "rdp": [ActionType.CORRELATE_ALERTS, ActionType.ISOLATE_HOST, ActionType.BLOCK_IP],
    "psexec": [ActionType.CORRELATE_ALERTS, ActionType.ISOLATE_HOST],
    "lateral": [ActionType.CORRELATE_ALERTS, ActionType.ISOLATE_HOST, ActionType.BLOCK_IP],
    # Privilege escalation
    "privilege": [ActionType.ISOLATE_HOST, ActionType.REVOKE_CREDENTIALS, ActionType.QUERY_THREAT_INTEL],
    "cve": [ActionType.ISOLATE_HOST, ActionType.QUERY_THREAT_INTEL],
    "system privileges": [ActionType.ISOLATE_HOST, ActionType.REVOKE_CREDENTIALS],
    # Data exfiltration
    "exfiltration": [ActionType.BLOCK_DOMAIN, ActionType.BLOCK_IP, ActionType.ESCALATE_INCIDENT],
    "dns tunnel": [ActionType.BLOCK_IP, ActionType.ISOLATE_HOST],
    "data transfer": [ActionType.BLOCK_DOMAIN, ActionType.BLOCK_IP],
    # Generic
    "anomal": [ActionType.CHECK_LOGS, ActionType.CORRELATE_ALERTS],
    "suspicious": [ActionType.QUERY_THREAT_INTEL, ActionType.CHECK_LOGS],
}

# Actions that should typically come at the end
_CLOSING_ACTIONS = [
    ActionType.ESCALATE_INCIDENT,
    ActionType.UPDATE_RULES,
    ActionType.CREATE_TICKET,
    ActionType.CLOSE_ALERT,
]


def _intent_based_action(obs: Observation) -> Optional[ActionType]:
    """Prioritise actions based on alert type and risk profile."""
    desc = obs.current_alert.description.lower()
    alert_type = obs.current_alert.alert_type.value.lower()
    history = set(obs.action_history)

    def first_available(candidates: List[ActionType]) -> Optional[ActionType]:
        for candidate in candidates:
            if candidate.value not in history:
                return candidate
        return None

    if obs.risk_score > 7.0:
        mitigation_priority = [
            ActionType.ISOLATE_HOST,
            ActionType.BLOCK_IP,
            ActionType.BLOCK_DOMAIN,
            ActionType.QUARANTINE_FILE,
            ActionType.REVOKE_CREDENTIALS,
        ]
        mitigation_choice = first_available(mitigation_priority)
        if mitigation_choice is not None:
            return mitigation_choice

    if "phishing" in alert_type or "email" in desc or "spf" in desc or "dkim" in desc:
        return first_available([
            ActionType.ANALYZE_EMAIL,
            ActionType.CHECK_SENDER_REPUTATION,
            ActionType.SCAN_URL,
            ActionType.ANALYZE_ATTACHMENT,
        ])

    if "credential" in alert_type or "login" in desc or "authentication" in desc:
        return first_available([
            ActionType.ESCALATE_INCIDENT,
            ActionType.DISABLE_ACCOUNT,
            ActionType.REVOKE_CREDENTIALS,
            ActionType.CHECK_LOGS,
        ])

    if "privilege" in alert_type or "lateral" in alert_type or "rdp" in desc or "psexec" in desc:
        return first_available([
            ActionType.ISOLATE_HOST,
            ActionType.BLOCK_IP,
            ActionType.CORRELATE_ALERTS,
            ActionType.QUERY_THREAT_INTEL,
        ])

    return None


def _rule_based_action(obs: Observation, step_idx: int) -> Optional[ActionType]:
    """Pick an action using keyword matching on the current alert description."""
    desc = obs.current_alert.description.lower()
    alert_type = obs.current_alert.alert_type.value.lower()
    history = set(obs.action_history)

    # Collect candidate actions from matching keywords
    candidates: List[ActionType] = []
    for keyword, actions in _KEYWORD_RULES.items():
        if keyword in desc or keyword in alert_type:
            for a in actions:
                if a.value not in history:
                    candidates.append(a)

    # De-duplicate while preserving order
    seen = set()
    unique: List[ActionType] = []
    for c in candidates:
        if c not in seen:
            seen.add(c)
            unique.append(c)

    if unique:
        return unique[0]

    # Fallback: try closing actions if we've done enough
    if step_idx > 2:
        for ca in _CLOSING_ACTIONS:
            if ca.value not in history:
                return ca

    return None


# ---------------------------------------------------------------------------
# LLM fallback
# ---------------------------------------------------------------------------

def _llm_action(obs: Observation) -> Optional[ActionType]:
    """Ask the LLM to pick the next action."""
    available = obs.available_actions
    prompt = (
        f"You are a SOC analyst AI. Current alert:\n"
        f"  Type: {obs.current_alert.alert_type.value}\n"
        f"  Severity: {obs.current_alert.severity.value}\n"
        f"  Description: {obs.current_alert.description}\n"
        f"  MITRE Technique: {obs.mitre_technique}\n"
        f"  Risk Score: {obs.risk_score}\n"
        f"  Actions taken so far: {obs.action_history}\n\n"
        f"Choose the SINGLE best next action from: {available}\n"
        f"Reply with ONLY the action name, nothing else."
    )

    try:
        response = client.chat.completions.create(
            model=MODEL_NAME,
            messages=[{"role": "user", "content": prompt}],
            max_tokens=50,
            temperature=0.0,
        )
        choice = response.choices[0].message.content.strip().lower()
        # Try to match to an ActionType
        for at in ActionType:
            if at.value == choice:
                return at
        # Fuzzy match
        for at in ActionType:
            if at.value in choice or choice in at.value:
                return at
    except Exception as exc:
        print(f"  [LLM fallback error: {exc}]", file=sys.stderr)

    return None


# ---------------------------------------------------------------------------
# Agent loop
# ---------------------------------------------------------------------------

def choose_action(obs: Observation, step_idx: int) -> ActionType:
    """Pick the best action: LLM via proxy first, rule-based fallbacks second."""
    # Always call LLM first to use the injected API_BASE_URL/API_KEY proxy
    action = _llm_action(obs)
    if action is not None:
        return action

    # Fall back to rule-based if LLM call fails
    action = _intent_based_action(obs)
    if action is not None:
        return action

    action = _rule_based_action(obs, step_idx)
    if action is not None:
        return action

    # Ultimate fallback
    return ActionType.CHECK_LOGS


def run_task(env: SOCEnvironment, task_name: str) -> float:
    """Run one task. Returns the final score."""
    obs = env.reset(task_name)

    print(f"\n[START]")
    print(f"task: {task_name}")
    print()

    step_idx = 0
    last_score = 0.0

    while not obs.done:
        action_type = choose_action(obs, step_idx)
        action = Action(action_type=action_type)
        obs, reward, done, info = env.step(action)

        print(f"[STEP]")
        print(f"action: {action_type.value}")
        print(f"reward: {reward.value}")
        print()

        step_idx += 1

        if done:
            grade = info.get("grade", {})
            last_score = grade.get("total", 0.0)

    print(f"[END]")
    print(f"score: {last_score}")
    print()

    return last_score


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    env = SOCEnvironment()
    tasks = TaskRegistry.list_tasks()

    scores = {}
    for task_name in tasks:
        score = run_task(env, task_name)
        scores[task_name] = score

    print("=" * 50)
    print("SUMMARY")
    print("=" * 50)
    for t, s in scores.items():
        print(f"  {t}: {s:.4f}")
    avg = sum(scores.values()) / len(scores) if scores else 0
    print(f"  AVERAGE: {avg:.4f}")


if __name__ == "__main__":
    main()
