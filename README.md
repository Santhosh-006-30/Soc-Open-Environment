<div align="center">

# 🛡️ SOC OpenEnv

### AI Training Environment for Security Operations Center Analysts

[![OpenEnv Compatible](https://img.shields.io/badge/OpenEnv-Compatible-brightgreen?style=for-the-badge)](https://github.com/openenv)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10+-blue?style=for-the-badge&logo=python)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.104+-009688?style=for-the-badge&logo=fastapi)](https://fastapi.tiangolo.com)
[![Docker Ready](https://img.shields.io/badge/Docker-Ready-2496ED?style=for-the-badge&logo=docker)](https://docker.com)
[![HuggingFace Spaces](https://img.shields.io/badge/🤗-HuggingFace%20Spaces-yellow?style=for-the-badge)](https://huggingface.co/spaces)

*A realistic, multi-task cybersecurity training environment where AI agents learn to detect phishing, investigate malware, and respond to multi-stage APT attacks — all with MITRE ATT&CK integration and dense reward signals.*

</div>

---

## 📖 Overview

**SOC OpenEnv** is an OpenEnv-compatible reinforcement learning environment that simulates a real-world Security Operations Center (SOC). It provides a structured, sequential decision-making framework for training AI agents on cybersecurity incident response.

### Key Features

| Feature | Description |
|---------|-------------|
| 🎯 **3 Realistic Tasks** | Phishing detection, malware investigation, multi-stage APT response |
| 🗺️ **MITRE ATT&CK** | Full technique mapping (T1566, T1078, T1021, T1068, T1048, ...) |
| 📊 **Dynamic Risk Scoring** | Real-time risk scores (1–10) based on severity, time, and context |
| 🏆 **Dense Rewards** | Continuous partial-credit rewards with time penalties |
| 📋 **Deterministic Grading** | Rule-based grading across correctness, sequence, completeness, efficiency |
| 🔗 **Sequential Decisions** | Multi-alert correlation with attack lifecycle progression |
| 🐳 **Docker + HF Spaces** | One-command deployment to Hugging Face Spaces |

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────┐
│                  SOC OpenEnv                     │
│                                                  │
│  ┌──────────┐  ┌──────────┐  ┌──────────────┐  │
│  │  Tasks   │  │  MITRE   │  │ Risk Scorer  │  │
│  │ Registry │  │  Mapper  │  │  (Dynamic)   │  │
│  └────┬─────┘  └────┬─────┘  └──────┬───────┘  │
│       │              │               │           │
│  ┌────▼──────────────▼───────────────▼───────┐  │
│  │           SOCEnvironment                   │  │
│  │       reset() / step() / state()           │  │
│  └────────────────┬──────────────────────────┘  │
│                   │                              │
│  ┌────────────────▼──────────────────────────┐  │
│  │         Grader (Deterministic)             │  │
│  │  correctness · sequence · completeness     │  │
│  └────────────────────────────────────────────┘  │
│                                                  │
├──────────────────────────────────────────────────┤
│               FastAPI Server (app.py)            │
│     GET /reset  ·  POST /step  ·  GET /state     │
└──────────────────────────────────────────────────┘
```

---

## 🎮 Tasks

### 🟢 Easy — Phishing Detection

| Property | Value |
|----------|-------|
| **Alerts** | 1 (suspicious email) |
| **Max Steps** | 12 |
| **MITRE Technique** | T1566 – Phishing |
| **Scenario** | Suspicious email from `noreply@secure-banklogin.com` targeting `jdoe@corp.local` with SPF/DKIM failures |

**Optimal flow:** Analyze email → Check sender → Scan URL → Block domain → Notify user → Create ticket → Close alert

---

### 🟡 Medium — Malware Investigation

| Property | Value |
|----------|-------|
| **Alerts** | 2 (EDR + exfiltration) |
| **Max Steps** | 16 |
| **MITRE Techniques** | T1059 (C&C), T1048 (Exfiltration) |
| **Scenario** | C2 beaconing from `svchost_update.exe` on finance workstation, followed by 2.3 GB DNS tunnel exfiltration |

**Optimal flow:** Threat intel → Network analysis → Isolate host → Quarantine → Block C2 → Check logs → Correlate → Escalate → Ticket → Close

---

### 🔴 Hard — Multi-Stage Attack Chain

| Property | Value |
|----------|-------|
| **Alerts** | 5 (sequential lifecycle) |
| **Max Steps** | 25 |
| **MITRE Techniques** | T1566.001 → T1078 → T1021 → T1068 → T1048 |
| **Scenario** | Full APT lifecycle: spearphishing CFO → credential harvesting → RDP lateral movement → privilege escalation via CVE → data exfiltration |

**Attack Lifecycle:**
```
📧 Spearphishing    →  🔑 Credential Access  →  🔀 Lateral Movement
    (T1566.001)           (T1078)                   (T1021)
                                                       ↓
                    💾 Data Exfiltration  ←  ⬆️ Privilege Escalation
                        (T1048)                  (T1068)
```

---

## 🎬 Action Space

| Category | Actions |
|----------|---------|
| **Investigation** | `analyze_email`, `analyze_attachment`, `check_sender_reputation`, `scan_url`, `query_threat_intel`, `correlate_alerts`, `check_logs`, `analyze_network_traffic` |
| **Containment** | `block_ip`, `block_domain`, `isolate_host`, `disable_account`, `quarantine_file`, `revoke_credentials` |
| **Response** | `escalate_incident`, `create_ticket`, `notify_user`, `update_rules`, `close_alert` |
| **Negative** | `ignore`, `no_action` (penalised) |

---

## 👁️ Observation Space

Each observation includes:

```json
{
  "task_name": "attack_chain_response",
  "current_alert": {
    "alert_id": "ALERT-APT-001",
    "alert_type": "phishing",
    "severity": "medium",
    "description": "Spearphishing email detected...",
    "indicators": { "sender": "...", "attachment": "..." },
    "mitre_technique_id": "T1566.001"
  },
  "pending_alerts": 4,
  "risk_score": 4.35,
  "action_history": ["analyze_email"],
  "step_count": 1,
  "max_steps": 25,
  "mitre_technique": "T1566.001",
  "available_actions": ["analyze_email", "block_ip", "..."],
  "context": { "attack_stages": ["..."] }
}
```

---

## 🏆 Reward Design

| Component | Range | Description |
|-----------|-------|-------------|
| **Alignment** | -0.5 to +1.0 | Optimal (+1.0), partial credit (+0.6), suboptimal (+0.1), harmful (-0.5) |
| **Time Penalty** | 0 to -0.05 | Linearly increases with step count |
| **Severity Bonus** | 0 to +0.15 | Higher for critical alerts when action is correct |
| **Chain Completion** | 0 to +2.0 | Final bonus based on overall grade |

---

## 📊 Grading System

| Axis | Weight | Evaluates |
|------|--------|-----------|
| **Correctness** | 40% | Match against optimal and partial-credit action sets |
| **Sequence** | 30% | Ordering alignment via Longest Common Subsequence |
| **Completeness** | 20% | Coverage of all optimal actions |
| **Efficiency** | 10% | Penalty for harmful or excess actions |

Final score: **0.0 – 1.0** (deterministic, no randomness)

---

## 🚀 Quick Start

### Local Setup

```bash
# Clone
git clone https://github.com/your-org/soc-openenv.git
cd soc-openenv

# Install
pip install -r requirements.txt

# Run API server
python app.py
# → Server at http://localhost:7860

# Run inference (rule-based, no API key needed)
python inference.py
```

### Docker

```bash
# Build
docker build -t soc-openenv .

# Run
docker run -p 7860:7860 soc-openenv

# With LLM support
docker run -p 7860:7860 \
  -e API_BASE_URL=https://api.openai.com/v1 \
  -e MODEL_NAME=gpt-3.5-turbo \
  -e OPENAI_API_KEY=sk-... \
  soc-openenv
```

### API Usage

```bash
# Reset to a task
curl http://localhost:7860/reset?task=phishing_detection

# Take a step
curl -X POST http://localhost:7860/step \
  -H "Content-Type: application/json" \
  -d '{"action": "analyze_email"}'

# Get current state
curl http://localhost:7860/state

# List tasks
curl http://localhost:7860/tasks
```

---

## 📈 Baseline Scores

Scores achieved by the built-in rule-based agent (no LLM):

| Task | Score | Difficulty |
|------|-------|------------|
| `phishing_detection` | **0.82** | 🟢 Easy |
| `malware_investigation` | **0.74** | 🟡 Medium |
| `attack_chain_response` | **0.65** | 🔴 Hard |
| **Average** | **0.74** | — |

*Scores may vary slightly based on keyword matching; LLM-augmented agents typically score 0.85+.*

---

## 📁 Project Structure

```
soc-openenv/
│
├── env/
│   ├── __init__.py          # Package exports
│   ├── environment.py       # Core SOCEnvironment (reset/step/state)
│   ├── models.py            # Pydantic models (Observation, Action, Reward)
│   ├── tasks.py             # Task definitions (easy/medium/hard)
│   ├── graders.py           # Deterministic grading system
│   ├── mitre.py             # MITRE ATT&CK technique mapping
│   └── risk.py              # Dynamic risk scoring engine
│
├── app.py                   # FastAPI server (port 7860)
├── inference.py             # Agent inference script
├── openenv.yaml             # OpenEnv schema definition
├── requirements.txt         # Python dependencies
├── Dockerfile               # Docker build configuration
└── README.md                # This file
```

---

## 🔧 Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `API_BASE_URL` | No | `https://api.openai.com/v1` | OpenAI-compatible API endpoint |
| `MODEL_NAME` | No | `gpt-3.5-turbo` | Model identifier |
| `OPENAI_API_KEY` | No | — | API key (rule-based works without it) |

---

## 🤗 Hugging Face Spaces Deployment

1. Create a new Space (Docker SDK)
2. Upload all project files
3. The app auto-starts on port 7860
4. Set environment variables in Space settings if using LLM features

---

## 📜 License

MIT License — see [LICENSE](LICENSE) for details.

---

<div align="center">
<strong>Built for the next generation of AI-powered SOC analysts 🛡️</strong>
</div>
