# Clearance

### Stop your AI agents from leaking secrets.

[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)
[![Tests](https://img.shields.io/badge/tests-189%20passed-brightgreen.svg)]()

---

**The Problem**: Your AI agents can read confidential documents. They talk to each other. They talk to users. But there's no access control on those conversations.

**The Solution**: Clearance adds a security layer that prevents sensitive information from flowing to unauthorized recipients. Built on the [Bell-LaPadula model](https://en.wikipedia.org/wiki/Bell%E2%80%93LaPadula_model) (1973) - the same formal model used in military systems for 50 years.

```
CEO Document (EXECUTIVE) → Agent → Agent → Intern (STAFF)
                              ↓
                         [BLOCKED by Clearance]
```

## Install

```bash
pip install clearance
```

## 3 Lines to Secure Your Agents

```python
from clearance import create_checker, SecurityLevel, User

# 1. Define what's sensitive
checker = create_checker({
    "revenue": SecurityLevel.EXECUTIVE,
    "salary": SecurityLevel.MANAGER,
})

# 2. Define who can see what
intern = User("intern", "Intern", SecurityLevel.STAFF)

# 3. Check before sending
result = checker.check_write("Q3 revenue is $10M", recipient=intern)
print(result.allowed)  # False - BLOCKED
```

## Why This Matters

```
                     Without Clearance          With Clearance
                     ─────────────────          ──────────────
CEO tells agent      "Revenue is $10M"          "Revenue is $10M"
about revenue                ↓                          ↓
                             ↓                          ↓
Agent processes              ↓                          ↓
the information              ↓                          ↓
                             ↓                          ↓
Intern asks          "What did CEO say?"        "What did CEO say?"
the agent                    ↓                          ↓
                             ↓                          ↓
Agent responds       "Revenue is $10M"          "I can't share that
                            ❌                    information with you"
                      DATA LEAKED                       ✅
```

## Try the Demo

```bash
pip install clearance[demo]
streamlit run demo/streamlit_app.py
```

6 agents, 4 attack scenarios, real-time BLP enforcement.

## Features

| Feature | Status | Description |
|---------|--------|-------------|
| Core BLP Engine | ✅ | No-Read-Up, No-Write-Down enforcement |
| Keyword Detection | ✅ | Flag sensitive terms automatically |
| LLM Semantic Analysis | ✅ | OpenAI/Anthropic/Ollama backends |
| Slack Integration | ✅ | Intercept messages in real-time |
| Email Gateway | ✅ | Filter outgoing emails |
| Declassification | ✅ | Controlled downgrade with audit trail |
| Audit Logging | ✅ | Track all security decisions |

## How It Works

### The Bell-LaPadula Model

Two rules that guarantee no information leakage:

| Rule | What It Means |
|------|---------------|
| **No Read Up** | Can't access info above your clearance |
| **No Write Down** | Can't send info to someone below your level |

The key insight: **even if an agent has access to secrets, it cannot share them with unauthorized users**.

### Security Levels

```python
PUBLIC (0)     →  Anyone
STAFF (1)      →  Internal employees
MANAGER (2)    →  Management
EXECUTIVE (3)  →  C-suite only
```

### Architecture

```
┌─────────────────────────────────────────┐
│           Your AI Agent                 │
│    (LangChain / CrewAI / AutoGen)       │
└─────────────────┬───────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────┐
│         Clearance Middleware            │
│                                         │
│  ┌─────────┐  ┌─────────┐  ┌─────────┐  │
│  │Analyzer │→ │ Checker │→ │  Audit  │  │
│  └─────────┘  └─────────┘  └─────────┘  │
│                                         │
│  "revenue" detected → EXECUTIVE level   │
│  recipient: STAFF → BLOCKED             │
└─────────────────┬───────────────────────┘
                  │
        ┌─────────┼─────────┐
        ▼         ▼         ▼
    [EXECUTIVE] [MANAGER] [STAFF]
       ✅          ❌        ❌
```

## Real-World Example: CEO Assistant

```python
from clearance import ClearanceChecker, LabelStore, MessageAnalyzer, Label, SecurityLevel, User

# Setup security keywords
store = LabelStore()
store.add_keyword("acquisition", Label(SecurityLevel.EXECUTIVE))
store.add_keyword("revenue", Label(SecurityLevel.EXECUTIVE))
store.add_keyword("salary", Label(SecurityLevel.MANAGER))

checker = ClearanceChecker(store, MessageAnalyzer(store))

# The organization
ceo = User("ceo", "CEO", SecurityLevel.EXECUTIVE)
manager = User("mgr", "Manager Kim", SecurityLevel.MANAGER)
intern = User("intern", "Intern Lee", SecurityLevel.STAFF)

# CEO tells assistant about acquisition
ceo_message = "We're acquiring TechCorp for $50M. Keep it confidential."

# Scenario 1: Assistant tries to tell manager
result = checker.check_write(
    "CEO mentioned we're acquiring TechCorp",
    recipient=manager
)
# ❌ BLOCKED - "acquisition" is EXECUTIVE level

# Scenario 2: Assistant rephrases safely
result = checker.check_write(
    "CEO wants the team prepared for an integration project",
    recipient=manager
)
# ✅ ALLOWED - No sensitive keywords

# Scenario 3: Intern asks about acquisition
result = checker.check_write(
    "The acquisition target is TechCorp",
    recipient=intern
)
# ❌ BLOCKED - Intern doesn't have EXECUTIVE clearance
```

## Benchmarks

### InjecAgent Benchmark (1,054 test cases)

Tested against [InjecAgent](https://arxiv.org/abs/2403.02691) - the first benchmark for indirect prompt injection attacks on tool-integrated LLM agents.

| Defense | Baseline ASR | Defended ASR | Reduction |
|---------|--------------|--------------|-----------|
| No Defense (GPT-4) | 24.0% | 24.0% | 0% |
| GPT-4 Fine-tuned | 24.0% | 7.1% | 70.4% |
| **Clearance** | 24.0% | **1.2%** | **95.2%** |

```bash
python benchmarks/injecagent_runner.py
# Block Rate: 95.2% | ASR: 24% → 1.2%
```

### Comparison with State-of-the-Art

| Defense | Type | ASR Reduction | Utility | Notes |
|---------|------|---------------|---------|-------|
| FIDES (Microsoft) | IFC | 100% | 94% | Complex, requires policy |
| DataFilter | Filtering | 98.4% | 98% | Custom benchmark |
| **Clearance** | IFC (BLP) | **95.2%** | **100%** | Simple, framework-agnostic |
| Spotlighting | Prompt Eng. | 96% | 98% | ⚠️ Bypassed by adaptive attacks |
| Progent | Filtering | 89.6% | - | Autonomous mode |
| Sandwich | Prompt Eng. | 42% | 66% | ⚠️ Bypassed by adaptive attacks |

**Key Insight**: Prompt engineering defenses show good initial results but are [vulnerable to adaptive attacks (>95% ASR)](https://arxiv.org/abs/2503.00061). Clearance uses content-based detection, not prompt-level, making it more robust to such attacks.

<details>
<summary>Run full comparison</summary>

```bash
python benchmarks/comparison.py
```

</details>

## Integrations

### Slack

```python
from clearance.integrations.slack import ClearanceSlackBot

bot = ClearanceSlackBot(checker, user_store)

# Automatically intercepts and checks all messages
@bot.message_handler
def on_message(message, sender, recipient):
    result = bot.intercept_message(message, sender, recipient)
    if not result.allowed:
        return f"⚠️ Message blocked: {result.reason}"
```

### Email

```python
from clearance.integrations.email import ClearanceEmailGateway

gateway = ClearanceEmailGateway(checker, user_store)
result = gateway.check_outgoing(email_content, sender, recipients)
```

### LLM-based Analysis

```python
from clearance import LLMAnalyzer

# Use GPT-4 for semantic analysis instead of keywords
analyzer = LLMAnalyzer(
    backend=OpenAIBackend(api_key="..."),
    label_store=store
)
```

## Comparison with Other Approaches

| Approach | Clearance | Prompt Engineering | Fine-tuning |
|----------|-----------|-------------------|-------------|
| Guarantees | Formal (BLP) | None | None |
| Bypassable | Hard | Easy | Medium |
| Explainable | Yes | No | No |
| Framework-agnostic | Yes | No | No |

## Research

This project applies the Bell-LaPadula model to AI agent communications, an approach explored in recent security research:

- **FIDES** (Microsoft, 2025): Information flow control for AI agents
- **f-secure** (arXiv:2409.19091): System-level defense using IFC
- **MASLEAK**: Shows 87% of multi-agent systems leak IP

Clearance provides a lightweight, practical implementation of these concepts.

## API Reference

<details>
<summary>ClearanceChecker</summary>

```python
checker = ClearanceChecker(label_store, analyzer)

# Check if message can be sent
result = checker.check_write(message, recipient)
result.allowed      # bool
result.violation    # "NO_WRITE_DOWN" | None
result.reason       # Human-readable explanation

# Get minimum clearance needed
level = checker.get_minimum_clearance(message)

# Filter recipients
allowed = checker.get_allowed_recipients(message, all_users)
```

</details>

<details>
<summary>LabelStore</summary>

```python
store = LabelStore()

# Add sensitive keywords
store.add_keyword("revenue", Label(SecurityLevel.EXECUTIVE))
store.add_keyword("salary", Label(SecurityLevel.MANAGER))

# Find matches in text
matches = store.find_matching_keywords("Q3 revenue report")
# [("revenue", Label(EXECUTIVE))]
```

</details>

<details>
<summary>SecurityLevel</summary>

```python
from clearance import SecurityLevel

SecurityLevel.PUBLIC     # 0
SecurityLevel.STAFF      # 1
SecurityLevel.MANAGER    # 2
SecurityLevel.EXECUTIVE  # 3

# Comparison works naturally
SecurityLevel.EXECUTIVE > SecurityLevel.STAFF  # True
```

</details>

## Contributing

Contributions welcome! Areas of interest:

- [ ] Persistent storage backends (Redis, PostgreSQL)
- [ ] Multi-category labels (compartmentalization)
- [ ] More LLM backends
- [ ] Framework integrations (LangChain, CrewAI)

## License

MIT License - Use it, modify it, ship it.

---

<p align="center">
  <b>Security from 1973. Applied to 2025.</b><br>
  <a href="#install">Get Started</a> ·
  <a href="https://github.com/clearance-project/clearance/issues">Report Bug</a> ·
  <a href="https://github.com/clearance-project/clearance/issues">Request Feature</a>
</p>
