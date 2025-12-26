# Clearance

> **AI Agent Security? The answer was in 1973.**

Bell-LaPadula model-based information flow control for AI agent communications.

## The Problem

Documents are everywhere. Too many for humans to read.

So AI agents read them for us. And they talk to each other.

But wait—**we locked the documents, not the conversations.**

```
Past:   Document → Human                    (ACL on documents ✓)
Now:    Document → Agent → Agent → Human   (??? on conversations)
```

Your company has document access control. But when an AI agent reads an executive document and chats with another agent... where's the security?

**Clearance** applies the classic Bell-LaPadula model to AI agent communications.

## Quick Start

```bash
pip install clearance
```

```python
from clearance import ClearanceChecker, SecurityLevel, User
from clearance.checker import create_checker

# Set up with security keywords
checker = create_checker({
    "revenue": SecurityLevel.EXECUTIVE,
    "salary": SecurityLevel.MANAGER,
    "internal": SecurityLevel.STAFF,
})

# Define users with clearance levels
staff = User("u1", "Alice", SecurityLevel.STAFF)
exec = User("u2", "Bob", SecurityLevel.EXECUTIVE)

# Check if message can be sent
result = checker.check_write("Q3 revenue is $10M", recipient=staff)
print(result.allowed)  # False - NO_WRITE_DOWN violation

result = checker.check_write("Q3 revenue is $10M", recipient=exec)
print(result.allowed)  # True - Executive can receive executive info
```

**That's it.** Three lines to add BLP security to your agent communications.

## Try the Demo

### Option 1: Interactive Multi-Agent Demo (Recommended)

Full-featured demo with multiple AI agents communicating:

```bash
# Install demo dependencies
pip install clearance[demo]

# Run the Streamlit app
streamlit run demo/streamlit_app.py
```

**Features:**
- 6 agents with different clearance levels (CEO, CFO, Manager, HR, Staff, Intern)
- Pre-built attack scenarios (acquisition leak, salary info, prompt injection)
- Free chat mode - send any message between any agents
- Real-time BLP enforcement visualization
- Security analysis matrix

### Option 2: Static HTML Demo

Quick demo without installation:

```bash
# Open directly in browser
open demo/index.html

# Or run local server
python -m http.server 8080
# Visit http://localhost:8080/demo/
```

## How It Works

### The Bell-LaPadula Model (1973)

Two simple rules that prevent information leakage:

| Rule | Name | Meaning |
|------|------|---------|
| **No Read Up** | Simple Security | Can't read above your clearance |
| **No Write Down** | *-Property | Can't write below your level |

The genius is in "No Write Down": even if you have top-secret access, you can't send that information to someone with lower clearance.

### Our Extension: Information-Level Labels

Traditional BLP labels *people*. We label *information*.

Why? Because a manager isn't always handling manager-level info. The CEO might casually mention the weather—that's PUBLIC. But when they mention the acquisition target—that's EXECUTIVE.

```python
# The manager isn't EXECUTIVE level
manager = User("mgr", "Lee", SecurityLevel.MANAGER)

# But this message contains EXECUTIVE information
message = "CEO mentioned acquiring TechCorp for $50M"

# So it gets blocked
result = checker.check_write(message, recipient=manager)
# BLOCKED: message contains EXECUTIVE level info
```

### Security Levels

```python
class SecurityLevel(IntEnum):
    PUBLIC = 0      # Anyone can see
    STAFF = 1       # Internal employees
    MANAGER = 2     # Management only
    EXECUTIVE = 3   # C-suite only
```

### Architecture

```
┌─────────────────────────────────────────────────────┐
│                    AI Agent                         │
│          (Has access to various documents)          │
└─────────────────────────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────┐
│              Clearance Layer (BLP)                  │
│                                                     │
│  1. Analyze message for security-sensitive content  │
│  2. Check recipient's clearance level               │
│  3. Apply No Write Down rule                        │
│  4. Block or allow message                          │
└─────────────────────────────────────────────────────┘
                        │
            ┌───────────┼───────────┐
            ▼           ▼           ▼
       ┌────────┐  ┌────────┐  ┌────────┐
       │  CEO   │  │ Manager│  │ Staff  │
       │EXECUTIVE│ │MANAGER │  │ STAFF  │
       └────────┘  └────────┘  └────────┘
```

## Examples

### Basic Check

```python
from clearance.checker import create_checker
from clearance import SecurityLevel, User

checker = create_checker({
    "confidential": SecurityLevel.MANAGER,
    "secret": SecurityLevel.EXECUTIVE,
})

staff = User("s1", "Staff Kim", SecurityLevel.STAFF)

# This gets blocked
result = checker.check_write("This is confidential info", staff)
assert not result.allowed
assert result.violation == "NO_WRITE_DOWN"
```

### CEO Assistant Scenario

```python
from clearance import (
    ClearanceChecker, Label, LabelStore,
    MessageAnalyzer, SecurityLevel, User
)

# Setup
store = LabelStore()
store.add_keyword("acquisition", Label(SecurityLevel.EXECUTIVE))
store.add_keyword("revenue", Label(SecurityLevel.EXECUTIVE))
store.add_keyword("salary", Label(SecurityLevel.MANAGER))

analyzer = MessageAnalyzer(store)
checker = ClearanceChecker(store, analyzer)

# Organization
ceo = User("ceo", "CEO", SecurityLevel.EXECUTIVE)
manager = User("mgr", "Manager", SecurityLevel.MANAGER)
staff = User("staff", "Staff", SecurityLevel.STAFF)

# CEO tells assistant about acquisition
ceo_message = "We're acquiring TechCorp. Tell the team to prepare."

# Assistant tries to relay to manager
result = checker.check_write(
    "CEO says we're acquiring TechCorp, prepare for integration",
    recipient=manager
)
# BLOCKED: "acquisition" is EXECUTIVE level

# Assistant rephrases without sensitive info
result = checker.check_write(
    "CEO wants the team to prepare for a potential integration project",
    recipient=manager
)
# ALLOWED: No EXECUTIVE-level keywords
```

### Finding Safe Recipients

```python
all_users = [ceo, manager, staff, intern]
message = "Q3 revenue exceeded projections"

# Who can safely receive this?
allowed = checker.get_allowed_recipients(message, all_users)
# Returns: [ceo] (only EXECUTIVE level users)
```

## API Reference

### ClearanceChecker

The main interface for BLP enforcement.

```python
checker = ClearanceChecker(label_store, analyzer)

# Check if message can be sent
result = checker.check_write(message, recipient, context=[])

# Check if user can read content
result = checker.check_read(content_level, reader)

# Get list of allowed recipients
allowed = checker.get_allowed_recipients(message, potential_recipients)

# Get minimum clearance needed for message
level = checker.get_minimum_clearance(message)
```

### LabelStore

Storage for security labels and keywords.

```python
store = LabelStore()

# Register keywords that indicate security levels
store.add_keyword("revenue", Label(SecurityLevel.EXECUTIVE))

# Add labeled content
store.add("Q3 revenue is $10M", Label(SecurityLevel.EXECUTIVE, source="q3_report"))

# Query labels
label = store.get_by_content("Q3 revenue is $10M")
labels = store.get_by_source("q3_report")
```

### MessageAnalyzer

Analyzes messages to determine security level.

```python
analyzer = MessageAnalyzer(label_store)

# Get security level of message
level = analyzer.analyze(message)

# Get detailed analysis
level, matching_labels = analyzer.analyze_detailed(message)
```

## Why BLP?

### Don't Reinvent the Wheel

Information flow control isn't new. The Bell-LaPadula model was developed in 1973 for military systems and has been battle-tested for 50 years.

When people say "we need AI agent security," they often mean:
- Prevent agents from leaking sensitive information
- Control what information flows where
- Maintain confidentiality across agent interactions

**That's literally what BLP was designed for.**

### Formal Foundations

BLP has formal proofs of security properties. When you use Clearance:

- **Theorem**: Information cannot flow from high to low security levels
- **Corollary**: An agent with EXECUTIVE info cannot leak to STAFF users

No ad-hoc rules. No hoping your prompt engineering holds. Mathematical guarantees.

### Simple Mental Model

Two rules. That's it.
- Can't read above your level
- Can't write below your level

Everyone from developers to executives can understand this.

## Roadmap

- [x] Core BLP checker
- [x] Keyword-based analyzer
- [x] In-memory label store
- [x] LLM-based semantic analyzer (OpenAI, Anthropic, Ollama)
- [x] Slack integration
- [x] Email integration
- [x] Declassification workflow (with expiration & revocation)
- [x] Audit logging (in-memory & file backends)
- [x] Interactive demo page
- [ ] Persistent label store (Redis, PostgreSQL)
- [ ] Multi-category labels (compartmentalization)

## References

- Bell, D.E. & LaPadula, L.J. (1973). *Secure Computer Systems: Mathematical Foundations*
- Denning, D.E. (1976). *A Lattice Model of Secure Information Flow*
- Myers, A.C. & Liskov, B. (2000). *Protecting Privacy using the Decentralized Label Model*

## Contributing

Contributions welcome! Please read our contributing guidelines.

## License

MIT License - see [LICENSE](LICENSE) for details.
