#!/usr/bin/env python3
"""
CEO Assistant Scenario - Full demonstration of Clearance.

Scenario:
- CEO's AI assistant receives instructions from CEO (EXECUTIVE level)
- Assistant needs to communicate with team leads and staff
- Some information can flow down, some cannot

This demonstrates real-world use of BLP in AI agent communications.
"""

from clearance import (
    ClearanceChecker,
    Label,
    LabelStore,
    MessageAnalyzer,
    SecurityLevel,
    User,
)


def setup_company():
    """Set up company structure and security keywords."""

    # Create label store with company-specific keywords
    store = LabelStore()

    # Executive-level keywords
    executive_keywords = [
        "acquisition", "merger", "layoff", "restructuring",
        "board meeting", "investor", "valuation", "股价",  # stock price
    ]
    for kw in executive_keywords:
        store.add_keyword(kw, Label(
            level=SecurityLevel.EXECUTIVE,
            source="executive_policy",
            topics=["executive", "confidential"]
        ))

    # Manager-level keywords
    manager_keywords = [
        "budget", "headcount", "performance review", "promotion",
        "salary", "compensation", "hiring plan",
    ]
    for kw in manager_keywords:
        store.add_keyword(kw, Label(
            level=SecurityLevel.MANAGER,
            source="hr_policy",
            topics=["hr", "management"]
        ))

    # Staff-level keywords
    staff_keywords = [
        "internal", "team only", "not for external",
    ]
    for kw in staff_keywords:
        store.add_keyword(kw, Label(
            level=SecurityLevel.STAFF,
            source="general_policy",
            topics=["internal"]
        ))

    analyzer = MessageAnalyzer(store)
    checker = ClearanceChecker(store, analyzer)

    return store, checker


def create_org():
    """Create organization structure."""
    return {
        "ceo": User("ceo", "CEO Kim", SecurityLevel.EXECUTIVE),
        "cfo": User("cfo", "CFO Park", SecurityLevel.EXECUTIVE),
        "eng_lead": User("eng_lead", "Engineering Lead Lee", SecurityLevel.MANAGER),
        "hr_lead": User("hr_lead", "HR Lead Choi", SecurityLevel.MANAGER),
        "dev1": User("dev1", "Developer Jung", SecurityLevel.STAFF),
        "dev2": User("dev2", "Developer Kang", SecurityLevel.STAFF),
        "external": User("ext", "External Consultant", SecurityLevel.PUBLIC),
    }


def simulate_ceo_assistant():
    """Simulate CEO assistant handling various requests."""

    print("=" * 70)
    print("CEO Assistant AI - Clearance Security Demo")
    print("=" * 70)
    print()

    store, checker = setup_company()
    org = create_org()

    # Scenario 1: CEO gives instruction about acquisition
    print("SCENARIO 1: Confidential Acquisition Discussion")
    print("-" * 70)

    ceo_instruction = """
    We're planning to acquire TechStartup Inc. for $50M.
    Don't share the valuation details with anyone except CFO.
    Tell the engineering lead to prepare integration plans.
    """
    print(f"CEO's instruction to assistant:\n{ceo_instruction}")

    # Assistant tries to relay different messages
    messages = [
        ("CFO Park", org["cfo"],
         "CEO wants to discuss the TechStartup acquisition valued at $50M"),
        ("Engineering Lead", org["eng_lead"],
         "CEO wants you to prepare for a potential integration project"),
        ("Engineering Lead", org["eng_lead"],
         "The acquisition target valuation is $50M, prepare accordingly"),
        ("Developer Jung", org["dev1"],
         "There might be some new integration work coming up"),
    ]

    print("\nAssistant attempts to send messages:")
    print()

    for recipient_name, recipient, message in messages:
        result = checker.check_write(message, recipient)
        status = "✓ SENT" if result.allowed else "✗ BLOCKED"
        print(f"To {recipient_name} ({recipient.clearance.name}):")
        print(f"  \"{message[:60]}...\"" if len(message) > 60 else f"  \"{message}\"")
        print(f"  Result: {status}")
        if not result.allowed:
            print(f"  Reason: {result.reason}")
        print()

    # Scenario 2: HR information flow
    print()
    print("SCENARIO 2: HR Information Handling")
    print("-" * 70)

    hr_messages = [
        ("HR Lead", org["hr_lead"],
         "Please prepare the salary adjustment proposals for Q1"),
        ("Developer", org["dev1"],
         "Please prepare the salary adjustment proposals for Q1"),
        ("Developer", org["dev1"],
         "Please update your goals for the upcoming review cycle"),
        ("External", org["external"],
         "We're looking at our internal team structure"),
    ]

    print("HR-related message attempts:")
    print()

    for recipient_name, recipient, message in hr_messages:
        result = checker.check_write(message, recipient)
        status = "✓ SENT" if result.allowed else "✗ BLOCKED"
        print(f"To {recipient_name} ({recipient.clearance.name}):")
        print(f"  \"{message}\"")
        print(f"  Result: {status}")
        if not result.allowed:
            print(f"  Reason: {result.reason}")
        print()

    # Scenario 3: Finding safe recipients
    print()
    print("SCENARIO 3: Finding Appropriate Recipients")
    print("-" * 70)

    sensitive_msg = "Board meeting decided on restructuring and layoff plans"
    print(f"Message: \"{sensitive_msg}\"")
    print()

    min_level = checker.get_minimum_clearance(sensitive_msg)
    print(f"Minimum clearance required: {min_level.name}")

    all_users = list(org.values())
    allowed = checker.get_allowed_recipients(sensitive_msg, all_users)
    blocked = [u for u in all_users if u not in allowed]

    print(f"\nCan receive: {[u.name for u in allowed]}")
    print(f"Cannot receive: {[u.name for u in blocked]}")

    print()
    print("=" * 70)
    print("Simulation complete - BLP enforcement working correctly!")
    print("=" * 70)


if __name__ == "__main__":
    simulate_ceo_assistant()
