#!/usr/bin/env python3
"""
Simple example of using Clearance for BLP enforcement.

This demonstrates the basic flow:
1. Set up security keywords
2. Create users with different clearance levels
3. Check if messages can be sent to recipients
"""

from clearance import (
    ClearanceChecker,
    Label,
    LabelStore,
    MessageAnalyzer,
    SecurityLevel,
    User,
)
from clearance.checker import create_checker


def main():
    print("=" * 60)
    print("Clearance - BLP Security Demo")
    print("=" * 60)
    print()

    # Method 1: Quick setup with create_checker factory
    print("Setting up Clearance with security keywords...")
    checker = create_checker({
        "revenue": SecurityLevel.EXECUTIVE,
        "profit": SecurityLevel.EXECUTIVE,
        "salary": SecurityLevel.MANAGER,
        "confidential": SecurityLevel.MANAGER,
        "internal": SecurityLevel.STAFF,
    })
    print("  - 'revenue', 'profit' -> EXECUTIVE level")
    print("  - 'salary', 'confidential' -> MANAGER level")
    print("  - 'internal' -> STAFF level")
    print()

    # Create users with different clearance levels
    ceo = User("ceo", "CEO Kim", SecurityLevel.EXECUTIVE)
    manager = User("mgr", "Manager Lee", SecurityLevel.MANAGER)
    staff = User("staff", "Staff Park", SecurityLevel.STAFF)
    public = User("public", "External User", SecurityLevel.PUBLIC)

    print("Users:")
    print(f"  - {ceo.name}: {ceo.clearance.name} clearance")
    print(f"  - {manager.name}: {manager.clearance.name} clearance")
    print(f"  - {staff.name}: {staff.clearance.name} clearance")
    print(f"  - {public.name}: {public.clearance.name} clearance")
    print()

    # Test messages
    messages = [
        ("Q3 revenue exceeded expectations!", "Contains 'revenue'"),
        ("Please review the salary adjustments", "Contains 'salary'"),
        ("This is internal information only", "Contains 'internal'"),
        ("Hello, how are you today?", "No sensitive keywords"),
    ]

    # Check each message against each recipient
    print("-" * 60)
    print("Message Security Checks")
    print("-" * 60)

    for message, description in messages:
        print(f"\nMessage: \"{message}\"")
        print(f"  ({description})")
        min_clearance = checker.get_minimum_clearance(message)
        print(f"  Minimum clearance required: {min_clearance.name}")
        print()

        for recipient in [ceo, manager, staff, public]:
            result = checker.check_write(message, recipient)
            status = "ALLOWED" if result.allowed else "BLOCKED"
            print(f"    -> {recipient.name}: {status}", end="")
            if not result.allowed:
                print(f" ({result.violation})")
            else:
                print()

    # Demonstrate filtering allowed recipients
    print()
    print("-" * 60)
    print("Filtering Allowed Recipients")
    print("-" * 60)

    sensitive_message = "Q3 revenue and profit margins are excellent"
    print(f"\nMessage: \"{sensitive_message}\"")

    all_users = [ceo, manager, staff, public]
    allowed = checker.get_allowed_recipients(sensitive_message, all_users)

    print(f"\nCan send to: {[u.name for u in allowed]}")
    print(f"Cannot send to: {[u.name for u in all_users if u not in allowed]}")

    print()
    print("=" * 60)
    print("Demo complete!")
    print("=" * 60)


if __name__ == "__main__":
    main()
