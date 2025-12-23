"""
Clearance Checker - BLP Policy Enforcement.

The core of Clearance: enforces Bell-LaPadula security properties
on agent communications.

Key BLP Properties:
- Simple Security (No Read Up): A subject can only read objects
  at or below their clearance level
- *-Property (No Write Down): A subject can only write to objects
  at or above their current level

For AI agents, we focus on No Write Down:
- An agent with access to EXECUTIVE information cannot send
  that information to someone with only STAFF clearance
"""

from clearance.models import CheckResult, Label, SecurityLevel, User
from clearance.analyzer import MessageAnalyzer
from clearance.label_store import LabelStore


class ClearanceChecker:
    """
    Enforces BLP security policy on message passing.

    Example:
        store = LabelStore()
        store.add_keyword("revenue", Label(SecurityLevel.EXECUTIVE))

        analyzer = MessageAnalyzer(store)
        checker = ClearanceChecker(store, analyzer)

        staff = User("u1", "Alice", SecurityLevel.STAFF)
        result = checker.check_write(
            message="Q3 revenue is $10M",
            recipient=staff
        )
        # result.allowed == False (NO_WRITE_DOWN violation)
    """

    def __init__(self, label_store: LabelStore, analyzer: MessageAnalyzer) -> None:
        """
        Initialize the checker.

        Args:
            label_store: Store for content-label mappings
            analyzer: Analyzer for determining message security levels
        """
        self.label_store = label_store
        self.analyzer = analyzer

    def check_write(
        self,
        message: str,
        recipient: User,
        context: list[Label] | None = None,
    ) -> CheckResult:
        """
        Check if sending a message to recipient violates No Write Down.

        This is the core BLP check: can this message be sent to this recipient?

        Args:
            message: The message content to check
            recipient: The intended recipient with their clearance level
            context: Optional additional context labels for analysis

        Returns:
            CheckResult indicating if the message can be sent
        """
        context = context or []

        # Analyze the message to determine its security level
        message_level, matching_labels = self.analyzer.analyze_detailed(
            message, context
        )

        # BLP No Write Down: message level must not exceed recipient clearance
        if message_level > recipient.clearance:
            violating = [l for l in matching_labels if l.level > recipient.clearance]
            return CheckResult(
                allowed=False,
                violation="NO_WRITE_DOWN",
                message_level=message_level,
                recipient_clearance=recipient.clearance,
                reason=(
                    f"Message contains {message_level.name} level information, "
                    f"but recipient {recipient.name} only has "
                    f"{recipient.clearance.name} clearance"
                ),
                violating_labels=violating,
            )

        return CheckResult(
            allowed=True,
            message_level=message_level,
            recipient_clearance=recipient.clearance,
        )

    def check_read(
        self,
        content_level: SecurityLevel,
        reader: User,
    ) -> CheckResult:
        """
        Check if a user can read content at a given level.

        BLP Simple Security: reader clearance must be >= content level.

        Args:
            content_level: Security level of the content
            reader: The user attempting to read

        Returns:
            CheckResult indicating if read is allowed
        """
        if reader.clearance < content_level:
            return CheckResult(
                allowed=False,
                violation="NO_READ_UP",
                message_level=content_level,
                recipient_clearance=reader.clearance,
                reason=(
                    f"Content is {content_level.name} level, "
                    f"but {reader.name} only has {reader.clearance.name} clearance"
                ),
            )

        return CheckResult(
            allowed=True,
            message_level=content_level,
            recipient_clearance=reader.clearance,
        )

    def get_allowed_recipients(
        self,
        message: str,
        potential_recipients: list[User],
        context: list[Label] | None = None,
    ) -> list[User]:
        """
        Filter recipients to only those who can receive this message.

        Useful for agents that need to broadcast information:
        this tells them who they can safely send to.

        Args:
            message: The message to send
            potential_recipients: List of potential recipients
            context: Optional context for analysis

        Returns:
            List of recipients who can safely receive this message
        """
        allowed = []
        for recipient in potential_recipients:
            result = self.check_write(message, recipient, context)
            if result.allowed:
                allowed.append(recipient)
        return allowed

    def get_minimum_clearance(
        self,
        message: str,
        context: list[Label] | None = None,
    ) -> SecurityLevel:
        """
        Get the minimum clearance needed to receive this message.

        Args:
            message: The message content
            context: Optional context for analysis

        Returns:
            Minimum SecurityLevel required to receive this message
        """
        return self.analyzer.analyze(message, context)


def create_checker(keywords: dict[str, SecurityLevel] | None = None) -> ClearanceChecker:
    """
    Factory function to create a configured ClearanceChecker.

    Convenience function for quick setup with keyword-based checking.

    Args:
        keywords: Optional dict mapping keywords to security levels

    Returns:
        Configured ClearanceChecker ready to use

    Example:
        checker = create_checker({
            "revenue": SecurityLevel.EXECUTIVE,
            "confidential": SecurityLevel.MANAGER,
            "internal": SecurityLevel.STAFF,
        })
    """
    store = LabelStore()
    if keywords:
        for keyword, level in keywords.items():
            store.add_keyword(keyword, Label(level=level))

    analyzer = MessageAnalyzer(store)
    return ClearanceChecker(store, analyzer)
