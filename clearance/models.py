"""
Core data models for Clearance.

Implements the Bell-LaPadula security model primitives:
- SecurityLevel: Hierarchical security classification
- Label: Information unit classification
- Message: Communication between agents
- User: Entity with security clearance
- CheckResult: Result of BLP policy check
"""

from dataclasses import dataclass, field
from enum import IntEnum
from typing import Optional


class SecurityLevel(IntEnum):
    """
    Hierarchical security levels forming a lattice.

    Higher values indicate higher classification.
    The ordering enables BLP comparisons:
    - No Read Up: subject.clearance >= object.level
    - No Write Down: object.level >= subject.clearance
    """
    PUBLIC = 0
    STAFF = 1
    MANAGER = 2
    EXECUTIVE = 3

    def __str__(self) -> str:
        return self.name

    def can_read(self, object_level: "SecurityLevel") -> bool:
        """Check if this clearance level can read the given object level."""
        return self >= object_level

    def can_write_to(self, recipient_clearance: "SecurityLevel") -> bool:
        """Check if writing to recipient would violate No Write Down."""
        return recipient_clearance >= self


@dataclass
class Label:
    """
    Security label for an information unit.

    Unlike traditional BLP where subjects (people) have clearances,
    we label information units. This enables fine-grained control:
    a manager isn't always MANAGER level - specific information they
    possess may be EXECUTIVE level.

    Attributes:
        level: Security classification of this information
        source: Origin of the information (e.g., "ceo_meeting_2024_01")
        topics: Related topics for keyword matching
    """
    level: SecurityLevel
    source: str = ""
    topics: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if isinstance(self.level, int):
            self.level = SecurityLevel(self.level)


@dataclass
class Message:
    """
    A message being sent between agents/users.

    Attributes:
        content: The message text
        sender: Sender identifier
        recipient: Recipient identifier
        labels: Security labels of information contained in this message
    """
    content: str
    sender: str
    recipient: str
    labels: list[Label] = field(default_factory=list)

    def get_max_level(self) -> SecurityLevel:
        """Get the highest security level in this message's labels."""
        if not self.labels:
            return SecurityLevel.PUBLIC
        return max(label.level for label in self.labels)


@dataclass
class User:
    """
    An entity (human or agent) with security clearance.

    Attributes:
        id: Unique identifier
        name: Display name
        clearance: Maximum security level this user can access
    """
    id: str
    name: str
    clearance: SecurityLevel

    def __post_init__(self) -> None:
        if isinstance(self.clearance, int):
            self.clearance = SecurityLevel(self.clearance)


@dataclass
class CheckResult:
    """
    Result of a BLP policy check.

    Attributes:
        allowed: Whether the operation is permitted
        violation: Type of violation if not allowed (e.g., "NO_WRITE_DOWN")
        message_level: Detected security level of the message
        recipient_clearance: Clearance level of the recipient
        reason: Human-readable explanation
        violating_labels: Labels that caused the violation
    """
    allowed: bool
    violation: Optional[str] = None
    message_level: Optional[SecurityLevel] = None
    recipient_clearance: Optional[SecurityLevel] = None
    reason: Optional[str] = None
    violating_labels: list[Label] = field(default_factory=list)

    def __bool__(self) -> bool:
        return self.allowed

    def __str__(self) -> str:
        if self.allowed:
            return "CheckResult(ALLOWED)"
        return (
            f"CheckResult(DENIED: {self.violation}, "
            f"message_level={self.message_level}, "
            f"recipient_clearance={self.recipient_clearance})"
        )
