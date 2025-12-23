"""
Declassifier - Authorized downward information transfer.

Sometimes information MUST flow downward (e.g., CEO briefing staff).
The declassifier provides a controlled, auditable mechanism for this.

Features:
- Request/approve workflow for declassification
- Time-limited declassification with automatic expiration
- Notification callbacks for approvers
- Audit trail integration
- Partial declassification (sanitization)
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Callable, Optional
import uuid
import re

from clearance.models import Label, SecurityLevel, User


class RequestStatus(Enum):
    """Status of a declassification request."""
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    EXPIRED = "expired"
    REVOKED = "revoked"


@dataclass
class DeclassifyRequest:
    """
    A request to declassify information for downward transfer.

    Attributes:
        id: Unique request identifier
        content: The content to be declassified
        from_level: Original security level
        to_level: Requested target level
        requester: User making the request
        justification: Why this declassification is needed
        recipient: Optional specific recipient
        status: Current status of the request
        created_at: When the request was created
        reviewed_by: User who reviewed the request
        reviewed_at: When the request was reviewed
        expires_at: When the declassification expires
        sanitized_content: Sanitized version if partial declassification
        denial_reason: Reason for denial if denied
    """
    id: str
    content: str
    from_level: SecurityLevel
    to_level: SecurityLevel
    requester: User
    justification: str
    recipient: Optional[User] = None
    status: RequestStatus = RequestStatus.PENDING
    created_at: datetime = field(default_factory=datetime.now)
    reviewed_by: Optional[User] = None
    reviewed_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    sanitized_content: Optional[str] = None
    denial_reason: Optional[str] = None

    def is_expired(self) -> bool:
        """Check if the declassification has expired."""
        if self.expires_at is None:
            return False
        return datetime.now() > self.expires_at

    def is_valid(self) -> bool:
        """Check if the declassification is currently valid."""
        return self.status == RequestStatus.APPROVED and not self.is_expired()


@dataclass
class SanitizationRule:
    """Rule for sanitizing content during partial declassification."""
    pattern: str  # Regex pattern
    replacement: str  # Replacement text
    level: SecurityLevel  # Minimum level to apply this rule


class Declassifier:
    """
    Manages declassification requests and approvals.

    Provides an audit trail for authorized downward information flow.
    This is essential for real-world use where strict BLP would be
    too restrictive.

    Example:
        declassifier = Declassifier()

        # CEO assistant requests to share summary with staff
        request = declassifier.request(
            content="Q3 summary: growth on track, revenue $10M",
            from_level=SecurityLevel.EXECUTIVE,
            to_level=SecurityLevel.STAFF,
            requester=ceo_assistant,
            justification="CEO approved sharing summary with team"
        )

        # CEO approves with 24-hour expiration
        declassifier.approve(
            request.id,
            approver=ceo,
            expires_in=timedelta(hours=24)
        )

        # Check if content can be shared
        if declassifier.can_share(request.id):
            content = declassifier.get_content(request.id)
    """

    def __init__(
        self,
        approval_callback: Optional[Callable[[DeclassifyRequest], None]] = None,
        require_justification: bool = True,
        default_expiration: Optional[timedelta] = None,
    ) -> None:
        """
        Initialize the declassifier.

        Args:
            approval_callback: Optional callback when requests need approval
            require_justification: Whether justification is required
            default_expiration: Default expiration time for approvals
        """
        self._requests: dict[str, DeclassifyRequest] = {}
        self._declassified: dict[str, Label] = {}
        self._approval_callback = approval_callback
        self._require_justification = require_justification
        self._default_expiration = default_expiration
        self._sanitization_rules: list[SanitizationRule] = []
        self._pending_notifiers: list[Callable[[DeclassifyRequest], None]] = []

    def add_sanitization_rule(
        self,
        pattern: str,
        replacement: str,
        level: SecurityLevel
    ) -> None:
        """
        Add a sanitization rule for partial declassification.

        Args:
            pattern: Regex pattern to match
            replacement: Text to replace with
            level: Minimum level this rule applies to
        """
        self._sanitization_rules.append(SanitizationRule(
            pattern=pattern,
            replacement=replacement,
            level=level
        ))

    def on_pending(self, callback: Callable[[DeclassifyRequest], None]) -> None:
        """Register a callback for new pending requests."""
        self._pending_notifiers.append(callback)

    def request(
        self,
        content: str,
        from_level: SecurityLevel,
        to_level: SecurityLevel,
        requester: User,
        justification: str = "",
        recipient: Optional[User] = None,
        auto_sanitize: bool = False,
    ) -> DeclassifyRequest:
        """
        Create a declassification request.

        Args:
            content: The content to declassify
            from_level: Current security level
            to_level: Requested target level
            requester: User making the request
            justification: Reason for declassification
            recipient: Optional specific recipient
            auto_sanitize: Whether to auto-generate sanitized version

        Returns:
            The created request
        """
        if to_level >= from_level:
            raise ValueError("Target level must be lower than current level")

        if self._require_justification and not justification.strip():
            raise ValueError("Justification is required")

        # Auto-sanitize if requested
        sanitized = None
        if auto_sanitize:
            sanitized = self._sanitize_content(content, to_level)

        request = DeclassifyRequest(
            id=str(uuid.uuid4()),
            content=content,
            from_level=from_level,
            to_level=to_level,
            requester=requester,
            justification=justification,
            recipient=recipient,
            sanitized_content=sanitized,
        )
        self._requests[request.id] = request

        # Notify pending callbacks
        for callback in self._pending_notifiers:
            try:
                callback(request)
            except Exception:
                pass  # Don't let callback errors block the request

        # Call approval callback if set
        if self._approval_callback:
            self._approval_callback(request)

        return request

    def _sanitize_content(self, content: str, target_level: SecurityLevel) -> str:
        """Apply sanitization rules to content."""
        result = content
        for rule in self._sanitization_rules:
            if rule.level > target_level:
                result = re.sub(rule.pattern, rule.replacement, result)
        return result

    def approve(
        self,
        request_id: str,
        approver: User,
        expires_in: Optional[timedelta] = None,
        sanitized_content: Optional[str] = None,
    ) -> bool:
        """
        Approve a declassification request.

        The approver must have clearance >= the original level.

        Args:
            request_id: ID of the request to approve
            approver: User approving the request
            expires_in: How long the declassification is valid
            sanitized_content: Optional sanitized version to use

        Returns:
            True if approved, False if approval failed
        """
        request = self._requests.get(request_id)
        if not request:
            return False

        if request.status != RequestStatus.PENDING:
            return False

        # Approver must have clearance for the original level
        if approver.clearance < request.from_level:
            return False

        request.status = RequestStatus.APPROVED
        request.reviewed_by = approver
        request.reviewed_at = datetime.now()

        # Set expiration
        expiration = expires_in or self._default_expiration
        if expiration:
            request.expires_at = datetime.now() + expiration

        # Set sanitized content if provided
        if sanitized_content:
            request.sanitized_content = sanitized_content

        # Record the declassified content with new label
        self._declassified[request_id] = Label(
            level=request.to_level,
            source=f"declassified:{request_id}",
            topics=["declassified"],
        )

        return True

    def deny(
        self,
        request_id: str,
        approver: User,
        reason: str = ""
    ) -> bool:
        """
        Deny a declassification request.

        Args:
            request_id: ID of the request to deny
            approver: User denying the request
            reason: Reason for denial

        Returns:
            True if denied, False if denial failed
        """
        request = self._requests.get(request_id)
        if not request:
            return False

        if request.status != RequestStatus.PENDING:
            return False

        request.status = RequestStatus.DENIED
        request.reviewed_by = approver
        request.reviewed_at = datetime.now()
        request.denial_reason = reason
        return True

    def revoke(self, request_id: str, revoker: User) -> bool:
        """
        Revoke an approved declassification.

        Args:
            request_id: ID of the request to revoke
            revoker: User revoking the declassification

        Returns:
            True if revoked, False otherwise
        """
        request = self._requests.get(request_id)
        if not request:
            return False

        if request.status != RequestStatus.APPROVED:
            return False

        # Revoker must have sufficient clearance
        if revoker.clearance < request.from_level:
            return False

        request.status = RequestStatus.REVOKED
        if request_id in self._declassified:
            del self._declassified[request_id]

        return True

    def can_share(self, request_id: str) -> bool:
        """
        Check if content can be shared based on declassification status.

        Args:
            request_id: The declassification request ID

        Returns:
            True if content can be shared
        """
        request = self._requests.get(request_id)
        if not request:
            return False

        # Check expiration
        if request.is_expired():
            request.status = RequestStatus.EXPIRED
            if request_id in self._declassified:
                del self._declassified[request_id]
            return False

        return request.is_valid()

    def get_content(
        self,
        request_id: str,
        use_sanitized: bool = True
    ) -> Optional[str]:
        """
        Get the content for an approved declassification.

        Args:
            request_id: The declassification request ID
            use_sanitized: Whether to return sanitized content if available

        Returns:
            The content if declassification is valid, None otherwise
        """
        if not self.can_share(request_id):
            return None

        request = self._requests.get(request_id)
        if not request:
            return None

        if use_sanitized and request.sanitized_content:
            return request.sanitized_content

        return request.content

    def get_request(self, request_id: str) -> Optional[DeclassifyRequest]:
        """Get a request by ID."""
        return self._requests.get(request_id)

    def get_pending_requests(
        self,
        for_level: Optional[SecurityLevel] = None
    ) -> list[DeclassifyRequest]:
        """
        Get all pending requests.

        Args:
            for_level: Optional filter for requests at or below this level

        Returns:
            List of pending requests
        """
        pending = [
            r for r in self._requests.values()
            if r.status == RequestStatus.PENDING
        ]

        if for_level is not None:
            pending = [r for r in pending if r.from_level <= for_level]

        return pending

    def get_requests_by_user(self, user_id: str) -> list[DeclassifyRequest]:
        """Get all requests made by a user."""
        return [
            r for r in self._requests.values()
            if r.requester.id == user_id
        ]

    def is_declassified(self, request_id: str) -> bool:
        """Check if content has been declassified."""
        return self.can_share(request_id)

    def get_declassified_label(self, request_id: str) -> Optional[Label]:
        """Get the new label for declassified content."""
        if not self.can_share(request_id):
            return None
        return self._declassified.get(request_id)

    def cleanup_expired(self) -> int:
        """
        Clean up expired declassifications.

        Returns:
            Number of declassifications expired
        """
        count = 0
        for request in self._requests.values():
            if request.status == RequestStatus.APPROVED and request.is_expired():
                request.status = RequestStatus.EXPIRED
                if request.id in self._declassified:
                    del self._declassified[request.id]
                count += 1
        return count

    def get_stats(self) -> dict:
        """Get statistics about declassification requests."""
        status_counts = {status: 0 for status in RequestStatus}
        for request in self._requests.values():
            status_counts[request.status] += 1

        return {
            "total": len(self._requests),
            "pending": status_counts[RequestStatus.PENDING],
            "approved": status_counts[RequestStatus.APPROVED],
            "denied": status_counts[RequestStatus.DENIED],
            "expired": status_counts[RequestStatus.EXPIRED],
            "revoked": status_counts[RequestStatus.REVOKED],
            "active_declassified": len(self._declassified),
        }
