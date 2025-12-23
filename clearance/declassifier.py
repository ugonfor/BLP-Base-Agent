"""
Declassifier - Authorized downward information transfer.

Sometimes information MUST flow downward (e.g., CEO briefing staff).
The declassifier provides a controlled, auditable mechanism for this.

This is a Phase 2 feature - placeholder implementation.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional
import uuid

from clearance.models import Label, SecurityLevel, User


class RequestStatus(Enum):
    """Status of a declassification request."""
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    EXPIRED = "expired"


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
        status: Current status of the request
        created_at: When the request was created
        reviewed_by: User who reviewed the request
        reviewed_at: When the request was reviewed
    """
    id: str
    content: str
    from_level: SecurityLevel
    to_level: SecurityLevel
    requester: User
    justification: str
    status: RequestStatus = RequestStatus.PENDING
    created_at: datetime = field(default_factory=datetime.now)
    reviewed_by: Optional[User] = None
    reviewed_at: Optional[datetime] = None


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
            content="Q3 summary: growth on track",
            from_level=SecurityLevel.EXECUTIVE,
            to_level=SecurityLevel.STAFF,
            requester=ceo_assistant,
            justification="CEO approved sharing summary with team"
        )

        # CEO approves
        declassifier.approve(request.id, ceo)
    """

    def __init__(self) -> None:
        self._requests: dict[str, DeclassifyRequest] = {}
        self._declassified: dict[str, Label] = {}

    def request(
        self,
        content: str,
        from_level: SecurityLevel,
        to_level: SecurityLevel,
        requester: User,
        justification: str,
    ) -> DeclassifyRequest:
        """
        Create a declassification request.

        Args:
            content: The content to declassify
            from_level: Current security level
            to_level: Requested target level
            requester: User making the request
            justification: Reason for declassification

        Returns:
            The created request
        """
        if to_level >= from_level:
            raise ValueError("Target level must be lower than current level")

        request = DeclassifyRequest(
            id=str(uuid.uuid4()),
            content=content,
            from_level=from_level,
            to_level=to_level,
            requester=requester,
            justification=justification,
        )
        self._requests[request.id] = request
        return request

    def approve(self, request_id: str, approver: User) -> bool:
        """
        Approve a declassification request.

        The approver must have clearance >= the original level.

        Args:
            request_id: ID of the request to approve
            approver: User approving the request

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

        # Record the declassified content with new label
        self._declassified[request_id] = Label(
            level=request.to_level,
            source=f"declassified:{request_id}",
            topics=["declassified"],
        )

        return True

    def deny(self, request_id: str, approver: User) -> bool:
        """
        Deny a declassification request.

        Args:
            request_id: ID of the request to deny
            approver: User denying the request

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
        return True

    def get_request(self, request_id: str) -> Optional[DeclassifyRequest]:
        """Get a request by ID."""
        return self._requests.get(request_id)

    def get_pending_requests(self) -> list[DeclassifyRequest]:
        """Get all pending requests."""
        return [
            r for r in self._requests.values()
            if r.status == RequestStatus.PENDING
        ]

    def is_declassified(self, request_id: str) -> bool:
        """Check if content has been declassified."""
        return request_id in self._declassified

    def get_declassified_label(self, request_id: str) -> Optional[Label]:
        """Get the new label for declassified content."""
        return self._declassified.get(request_id)
