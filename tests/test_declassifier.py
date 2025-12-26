"""Tests for clearance.declassifier"""

import pytest
from datetime import timedelta
import time

from clearance.declassifier import (
    Declassifier,
    DeclassifyRequest,
    RequestStatus,
    SanitizationRule,
)
from clearance.models import SecurityLevel, User


class TestDeclassifyRequest:
    """Tests for DeclassifyRequest dataclass."""

    def test_is_expired_no_expiration(self):
        """Test is_expired with no expiration set."""
        request = DeclassifyRequest(
            id="test",
            content="test",
            from_level=SecurityLevel.EXECUTIVE,
            to_level=SecurityLevel.STAFF,
            requester=User("u1", "Test", SecurityLevel.MANAGER),
            justification="test",
        )
        assert not request.is_expired()

    def test_is_valid_pending(self):
        """Test is_valid for pending request."""
        request = DeclassifyRequest(
            id="test",
            content="test",
            from_level=SecurityLevel.EXECUTIVE,
            to_level=SecurityLevel.STAFF,
            requester=User("u1", "Test", SecurityLevel.MANAGER),
            justification="test",
        )
        assert not request.is_valid()

    def test_is_valid_approved(self):
        """Test is_valid for approved request."""
        request = DeclassifyRequest(
            id="test",
            content="test",
            from_level=SecurityLevel.EXECUTIVE,
            to_level=SecurityLevel.STAFF,
            requester=User("u1", "Test", SecurityLevel.MANAGER),
            justification="test",
            status=RequestStatus.APPROVED,
        )
        assert request.is_valid()


class TestDeclassifier:
    """Tests for Declassifier class."""

    @pytest.fixture
    def declassifier(self):
        """Create a declassifier instance."""
        return Declassifier(require_justification=True)

    @pytest.fixture
    def users(self):
        """Create test users."""
        return {
            "ceo": User("ceo", "CEO Kim", SecurityLevel.EXECUTIVE),
            "manager": User("mgr", "Manager Lee", SecurityLevel.MANAGER),
            "staff": User("staff", "Staff Park", SecurityLevel.STAFF),
        }

    def test_request_creation(self, declassifier, users):
        """Test creating a declassification request."""
        request = declassifier.request(
            content="Sensitive info",
            from_level=SecurityLevel.EXECUTIVE,
            to_level=SecurityLevel.STAFF,
            requester=users["manager"],
            justification="Need to share with team",
        )

        assert request.id
        assert request.status == RequestStatus.PENDING
        assert request.from_level == SecurityLevel.EXECUTIVE
        assert request.to_level == SecurityLevel.STAFF

    def test_request_invalid_level(self, declassifier, users):
        """Test that upward declassification is rejected."""
        with pytest.raises(ValueError, match="lower than current"):
            declassifier.request(
                content="test",
                from_level=SecurityLevel.STAFF,
                to_level=SecurityLevel.EXECUTIVE,
                requester=users["manager"],
                justification="test",
            )

    def test_request_requires_justification(self, declassifier, users):
        """Test that justification is required when configured."""
        with pytest.raises(ValueError, match="required"):
            declassifier.request(
                content="test",
                from_level=SecurityLevel.EXECUTIVE,
                to_level=SecurityLevel.STAFF,
                requester=users["manager"],
                justification="",
            )

    def test_approve_success(self, declassifier, users):
        """Test successful approval."""
        request = declassifier.request(
            content="test",
            from_level=SecurityLevel.EXECUTIVE,
            to_level=SecurityLevel.STAFF,
            requester=users["manager"],
            justification="test",
        )

        result = declassifier.approve(request.id, users["ceo"])

        assert result is True
        assert request.status == RequestStatus.APPROVED
        assert request.reviewed_by == users["ceo"]
        assert declassifier.is_declassified(request.id)

    def test_approve_insufficient_clearance(self, declassifier, users):
        """Test approval fails with insufficient clearance."""
        request = declassifier.request(
            content="test",
            from_level=SecurityLevel.EXECUTIVE,
            to_level=SecurityLevel.STAFF,
            requester=users["manager"],
            justification="test",
        )

        # Manager can't approve EXECUTIVE level
        result = declassifier.approve(request.id, users["manager"])

        assert result is False
        assert request.status == RequestStatus.PENDING

    def test_approve_with_expiration(self, declassifier, users):
        """Test approval with expiration."""
        request = declassifier.request(
            content="test",
            from_level=SecurityLevel.EXECUTIVE,
            to_level=SecurityLevel.STAFF,
            requester=users["manager"],
            justification="test",
        )

        declassifier.approve(
            request.id,
            users["ceo"],
            expires_in=timedelta(hours=1)
        )

        assert request.expires_at is not None
        assert declassifier.can_share(request.id)

    def test_deny_request(self, declassifier, users):
        """Test denying a request."""
        request = declassifier.request(
            content="test",
            from_level=SecurityLevel.EXECUTIVE,
            to_level=SecurityLevel.STAFF,
            requester=users["manager"],
            justification="test",
        )

        result = declassifier.deny(request.id, users["ceo"], reason="Not appropriate")

        assert result is True
        assert request.status == RequestStatus.DENIED
        assert request.denial_reason == "Not appropriate"

    def test_revoke_approved(self, declassifier, users):
        """Test revoking an approved request."""
        request = declassifier.request(
            content="test",
            from_level=SecurityLevel.EXECUTIVE,
            to_level=SecurityLevel.STAFF,
            requester=users["manager"],
            justification="test",
        )
        declassifier.approve(request.id, users["ceo"])

        assert declassifier.can_share(request.id)

        result = declassifier.revoke(request.id, users["ceo"])

        assert result is True
        assert request.status == RequestStatus.REVOKED
        assert not declassifier.can_share(request.id)

    def test_get_content(self, declassifier, users):
        """Test getting content after approval."""
        content = "Secret information"
        request = declassifier.request(
            content=content,
            from_level=SecurityLevel.EXECUTIVE,
            to_level=SecurityLevel.STAFF,
            requester=users["manager"],
            justification="test",
        )
        declassifier.approve(request.id, users["ceo"])

        retrieved = declassifier.get_content(request.id)
        assert retrieved == content

    def test_get_content_with_sanitized(self, declassifier, users):
        """Test getting sanitized content."""
        request = declassifier.request(
            content="Original secret",
            from_level=SecurityLevel.EXECUTIVE,
            to_level=SecurityLevel.STAFF,
            requester=users["manager"],
            justification="test",
        )
        declassifier.approve(
            request.id,
            users["ceo"],
            sanitized_content="Redacted version"
        )

        retrieved = declassifier.get_content(request.id, use_sanitized=True)
        assert retrieved == "Redacted version"

        retrieved = declassifier.get_content(request.id, use_sanitized=False)
        assert retrieved == "Original secret"

    def test_get_pending_requests(self, declassifier, users):
        """Test getting pending requests."""
        declassifier.request(
            content="test1",
            from_level=SecurityLevel.EXECUTIVE,
            to_level=SecurityLevel.STAFF,
            requester=users["manager"],
            justification="test",
        )
        declassifier.request(
            content="test2",
            from_level=SecurityLevel.MANAGER,
            to_level=SecurityLevel.STAFF,
            requester=users["staff"],
            justification="test",
        )

        pending = declassifier.get_pending_requests()
        assert len(pending) == 2

        # Filter by level
        pending = declassifier.get_pending_requests(for_level=SecurityLevel.MANAGER)
        assert len(pending) == 1

    def test_get_stats(self, declassifier, users):
        """Test getting statistics."""
        req1 = declassifier.request(
            content="test1",
            from_level=SecurityLevel.EXECUTIVE,
            to_level=SecurityLevel.STAFF,
            requester=users["manager"],
            justification="test",
        )
        req2 = declassifier.request(
            content="test2",
            from_level=SecurityLevel.MANAGER,
            to_level=SecurityLevel.STAFF,
            requester=users["staff"],
            justification="test",
        )

        declassifier.approve(req1.id, users["ceo"])
        declassifier.deny(req2.id, users["manager"])

        stats = declassifier.get_stats()
        assert stats["total"] == 2
        assert stats["approved"] == 1
        assert stats["denied"] == 1
        assert stats["pending"] == 0

    def test_on_pending_callback(self, declassifier, users):
        """Test pending notification callback."""
        received = []

        def callback(request):
            received.append(request)

        declassifier.on_pending(callback)

        declassifier.request(
            content="test",
            from_level=SecurityLevel.EXECUTIVE,
            to_level=SecurityLevel.STAFF,
            requester=users["manager"],
            justification="test",
        )

        assert len(received) == 1


class TestSanitization:
    """Tests for content sanitization."""

    def test_auto_sanitize(self):
        """Test automatic sanitization."""
        declassifier = Declassifier(require_justification=False)

        # Add sanitization rules
        declassifier.add_sanitization_rule(
            pattern=r"\$[\d,]+",
            replacement="[REDACTED]",
            level=SecurityLevel.EXECUTIVE
        )

        user = User("u1", "Test", SecurityLevel.MANAGER)
        request = declassifier.request(
            content="Revenue is $10,000,000",
            from_level=SecurityLevel.EXECUTIVE,
            to_level=SecurityLevel.STAFF,
            requester=user,
            auto_sanitize=True,
        )

        assert request.sanitized_content == "Revenue is [REDACTED]"
