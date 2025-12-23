"""Tests for integrations.email.gateway"""

import pytest

from integrations.email.gateway import (
    EmailGateway,
    EmailMessage,
    EmailCheckResult,
    MockEmailBackend,
    SimpleUserLookup,
)
from clearance.models import SecurityLevel, User
from clearance.checker import create_checker


class TestEmailMessage:
    """Tests for EmailMessage dataclass."""

    def test_all_recipients(self):
        """Test getting all recipients."""
        msg = EmailMessage(
            subject="Test",
            body="Test body",
            sender="sender@test.com",
            recipients=["r1@test.com", "r2@test.com"],
            cc=["cc@test.com"],
            bcc=["bcc@test.com"],
        )

        all_recipients = msg.all_recipients()

        assert len(all_recipients) == 4
        assert "r1@test.com" in all_recipients
        assert "cc@test.com" in all_recipients
        assert "bcc@test.com" in all_recipients


class TestMockEmailBackend:
    """Tests for MockEmailBackend."""

    def test_send(self):
        """Test sending email."""
        backend = MockEmailBackend()

        msg = EmailMessage(
            subject="Test",
            body="Body",
            sender="sender@test.com",
            recipients=["r@test.com"],
        )

        result = backend.send(msg)

        assert result is True
        assert len(backend.get_sent()) == 1

    def test_is_available(self):
        """Test availability check."""
        backend = MockEmailBackend()

        assert backend.is_available() is True

        backend.set_available(False)
        assert backend.is_available() is False

    def test_clear(self):
        """Test clearing sent messages."""
        backend = MockEmailBackend()
        backend.send(EmailMessage(
            subject="Test",
            body="Body",
            sender="s@test.com",
            recipients=["r@test.com"],
        ))

        backend.clear()

        assert len(backend.get_sent()) == 0


class TestSimpleUserLookup:
    """Tests for SimpleUserLookup."""

    def test_add_and_get(self):
        """Test adding and getting users."""
        lookup = SimpleUserLookup()

        user = User("u1", "Test User", SecurityLevel.MANAGER)
        lookup.add("test@example.com", user)

        retrieved = lookup.get_by_email("test@example.com")
        assert retrieved is not None
        assert retrieved.id == "u1"

    def test_case_insensitive(self):
        """Test case insensitive lookup."""
        lookup = SimpleUserLookup()

        user = User("u1", "Test", SecurityLevel.STAFF)
        lookup.add("Test@Example.COM", user)

        retrieved = lookup.get_by_email("test@example.com")
        assert retrieved is not None


class TestEmailGateway:
    """Tests for EmailGateway."""

    @pytest.fixture
    def checker(self):
        """Create a checker with test keywords."""
        return create_checker({
            "revenue": SecurityLevel.EXECUTIVE,
            "confidential": SecurityLevel.MANAGER,
            "internal": SecurityLevel.STAFF,
        })

    @pytest.fixture
    def user_lookup(self):
        """Create user lookup with test users."""
        lookup = SimpleUserLookup()
        lookup.add("ceo@company.com", User("ceo", "CEO", SecurityLevel.EXECUTIVE))
        lookup.add("manager@company.com", User("mgr", "Manager", SecurityLevel.MANAGER))
        lookup.add("staff@company.com", User("staff", "Staff", SecurityLevel.STAFF))
        lookup.add("external@other.com", User("ext", "External", SecurityLevel.PUBLIC))
        return lookup

    @pytest.fixture
    def gateway(self, checker, user_lookup):
        """Create email gateway."""
        return EmailGateway(
            checker=checker,
            backend=MockEmailBackend(),
            user_lookup=user_lookup,
            default_clearance=SecurityLevel.PUBLIC,
        )

    def test_check_allowed(self, gateway):
        """Test checking an allowed email."""
        msg = EmailMessage(
            subject="Hello",
            body="Just saying hi!",
            sender="agent@company.com",
            recipients=["external@other.com"],
        )

        result = gateway.check(msg)

        assert result.allowed is True
        assert "external@other.com" in result.allowed_recipients

    def test_check_blocked(self, gateway):
        """Test checking a blocked email."""
        msg = EmailMessage(
            subject="Q3 Revenue",
            body="The revenue is $10M",
            sender="agent@company.com",
            recipients=["staff@company.com"],
        )

        result = gateway.check(msg)

        assert result.allowed is False
        assert "staff@company.com" in result.blocked_recipients
        assert result.message_level == SecurityLevel.EXECUTIVE

    def test_check_partial_block(self, gateway):
        """Test email with some recipients blocked."""
        msg = EmailMessage(
            subject="Revenue Report",
            body="Revenue is up",
            sender="agent@company.com",
            recipients=["ceo@company.com", "staff@company.com"],
        )

        result = gateway.check(msg)

        assert result.allowed is True
        assert "ceo@company.com" in result.allowed_recipients
        assert "staff@company.com" in result.blocked_recipients

    def test_send_allowed(self, gateway):
        """Test sending an allowed email."""
        msg = EmailMessage(
            subject="Hello",
            body="Hi everyone!",
            sender="agent@company.com",
            recipients=["staff@company.com"],
        )

        result = gateway.send(msg)

        assert result.allowed is True
        # Check that email was actually sent
        backend = gateway.backend
        assert len(backend.get_sent()) == 1

    def test_send_blocked(self, gateway):
        """Test sending a blocked email."""
        msg = EmailMessage(
            subject="Confidential",
            body="This is confidential info",
            sender="agent@company.com",
            recipients=["external@other.com"],
        )

        result = gateway.send(msg)

        assert result.allowed is False
        # Check that email was NOT sent
        backend = gateway.backend
        assert len(backend.get_sent()) == 0

    def test_send_to_allowed_only(self, gateway):
        """Test sending to allowed recipients only."""
        msg = EmailMessage(
            subject="Revenue",
            body="Revenue is up",
            sender="agent@company.com",
            recipients=["ceo@company.com", "external@other.com"],
        )

        result = gateway.send(msg, send_to_allowed_only=True)

        assert result.allowed is True
        assert "ceo@company.com" in result.allowed_recipients
        assert "external@other.com" in result.blocked_recipients

        # Check only allowed recipient got the email
        backend = gateway.backend
        sent = backend.get_sent()
        assert len(sent) == 1
        assert sent[0].recipients == ["ceo@company.com"]

    def test_send_force(self, gateway):
        """Test force sending without check."""
        msg = EmailMessage(
            subject="Revenue",
            body="Revenue is up",
            sender="agent@company.com",
            recipients=["external@other.com"],
            security_level=SecurityLevel.EXECUTIVE,
        )

        result = gateway.send(msg, force=True)

        assert result.allowed is True
        backend = gateway.backend
        assert len(backend.get_sent()) == 1

    def test_security_header_added(self, gateway):
        """Test that security header is added."""
        msg = EmailMessage(
            subject="Internal",
            body="Internal update",
            sender="agent@company.com",
            recipients=["staff@company.com"],
        )

        gateway.send(msg)

        backend = gateway.backend
        sent = backend.get_sent()
        assert "X-Security-Level" in sent[0].headers

    def test_get_allowed_recipients(self, gateway):
        """Test filtering allowed recipients."""
        message = "Revenue is excellent"

        allowed = gateway.get_allowed_recipients(
            message=message,
            potential_recipients=[
                "ceo@company.com",
                "manager@company.com",
                "staff@company.com",
            ]
        )

        assert "ceo@company.com" in allowed
        assert "manager@company.com" not in allowed
        assert "staff@company.com" not in allowed

    def test_block_on_any_violation(self, checker, user_lookup):
        """Test blocking entire email if any recipient blocked."""
        gateway = EmailGateway(
            checker=checker,
            backend=MockEmailBackend(),
            user_lookup=user_lookup,
            block_on_any_violation=True,
        )

        msg = EmailMessage(
            subject="Revenue",
            body="Revenue is up",
            sender="agent@company.com",
            recipients=["ceo@company.com", "external@other.com"],
        )

        result = gateway.check(msg)

        assert result.allowed is False
        # All recipients should be in blocked list
        assert "ceo@company.com" in result.blocked_recipients
        assert "external@other.com" in result.blocked_recipients

    def test_unknown_recipient_uses_default(self, gateway):
        """Test that unknown recipients use default clearance."""
        msg = EmailMessage(
            subject="Internal",
            body="Internal only",
            sender="agent@company.com",
            recipients=["unknown@random.com"],
        )

        result = gateway.check(msg)

        # Default is PUBLIC, internal is STAFF level
        assert result.allowed is False
        assert result.message_level == SecurityLevel.STAFF
