"""Tests for clearance.models"""

import pytest
from clearance.models import (
    SecurityLevel,
    Label,
    Message,
    User,
    CheckResult,
)


class TestSecurityLevel:
    """Tests for SecurityLevel enum."""

    def test_ordering(self):
        """Security levels should be ordered."""
        assert SecurityLevel.PUBLIC < SecurityLevel.STAFF
        assert SecurityLevel.STAFF < SecurityLevel.MANAGER
        assert SecurityLevel.MANAGER < SecurityLevel.EXECUTIVE

    def test_can_read(self):
        """Test can_read method."""
        exec_level = SecurityLevel.EXECUTIVE
        manager_level = SecurityLevel.MANAGER
        staff_level = SecurityLevel.STAFF

        # Executive can read all levels
        assert exec_level.can_read(SecurityLevel.EXECUTIVE)
        assert exec_level.can_read(SecurityLevel.MANAGER)
        assert exec_level.can_read(SecurityLevel.STAFF)
        assert exec_level.can_read(SecurityLevel.PUBLIC)

        # Staff can only read staff and below
        assert staff_level.can_read(SecurityLevel.STAFF)
        assert staff_level.can_read(SecurityLevel.PUBLIC)
        assert not staff_level.can_read(SecurityLevel.MANAGER)
        assert not staff_level.can_read(SecurityLevel.EXECUTIVE)

    def test_can_write_to(self):
        """Test can_write_to method (No Write Down)."""
        exec_level = SecurityLevel.EXECUTIVE
        staff_level = SecurityLevel.STAFF

        # Executive info can only be written to Executive
        assert exec_level.can_write_to(SecurityLevel.EXECUTIVE)
        assert not exec_level.can_write_to(SecurityLevel.MANAGER)
        assert not exec_level.can_write_to(SecurityLevel.STAFF)

        # Staff info can be written to Staff and above
        assert staff_level.can_write_to(SecurityLevel.STAFF)
        assert staff_level.can_write_to(SecurityLevel.MANAGER)
        assert staff_level.can_write_to(SecurityLevel.EXECUTIVE)

    def test_str(self):
        """Test string representation."""
        assert str(SecurityLevel.EXECUTIVE) == "EXECUTIVE"
        assert str(SecurityLevel.PUBLIC) == "PUBLIC"


class TestLabel:
    """Tests for Label dataclass."""

    def test_creation(self):
        """Test basic label creation."""
        label = Label(
            level=SecurityLevel.EXECUTIVE,
            source="ceo_meeting",
            topics=["revenue", "acquisition"]
        )
        assert label.level == SecurityLevel.EXECUTIVE
        assert label.source == "ceo_meeting"
        assert "revenue" in label.topics

    def test_int_level_conversion(self):
        """Test that int levels are converted to SecurityLevel."""
        label = Label(level=3, source="test")
        assert label.level == SecurityLevel.EXECUTIVE
        assert isinstance(label.level, SecurityLevel)

    def test_default_values(self):
        """Test default values."""
        label = Label(level=SecurityLevel.STAFF)
        assert label.source == ""
        assert label.topics == []


class TestMessage:
    """Tests for Message dataclass."""

    def test_creation(self):
        """Test message creation."""
        msg = Message(
            content="Hello world",
            sender="agent1",
            recipient="user1"
        )
        assert msg.content == "Hello world"
        assert msg.sender == "agent1"
        assert msg.recipient == "user1"
        assert msg.labels == []

    def test_get_max_level_empty(self):
        """Test get_max_level with no labels."""
        msg = Message(content="test", sender="a", recipient="b")
        assert msg.get_max_level() == SecurityLevel.PUBLIC

    def test_get_max_level_with_labels(self):
        """Test get_max_level with multiple labels."""
        msg = Message(
            content="test",
            sender="a",
            recipient="b",
            labels=[
                Label(level=SecurityLevel.STAFF),
                Label(level=SecurityLevel.EXECUTIVE),
                Label(level=SecurityLevel.MANAGER),
            ]
        )
        assert msg.get_max_level() == SecurityLevel.EXECUTIVE


class TestUser:
    """Tests for User dataclass."""

    def test_creation(self):
        """Test user creation."""
        user = User(
            id="u1",
            name="Alice",
            clearance=SecurityLevel.MANAGER
        )
        assert user.id == "u1"
        assert user.name == "Alice"
        assert user.clearance == SecurityLevel.MANAGER

    def test_int_clearance_conversion(self):
        """Test that int clearances are converted to SecurityLevel."""
        user = User(id="u1", name="Test", clearance=2)
        assert user.clearance == SecurityLevel.MANAGER
        assert isinstance(user.clearance, SecurityLevel)


class TestCheckResult:
    """Tests for CheckResult dataclass."""

    def test_allowed_result(self):
        """Test allowed result."""
        result = CheckResult(allowed=True)
        assert result.allowed
        assert bool(result)
        assert "ALLOWED" in str(result)

    def test_denied_result(self):
        """Test denied result."""
        result = CheckResult(
            allowed=False,
            violation="NO_WRITE_DOWN",
            message_level=SecurityLevel.EXECUTIVE,
            recipient_clearance=SecurityLevel.STAFF,
        )
        assert not result.allowed
        assert not bool(result)
        assert result.violation == "NO_WRITE_DOWN"
        assert "DENIED" in str(result)

    def test_with_reason(self):
        """Test result with reason."""
        result = CheckResult(
            allowed=False,
            violation="NO_WRITE_DOWN",
            reason="Message too sensitive"
        )
        assert result.reason == "Message too sensitive"

    def test_with_violating_labels(self):
        """Test result with violating labels."""
        labels = [Label(level=SecurityLevel.EXECUTIVE)]
        result = CheckResult(
            allowed=False,
            violation="NO_WRITE_DOWN",
            violating_labels=labels
        )
        assert len(result.violating_labels) == 1
