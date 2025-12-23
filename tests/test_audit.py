"""Tests for clearance.audit"""

import pytest
import tempfile
from datetime import datetime, timedelta
from pathlib import Path

from clearance.audit import (
    AuditLogger,
    AuditEvent,
    AuditEventType,
    InMemoryAuditBackend,
    FileAuditBackend,
    create_audit_logger,
)
from clearance.models import CheckResult, SecurityLevel, User


class TestAuditEvent:
    """Tests for AuditEvent dataclass."""

    def test_to_dict(self):
        """Test conversion to dictionary."""
        event = AuditEvent(
            event_type=AuditEventType.MESSAGE_BLOCKED,
            actor_id="user1",
            actor_name="Test User",
            message_level=SecurityLevel.EXECUTIVE,
            allowed=False,
            violation_type="NO_WRITE_DOWN",
        )

        data = event.to_dict()

        assert data["event_type"] == "message_blocked"
        assert data["actor_id"] == "user1"
        assert data["message_level"] == "EXECUTIVE"
        assert data["allowed"] is False

    def test_from_dict(self):
        """Test creation from dictionary."""
        data = {
            "event_type": "message_allowed",
            "timestamp": "2024-01-01T12:00:00",
            "actor_id": "user1",
            "actor_clearance": "MANAGER",
            "allowed": True,
        }

        event = AuditEvent.from_dict(data)

        assert event.event_type == AuditEventType.MESSAGE_ALLOWED
        assert event.actor_id == "user1"
        assert event.actor_clearance == SecurityLevel.MANAGER

    def test_roundtrip(self):
        """Test to_dict/from_dict roundtrip."""
        original = AuditEvent(
            event_type=AuditEventType.DECLASS_APPROVED,
            actor_id="admin1",
            target_id="user1",
            message_level=SecurityLevel.EXECUTIVE,
            target_clearance=SecurityLevel.STAFF,
            request_id="req-123",
            details={"key": "value"},
        )

        data = original.to_dict()
        restored = AuditEvent.from_dict(data)

        assert restored.event_type == original.event_type
        assert restored.actor_id == original.actor_id
        assert restored.request_id == original.request_id
        assert restored.details == original.details


class TestInMemoryAuditBackend:
    """Tests for InMemoryAuditBackend."""

    def test_log_and_query(self):
        """Test basic logging and querying."""
        backend = InMemoryAuditBackend()

        event = AuditEvent(
            event_type=AuditEventType.MESSAGE_ALLOWED,
            actor_id="user1",
        )
        backend.log(event)

        results = backend.query()
        assert len(results) == 1
        assert results[0].actor_id == "user1"

    def test_query_by_event_type(self):
        """Test querying by event type."""
        backend = InMemoryAuditBackend()

        backend.log(AuditEvent(event_type=AuditEventType.MESSAGE_ALLOWED))
        backend.log(AuditEvent(event_type=AuditEventType.MESSAGE_BLOCKED))
        backend.log(AuditEvent(event_type=AuditEventType.MESSAGE_ALLOWED))

        results = backend.query(event_type=AuditEventType.MESSAGE_BLOCKED)
        assert len(results) == 1

    def test_query_by_actor(self):
        """Test querying by actor."""
        backend = InMemoryAuditBackend()

        backend.log(AuditEvent(event_type=AuditEventType.MESSAGE_ALLOWED, actor_id="user1"))
        backend.log(AuditEvent(event_type=AuditEventType.MESSAGE_ALLOWED, actor_id="user2"))

        results = backend.query(actor_id="user1")
        assert len(results) == 1

    def test_query_with_limit(self):
        """Test query limit."""
        backend = InMemoryAuditBackend()

        for i in range(10):
            backend.log(AuditEvent(event_type=AuditEventType.MESSAGE_ALLOWED))

        results = backend.query(limit=5)
        assert len(results) == 5

    def test_max_events(self):
        """Test max events limit."""
        backend = InMemoryAuditBackend(max_events=5)

        for i in range(10):
            backend.log(AuditEvent(
                event_type=AuditEventType.MESSAGE_ALLOWED,
                actor_id=str(i)
            ))

        all_events = backend.get_all()
        assert len(all_events) == 5
        # Should have kept the last 5
        assert all_events[0].actor_id == "5"

    def test_clear(self):
        """Test clearing events."""
        backend = InMemoryAuditBackend()
        backend.log(AuditEvent(event_type=AuditEventType.MESSAGE_ALLOWED))

        backend.clear()

        assert len(backend.get_all()) == 0


class TestFileAuditBackend:
    """Tests for FileAuditBackend."""

    def test_log_and_query(self):
        """Test file-based logging and querying."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "audit.jsonl"
            backend = FileAuditBackend(path)

            event = AuditEvent(
                event_type=AuditEventType.MESSAGE_BLOCKED,
                actor_id="user1",
                violation_type="NO_WRITE_DOWN",
            )
            backend.log(event)

            results = backend.query()
            assert len(results) == 1
            assert results[0].violation_type == "NO_WRITE_DOWN"

    def test_persistence(self):
        """Test that events persist."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "audit.jsonl"

            # Write with first instance
            backend1 = FileAuditBackend(path)
            backend1.log(AuditEvent(event_type=AuditEventType.MESSAGE_ALLOWED))

            # Read with second instance
            backend2 = FileAuditBackend(path)
            results = backend2.query()
            assert len(results) == 1


class TestAuditLogger:
    """Tests for AuditLogger."""

    @pytest.fixture
    def logger(self):
        """Create an audit logger."""
        return AuditLogger()

    @pytest.fixture
    def users(self):
        """Create test users."""
        return {
            "sender": User("s1", "Sender", SecurityLevel.MANAGER),
            "recipient": User("r1", "Recipient", SecurityLevel.STAFF),
            "admin": User("a1", "Admin", SecurityLevel.EXECUTIVE),
        }

    def test_log_message_check_allowed(self, logger, users):
        """Test logging allowed message."""
        result = CheckResult(
            allowed=True,
            message_level=SecurityLevel.STAFF,
            recipient_clearance=SecurityLevel.STAFF,
        )

        logger.log_message_check(
            sender=users["sender"],
            recipient=users["recipient"],
            check_result=result,
            message_preview="Hello world",
        )

        events = logger.query(event_type=AuditEventType.MESSAGE_ALLOWED)
        assert len(events) == 1
        assert events[0].allowed is True

    def test_log_message_check_blocked(self, logger, users):
        """Test logging blocked message."""
        result = CheckResult(
            allowed=False,
            violation="NO_WRITE_DOWN",
            message_level=SecurityLevel.EXECUTIVE,
            recipient_clearance=SecurityLevel.STAFF,
            reason="Message too sensitive",
        )

        logger.log_message_check(
            sender=users["sender"],
            recipient=users["recipient"],
            check_result=result,
        )

        events = logger.query(event_type=AuditEventType.MESSAGE_BLOCKED)
        assert len(events) == 1
        assert events[0].violation_type == "NO_WRITE_DOWN"

    def test_log_declassification_request(self, logger, users):
        """Test logging declassification request."""
        logger.log_declassification_request(
            requester=users["sender"],
            from_level=SecurityLevel.EXECUTIVE,
            to_level=SecurityLevel.STAFF,
            request_id="req-123",
            justification="Need to share summary",
        )

        events = logger.query(event_type=AuditEventType.DECLASS_REQUESTED)
        assert len(events) == 1
        assert events[0].request_id == "req-123"

    def test_log_clearance_change(self, logger, users):
        """Test logging clearance change."""
        logger.log_clearance_change(
            admin=users["admin"],
            target=users["recipient"],
            old_clearance=SecurityLevel.STAFF,
            new_clearance=SecurityLevel.MANAGER,
            reason="Promotion",
        )

        events = logger.query(event_type=AuditEventType.USER_CLEARANCE_CHANGED)
        assert len(events) == 1
        assert events[0].details["old_clearance"] == "STAFF"
        assert events[0].details["new_clearance"] == "MANAGER"

    def test_get_violations(self, logger, users):
        """Test getting violations."""
        # Log some events
        logger.log_message_check(
            sender=users["sender"],
            recipient=users["recipient"],
            check_result=CheckResult(allowed=True),
        )
        logger.log_message_check(
            sender=users["sender"],
            recipient=users["recipient"],
            check_result=CheckResult(allowed=False, violation="NO_WRITE_DOWN"),
        )
        logger.log_security_violation(
            actor=users["sender"],
            violation_type="UNAUTHORIZED_ACCESS",
        )

        violations = logger.get_violations()
        assert len(violations) == 2

    def test_get_user_activity(self, logger, users):
        """Test getting user activity."""
        for _ in range(3):
            logger.log_message_check(
                sender=users["sender"],
                recipient=users["recipient"],
                check_result=CheckResult(allowed=True),
            )

        activity = logger.get_user_activity(users["sender"].id)
        assert len(activity) == 3

    def test_get_stats(self, logger, users):
        """Test getting statistics."""
        logger.log_message_check(
            sender=users["sender"],
            recipient=users["recipient"],
            check_result=CheckResult(allowed=True),
        )
        logger.log_message_check(
            sender=users["sender"],
            recipient=users["recipient"],
            check_result=CheckResult(allowed=False, violation="X"),
        )

        stats = logger.get_stats()
        assert stats["messages_allowed"] == 1
        assert stats["messages_blocked"] == 1
        assert stats["violations"] == 1


class TestCreateAuditLogger:
    """Tests for create_audit_logger factory."""

    def test_create_memory_backend(self):
        """Test creating with memory backend."""
        logger = create_audit_logger(backend_type="memory")
        assert isinstance(logger._backend, InMemoryAuditBackend)

    def test_create_file_backend(self):
        """Test creating with file backend."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "audit.jsonl"
            logger = create_audit_logger(
                backend_type="file",
                log_path=str(path)
            )
            assert isinstance(logger._backend, FileAuditBackend)

    def test_create_file_backend_requires_path(self):
        """Test that file backend requires path."""
        with pytest.raises(ValueError, match="log_path required"):
            create_audit_logger(backend_type="file")
