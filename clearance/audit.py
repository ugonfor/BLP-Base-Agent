"""
Audit Logging for Clearance.

Provides comprehensive audit trails for all security-relevant events:
- Message checks (allowed/blocked)
- Declassification requests and decisions
- User clearance changes
- Security violations

Supports multiple backends:
- In-memory (development/testing)
- File-based (simple production)
- JSON Lines (structured logging)
- Custom (via protocol)
"""

import json
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Optional, Protocol, Iterator
import threading

from clearance.models import CheckResult, SecurityLevel, User


logger = logging.getLogger(__name__)


class AuditEventType(Enum):
    """Types of audit events."""
    # Message events
    MESSAGE_ALLOWED = "message_allowed"
    MESSAGE_BLOCKED = "message_blocked"

    # Declassification events
    DECLASS_REQUESTED = "declassification_requested"
    DECLASS_APPROVED = "declassification_approved"
    DECLASS_DENIED = "declassification_denied"
    DECLASS_REVOKED = "declassification_revoked"
    DECLASS_EXPIRED = "declassification_expired"

    # User events
    USER_CLEARANCE_CHANGED = "user_clearance_changed"
    USER_CREATED = "user_created"

    # System events
    SECURITY_VIOLATION = "security_violation"
    POLICY_CHANGED = "policy_changed"
    SYSTEM_START = "system_start"
    SYSTEM_STOP = "system_stop"


@dataclass
class AuditEvent:
    """
    A single audit event.

    Attributes:
        event_type: Type of event
        timestamp: When the event occurred
        actor_id: ID of the user/agent that triggered the event
        actor_name: Name of the actor
        target_id: Optional ID of the target (e.g., recipient)
        target_name: Optional name of the target
        message_level: Security level of message (if applicable)
        actor_clearance: Clearance of actor (if applicable)
        target_clearance: Clearance of target (if applicable)
        allowed: Whether the action was allowed
        violation_type: Type of violation (if any)
        details: Additional event-specific details
        request_id: Related request ID (e.g., declassification)
        session_id: Session identifier for grouping events
    """
    event_type: AuditEventType
    timestamp: datetime = field(default_factory=datetime.now)
    actor_id: Optional[str] = None
    actor_name: Optional[str] = None
    target_id: Optional[str] = None
    target_name: Optional[str] = None
    message_level: Optional[SecurityLevel] = None
    actor_clearance: Optional[SecurityLevel] = None
    target_clearance: Optional[SecurityLevel] = None
    allowed: Optional[bool] = None
    violation_type: Optional[str] = None
    details: dict = field(default_factory=dict)
    request_id: Optional[str] = None
    session_id: Optional[str] = None

    def to_dict(self) -> dict:
        """Convert event to dictionary for serialization."""
        result = {
            "event_type": self.event_type.value,
            "timestamp": self.timestamp.isoformat(),
        }

        # Add optional fields if set
        if self.actor_id:
            result["actor_id"] = self.actor_id
        if self.actor_name:
            result["actor_name"] = self.actor_name
        if self.target_id:
            result["target_id"] = self.target_id
        if self.target_name:
            result["target_name"] = self.target_name
        if self.message_level is not None:
            result["message_level"] = self.message_level.name
        if self.actor_clearance is not None:
            result["actor_clearance"] = self.actor_clearance.name
        if self.target_clearance is not None:
            result["target_clearance"] = self.target_clearance.name
        if self.allowed is not None:
            result["allowed"] = self.allowed
        if self.violation_type:
            result["violation_type"] = self.violation_type
        if self.details:
            result["details"] = self.details
        if self.request_id:
            result["request_id"] = self.request_id
        if self.session_id:
            result["session_id"] = self.session_id

        return result

    @classmethod
    def from_dict(cls, data: dict) -> "AuditEvent":
        """Create event from dictionary."""
        event_type = AuditEventType(data["event_type"])
        timestamp = datetime.fromisoformat(data["timestamp"])

        message_level = None
        if "message_level" in data:
            message_level = SecurityLevel[data["message_level"]]

        actor_clearance = None
        if "actor_clearance" in data:
            actor_clearance = SecurityLevel[data["actor_clearance"]]

        target_clearance = None
        if "target_clearance" in data:
            target_clearance = SecurityLevel[data["target_clearance"]]

        return cls(
            event_type=event_type,
            timestamp=timestamp,
            actor_id=data.get("actor_id"),
            actor_name=data.get("actor_name"),
            target_id=data.get("target_id"),
            target_name=data.get("target_name"),
            message_level=message_level,
            actor_clearance=actor_clearance,
            target_clearance=target_clearance,
            allowed=data.get("allowed"),
            violation_type=data.get("violation_type"),
            details=data.get("details", {}),
            request_id=data.get("request_id"),
            session_id=data.get("session_id"),
        )


class AuditBackend(ABC):
    """Abstract base class for audit backends."""

    @abstractmethod
    def log(self, event: AuditEvent) -> None:
        """Log an audit event."""
        ...

    @abstractmethod
    def query(
        self,
        event_type: Optional[AuditEventType] = None,
        actor_id: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: int = 100,
    ) -> list[AuditEvent]:
        """Query audit events."""
        ...


class InMemoryAuditBackend(AuditBackend):
    """In-memory audit backend for development/testing."""

    def __init__(self, max_events: int = 10000) -> None:
        self._events: list[AuditEvent] = []
        self._max_events = max_events
        self._lock = threading.Lock()

    def log(self, event: AuditEvent) -> None:
        with self._lock:
            self._events.append(event)
            # Trim old events if over limit
            if len(self._events) > self._max_events:
                self._events = self._events[-self._max_events:]

    def query(
        self,
        event_type: Optional[AuditEventType] = None,
        actor_id: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: int = 100,
    ) -> list[AuditEvent]:
        with self._lock:
            results = self._events.copy()

        # Apply filters
        if event_type:
            results = [e for e in results if e.event_type == event_type]
        if actor_id:
            results = [e for e in results if e.actor_id == actor_id]
        if start_time:
            results = [e for e in results if e.timestamp >= start_time]
        if end_time:
            results = [e for e in results if e.timestamp <= end_time]

        # Return most recent first, limited
        return list(reversed(results))[:limit]

    def get_all(self) -> list[AuditEvent]:
        """Get all events."""
        with self._lock:
            return self._events.copy()

    def clear(self) -> None:
        """Clear all events."""
        with self._lock:
            self._events.clear()


class FileAuditBackend(AuditBackend):
    """
    File-based audit backend using JSON Lines format.

    Each line is a JSON object representing one event.
    """

    def __init__(self, log_path: str | Path) -> None:
        self._path = Path(log_path)
        self._lock = threading.Lock()

        # Ensure directory exists
        self._path.parent.mkdir(parents=True, exist_ok=True)

    def log(self, event: AuditEvent) -> None:
        with self._lock:
            with open(self._path, "a") as f:
                f.write(json.dumps(event.to_dict()) + "\n")

    def query(
        self,
        event_type: Optional[AuditEventType] = None,
        actor_id: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: int = 100,
    ) -> list[AuditEvent]:
        results = []

        if not self._path.exists():
            return results

        with open(self._path, "r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue

                try:
                    data = json.loads(line)
                    event = AuditEvent.from_dict(data)

                    # Apply filters
                    if event_type and event.event_type != event_type:
                        continue
                    if actor_id and event.actor_id != actor_id:
                        continue
                    if start_time and event.timestamp < start_time:
                        continue
                    if end_time and event.timestamp > end_time:
                        continue

                    results.append(event)

                except (json.JSONDecodeError, KeyError, ValueError) as e:
                    logger.warning(f"Failed to parse audit line: {e}")

        # Return most recent first, limited
        return list(reversed(results))[:limit]

    def rotate(self, suffix: Optional[str] = None) -> Path:
        """
        Rotate the log file.

        Args:
            suffix: Optional suffix for rotated file (default: timestamp)

        Returns:
            Path to the rotated file
        """
        if not self._path.exists():
            return self._path

        suffix = suffix or datetime.now().strftime("%Y%m%d_%H%M%S")
        rotated_path = self._path.with_suffix(f".{suffix}.jsonl")

        with self._lock:
            self._path.rename(rotated_path)

        return rotated_path


class AuditLogger:
    """
    Main audit logging interface.

    Provides convenient methods for logging various security events
    and querying the audit trail.

    Example:
        audit = AuditLogger()

        # Log a blocked message
        audit.log_message_check(
            sender=agent_user,
            recipient=staff_user,
            check_result=result,
            message_preview="Q3 revenue..."
        )

        # Query violations
        violations = audit.get_violations(last_hours=24)
    """

    def __init__(
        self,
        backend: Optional[AuditBackend] = None,
        session_id: Optional[str] = None,
    ) -> None:
        """
        Initialize the audit logger.

        Args:
            backend: Audit backend to use (default: InMemoryAuditBackend)
            session_id: Optional session ID for grouping events
        """
        self._backend = backend or InMemoryAuditBackend()
        self._session_id = session_id

    def log(self, event: AuditEvent) -> None:
        """Log a raw audit event."""
        if self._session_id and not event.session_id:
            event.session_id = self._session_id
        self._backend.log(event)

    def log_message_check(
        self,
        sender: User,
        recipient: User,
        check_result: CheckResult,
        message_preview: Optional[str] = None,
    ) -> None:
        """
        Log a message security check.

        Args:
            sender: User sending the message
            recipient: Intended recipient
            check_result: Result of the BLP check
            message_preview: Optional preview of the message
        """
        event_type = (
            AuditEventType.MESSAGE_ALLOWED
            if check_result.allowed
            else AuditEventType.MESSAGE_BLOCKED
        )

        details = {}
        if message_preview:
            # Truncate for privacy
            details["message_preview"] = message_preview[:100]
        if check_result.reason:
            details["reason"] = check_result.reason

        event = AuditEvent(
            event_type=event_type,
            actor_id=sender.id,
            actor_name=sender.name,
            actor_clearance=sender.clearance,
            target_id=recipient.id,
            target_name=recipient.name,
            target_clearance=recipient.clearance,
            message_level=check_result.message_level,
            allowed=check_result.allowed,
            violation_type=check_result.violation,
            details=details,
        )

        self.log(event)

    def log_declassification_request(
        self,
        requester: User,
        from_level: SecurityLevel,
        to_level: SecurityLevel,
        request_id: str,
        justification: str,
    ) -> None:
        """Log a declassification request."""
        event = AuditEvent(
            event_type=AuditEventType.DECLASS_REQUESTED,
            actor_id=requester.id,
            actor_name=requester.name,
            actor_clearance=requester.clearance,
            message_level=from_level,
            target_clearance=to_level,
            request_id=request_id,
            details={"justification": justification},
        )
        self.log(event)

    def log_declassification_decision(
        self,
        approver: User,
        request_id: str,
        approved: bool,
        reason: Optional[str] = None,
    ) -> None:
        """Log a declassification decision."""
        event_type = (
            AuditEventType.DECLASS_APPROVED
            if approved
            else AuditEventType.DECLASS_DENIED
        )

        details = {}
        if reason:
            details["reason"] = reason

        event = AuditEvent(
            event_type=event_type,
            actor_id=approver.id,
            actor_name=approver.name,
            actor_clearance=approver.clearance,
            allowed=approved,
            request_id=request_id,
            details=details,
        )
        self.log(event)

    def log_clearance_change(
        self,
        admin: User,
        target: User,
        old_clearance: SecurityLevel,
        new_clearance: SecurityLevel,
        reason: Optional[str] = None,
    ) -> None:
        """Log a user clearance change."""
        details = {
            "old_clearance": old_clearance.name,
            "new_clearance": new_clearance.name,
        }
        if reason:
            details["reason"] = reason

        event = AuditEvent(
            event_type=AuditEventType.USER_CLEARANCE_CHANGED,
            actor_id=admin.id,
            actor_name=admin.name,
            actor_clearance=admin.clearance,
            target_id=target.id,
            target_name=target.name,
            target_clearance=new_clearance,
            details=details,
        )
        self.log(event)

    def log_security_violation(
        self,
        actor: User,
        violation_type: str,
        details: Optional[dict] = None,
    ) -> None:
        """Log a security violation."""
        event = AuditEvent(
            event_type=AuditEventType.SECURITY_VIOLATION,
            actor_id=actor.id,
            actor_name=actor.name,
            actor_clearance=actor.clearance,
            violation_type=violation_type,
            allowed=False,
            details=details or {},
        )
        self.log(event)

    def query(
        self,
        event_type: Optional[AuditEventType] = None,
        actor_id: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: int = 100,
    ) -> list[AuditEvent]:
        """Query audit events."""
        return self._backend.query(
            event_type=event_type,
            actor_id=actor_id,
            start_time=start_time,
            end_time=end_time,
            limit=limit,
        )

    def get_violations(
        self,
        last_hours: Optional[int] = None,
        limit: int = 100,
    ) -> list[AuditEvent]:
        """Get security violations and blocked messages."""
        start_time = None
        if last_hours:
            from datetime import timedelta
            start_time = datetime.now() - timedelta(hours=last_hours)

        # Get both blocked messages and explicit violations
        blocked = self.query(
            event_type=AuditEventType.MESSAGE_BLOCKED,
            start_time=start_time,
            limit=limit,
        )
        violations = self.query(
            event_type=AuditEventType.SECURITY_VIOLATION,
            start_time=start_time,
            limit=limit,
        )

        # Combine and sort by timestamp
        all_events = blocked + violations
        all_events.sort(key=lambda e: e.timestamp, reverse=True)

        return all_events[:limit]

    def get_user_activity(self, user_id: str, limit: int = 100) -> list[AuditEvent]:
        """Get all activity for a user."""
        return self.query(actor_id=user_id, limit=limit)

    def get_stats(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
    ) -> dict:
        """Get audit statistics."""
        events = self.query(
            start_time=start_time,
            end_time=end_time,
            limit=10000,
        )

        stats = {
            "total_events": len(events),
            "by_type": {},
            "violations": 0,
            "messages_allowed": 0,
            "messages_blocked": 0,
        }

        for event in events:
            event_type = event.event_type.value
            stats["by_type"][event_type] = stats["by_type"].get(event_type, 0) + 1

            if event.event_type == AuditEventType.MESSAGE_ALLOWED:
                stats["messages_allowed"] += 1
            elif event.event_type == AuditEventType.MESSAGE_BLOCKED:
                stats["messages_blocked"] += 1
                stats["violations"] += 1
            elif event.event_type == AuditEventType.SECURITY_VIOLATION:
                stats["violations"] += 1

        return stats


# Convenience function for creating audit logger
def create_audit_logger(
    backend_type: str = "memory",
    log_path: Optional[str] = None,
    session_id: Optional[str] = None,
) -> AuditLogger:
    """
    Create an audit logger with the specified backend.

    Args:
        backend_type: "memory" or "file"
        log_path: Path for file backend
        session_id: Optional session ID

    Returns:
        Configured AuditLogger
    """
    if backend_type == "file":
        if not log_path:
            raise ValueError("log_path required for file backend")
        backend = FileAuditBackend(log_path)
    else:
        backend = InMemoryAuditBackend()

    return AuditLogger(backend=backend, session_id=session_id)
