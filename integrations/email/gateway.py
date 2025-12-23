"""
Email Gateway with Clearance Integration.

Provides BLP-aware email sending that checks security levels before
allowing emails to be sent. Can be used as a drop-in replacement for
standard email sending in applications.

Features:
- Pre-send security checks
- Automatic recipient filtering
- Content sanitization options
- Audit trail integration
- Multiple backend support (SMTP, mock)

Requirements:
    Standard library only (smtplib, email)
"""

import logging
import smtplib
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Optional, Protocol

from clearance.models import CheckResult, SecurityLevel, User
from clearance.checker import ClearanceChecker


logger = logging.getLogger(__name__)


@dataclass
class EmailMessage:
    """
    An email message with security metadata.

    Attributes:
        subject: Email subject
        body: Email body (plain text or HTML)
        sender: Sender email address
        recipients: List of recipient email addresses
        cc: Optional CC recipients
        bcc: Optional BCC recipients
        html: Whether body is HTML
        security_level: Detected/assigned security level
        headers: Additional headers
    """
    subject: str
    body: str
    sender: str
    recipients: list[str]
    cc: list[str] = field(default_factory=list)
    bcc: list[str] = field(default_factory=list)
    html: bool = False
    security_level: Optional[SecurityLevel] = None
    headers: dict[str, str] = field(default_factory=dict)

    def all_recipients(self) -> list[str]:
        """Get all recipients including CC and BCC."""
        return self.recipients + self.cc + self.bcc


@dataclass
class EmailCheckResult:
    """
    Result of email security check.

    Attributes:
        allowed: Whether email can be sent
        allowed_recipients: Recipients who can receive
        blocked_recipients: Recipients who were blocked
        reason: Reason for blocking (if any)
        message_level: Detected security level
        modified_body: Sanitized body (if applicable)
    """
    allowed: bool
    allowed_recipients: list[str] = field(default_factory=list)
    blocked_recipients: list[str] = field(default_factory=list)
    reason: Optional[str] = None
    message_level: Optional[SecurityLevel] = None
    modified_body: Optional[str] = None


class EmailBackend(ABC):
    """Abstract base class for email backends."""

    @abstractmethod
    def send(self, message: EmailMessage) -> bool:
        """Send an email message."""
        ...

    @abstractmethod
    def is_available(self) -> bool:
        """Check if backend is available."""
        ...


class MockEmailBackend(EmailBackend):
    """Mock email backend for testing."""

    def __init__(self) -> None:
        self._sent: list[EmailMessage] = []
        self._available = True

    def send(self, message: EmailMessage) -> bool:
        self._sent.append(message)
        logger.info(f"Mock email sent to {message.recipients}")
        return True

    def is_available(self) -> bool:
        return self._available

    def set_available(self, available: bool) -> None:
        self._available = available

    def get_sent(self) -> list[EmailMessage]:
        """Get all sent messages."""
        return self._sent.copy()

    def clear(self) -> None:
        """Clear sent messages."""
        self._sent.clear()


class SMTPEmailBackend(EmailBackend):
    """SMTP email backend."""

    def __init__(
        self,
        host: str = "localhost",
        port: int = 587,
        username: Optional[str] = None,
        password: Optional[str] = None,
        use_tls: bool = True,
        timeout: int = 30,
    ) -> None:
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.use_tls = use_tls
        self.timeout = timeout

    def is_available(self) -> bool:
        try:
            with smtplib.SMTP(self.host, self.port, timeout=5) as server:
                server.noop()
            return True
        except Exception:
            return False

    def send(self, message: EmailMessage) -> bool:
        try:
            # Create message
            if message.html:
                msg = MIMEMultipart("alternative")
                msg.attach(MIMEText(message.body, "html"))
            else:
                msg = MIMEText(message.body)

            msg["Subject"] = message.subject
            msg["From"] = message.sender
            msg["To"] = ", ".join(message.recipients)

            if message.cc:
                msg["Cc"] = ", ".join(message.cc)

            for key, value in message.headers.items():
                msg[key] = value

            # Send
            with smtplib.SMTP(self.host, self.port, timeout=self.timeout) as server:
                if self.use_tls:
                    server.starttls()
                if self.username and self.password:
                    server.login(self.username, self.password)

                server.sendmail(
                    message.sender,
                    message.all_recipients(),
                    msg.as_string()
                )

            logger.info(f"Email sent to {message.recipients}")
            return True

        except Exception as e:
            logger.error(f"Failed to send email: {e}")
            return False


class UserLookupProtocol(Protocol):
    """Protocol for looking up users by email."""

    def get_by_email(self, email: str) -> Optional[User]:
        """Get user by email address."""
        ...


class SimpleUserLookup:
    """Simple in-memory user lookup by email."""

    def __init__(self) -> None:
        self._users: dict[str, User] = {}

    def add(self, email: str, user: User) -> None:
        """Add a user mapping."""
        self._users[email.lower()] = user

    def get_by_email(self, email: str) -> Optional[User]:
        """Get user by email."""
        return self._users.get(email.lower())

    def set_default_clearance(self, clearance: SecurityLevel) -> None:
        """Set default clearance for unknown users."""
        self._default_clearance = clearance


class EmailGateway:
    """
    Email gateway with BLP security enforcement.

    Checks all outgoing emails against security policies before sending.
    Can filter recipients, block emails entirely, or sanitize content.

    Example:
        checker = create_checker({"confidential": SecurityLevel.MANAGER})
        gateway = EmailGateway(checker, backend=SMTPEmailBackend(...))

        # Add user mappings
        gateway.user_lookup.add("ceo@company.com", ceo_user)
        gateway.user_lookup.add("intern@company.com", intern_user)

        # Send email - will be checked
        result = gateway.send(EmailMessage(
            subject="Q3 Results",
            body="Confidential: Revenue is...",
            sender="agent@company.com",
            recipients=["intern@company.com"]
        ))
        # result.allowed = False (confidential to intern)
    """

    def __init__(
        self,
        checker: ClearanceChecker,
        backend: Optional[EmailBackend] = None,
        user_lookup: Optional[UserLookupProtocol] = None,
        default_clearance: SecurityLevel = SecurityLevel.PUBLIC,
        block_on_any_violation: bool = False,
        add_security_header: bool = True,
    ) -> None:
        """
        Initialize the email gateway.

        Args:
            checker: ClearanceChecker for security checks
            backend: Email backend to use
            user_lookup: User lookup service for recipient clearances
            default_clearance: Default clearance for unknown recipients
            block_on_any_violation: Block email if any recipient blocked
            add_security_header: Add X-Security-Level header
        """
        self.checker = checker
        self.backend = backend or MockEmailBackend()
        self._user_lookup = user_lookup or SimpleUserLookup()
        self.default_clearance = default_clearance
        self.block_on_any_violation = block_on_any_violation
        self.add_security_header = add_security_header

    @property
    def user_lookup(self) -> UserLookupProtocol:
        """Get the user lookup service."""
        return self._user_lookup

    def check(self, message: EmailMessage) -> EmailCheckResult:
        """
        Check if an email can be sent.

        Args:
            message: The email to check

        Returns:
            EmailCheckResult with check outcome
        """
        # Analyze message to get security level
        content = f"{message.subject}\n{message.body}"
        message_level = self.checker.get_minimum_clearance(content)
        message.security_level = message_level

        allowed_recipients = []
        blocked_recipients = []
        block_reasons = []

        # Check each recipient
        for email in message.all_recipients():
            user = self._user_lookup.get_by_email(email)
            if not user:
                user = User(
                    id=email,
                    name=email,
                    clearance=self.default_clearance
                )

            result = self.checker.check_write(content, user)

            if result.allowed:
                allowed_recipients.append(email)
            else:
                blocked_recipients.append(email)
                block_reasons.append(
                    f"{email}: {result.violation} "
                    f"(has {user.clearance.name}, needs {message_level.name})"
                )

        # Determine overall result
        if blocked_recipients and self.block_on_any_violation:
            return EmailCheckResult(
                allowed=False,
                allowed_recipients=[],
                blocked_recipients=message.all_recipients(),
                reason=f"Blocked due to: {'; '.join(block_reasons)}",
                message_level=message_level,
            )

        if not allowed_recipients:
            return EmailCheckResult(
                allowed=False,
                allowed_recipients=[],
                blocked_recipients=blocked_recipients,
                reason="No recipients have sufficient clearance",
                message_level=message_level,
            )

        return EmailCheckResult(
            allowed=True,
            allowed_recipients=allowed_recipients,
            blocked_recipients=blocked_recipients,
            reason="; ".join(block_reasons) if blocked_recipients else None,
            message_level=message_level,
        )

    def send(
        self,
        message: EmailMessage,
        force: bool = False,
        send_to_allowed_only: bool = True,
    ) -> EmailCheckResult:
        """
        Check and send an email.

        Args:
            message: The email to send
            force: Skip security check (for pre-approved content)
            send_to_allowed_only: Send to allowed recipients even if some blocked

        Returns:
            EmailCheckResult with outcome
        """
        if force:
            # Skip check, just send
            if self.add_security_header and message.security_level:
                message.headers["X-Security-Level"] = message.security_level.name
            success = self.backend.send(message)
            return EmailCheckResult(
                allowed=success,
                allowed_recipients=message.all_recipients(),
                message_level=message.security_level,
            )

        # Check security
        result = self.check(message)

        if not result.allowed and not send_to_allowed_only:
            return result

        if not result.allowed_recipients:
            return result

        # Create modified message with only allowed recipients
        send_message = EmailMessage(
            subject=message.subject,
            body=result.modified_body or message.body,
            sender=message.sender,
            recipients=[r for r in message.recipients if r in result.allowed_recipients],
            cc=[r for r in message.cc if r in result.allowed_recipients],
            bcc=[r for r in message.bcc if r in result.allowed_recipients],
            html=message.html,
            security_level=result.message_level,
            headers=message.headers.copy(),
        )

        # Add security header
        if self.add_security_header and result.message_level:
            send_message.headers["X-Security-Level"] = result.message_level.name

        # Send
        success = self.backend.send(send_message)

        return EmailCheckResult(
            allowed=success,
            allowed_recipients=result.allowed_recipients,
            blocked_recipients=result.blocked_recipients,
            reason=result.reason,
            message_level=result.message_level,
        )

    def get_allowed_recipients(
        self,
        message: str,
        potential_recipients: list[str],
    ) -> list[str]:
        """
        Get list of recipients who can receive this message.

        Args:
            message: Message content to check
            potential_recipients: List of email addresses

        Returns:
            List of allowed email addresses
        """
        allowed = []
        for email in potential_recipients:
            user = self._user_lookup.get_by_email(email)
            if not user:
                user = User(id=email, name=email, clearance=self.default_clearance)

            result = self.checker.check_write(message, user)
            if result.allowed:
                allowed.append(email)

        return allowed
