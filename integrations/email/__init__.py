"""Email integration for Clearance."""

from integrations.email.gateway import (
    EmailGateway,
    EmailMessage,
    EmailCheckResult,
    MockEmailBackend,
    SMTPEmailBackend,
)

__all__ = [
    "EmailGateway",
    "EmailMessage",
    "EmailCheckResult",
    "MockEmailBackend",
    "SMTPEmailBackend",
]
