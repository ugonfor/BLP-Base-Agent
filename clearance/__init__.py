"""
Clearance - Bell-LaPadula model-based information flow control for AI agents.

The answer to AI agent security was in 1973.
"""

from clearance.models import SecurityLevel, Label, Message, User, CheckResult
from clearance.label_store import LabelStore
from clearance.analyzer import MessageAnalyzer, ContextAwareAnalyzer
from clearance.checker import ClearanceChecker, create_checker
from clearance.declassifier import Declassifier, DeclassifyRequest, RequestStatus
from clearance.audit import AuditLogger, AuditEvent, AuditEventType, create_audit_logger

__version__ = "0.2.0"
__all__ = [
    # Core models
    "SecurityLevel",
    "Label",
    "Message",
    "User",
    "CheckResult",
    # Storage
    "LabelStore",
    # Analyzers
    "MessageAnalyzer",
    "ContextAwareAnalyzer",
    # Checker
    "ClearanceChecker",
    "create_checker",
    # Declassifier
    "Declassifier",
    "DeclassifyRequest",
    "RequestStatus",
    # Audit
    "AuditLogger",
    "AuditEvent",
    "AuditEventType",
    "create_audit_logger",
]
