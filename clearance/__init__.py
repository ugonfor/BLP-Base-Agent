"""
Clearance - Bell-LaPadula model-based information flow control for AI agents.

The answer to AI agent security was in 1973.
"""

from clearance.models import SecurityLevel, Label, Message, User, CheckResult
from clearance.label_store import LabelStore
from clearance.analyzer import MessageAnalyzer
from clearance.checker import ClearanceChecker

__version__ = "0.1.0"
__all__ = [
    "SecurityLevel",
    "Label",
    "Message",
    "User",
    "CheckResult",
    "LabelStore",
    "MessageAnalyzer",
    "ClearanceChecker",
]
