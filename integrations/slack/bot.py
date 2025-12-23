"""
Slack Integration for Clearance.

Provides a Slack bot that intercepts messages and applies BLP security checks
before allowing them to be sent. Supports both synchronous blocking and
async notification modes.

Requirements:
    pip install slack-sdk

Usage:
    from clearance import ClearanceChecker
    from clearance.checker import create_checker
    from integrations.slack import ClearanceSlackBot

    checker = create_checker({"revenue": SecurityLevel.EXECUTIVE})
    bot = ClearanceSlackBot(checker, slack_token="xoxb-...")
    bot.start()
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable, Optional, Protocol
from enum import Enum

try:
    from slack_sdk import WebClient
    from slack_sdk.errors import SlackApiError
    SLACK_AVAILABLE = True
except ImportError:
    SLACK_AVAILABLE = False
    WebClient = None
    SlackApiError = Exception

from clearance.models import CheckResult, SecurityLevel, User
from clearance.checker import ClearanceChecker


logger = logging.getLogger(__name__)


class BlockMode(Enum):
    """How to handle blocked messages."""
    SILENT = "silent"           # Silently drop the message
    NOTIFY_SENDER = "notify"    # Notify sender only
    NOTIFY_ADMIN = "admin"      # Notify sender and admin
    REPLACE = "replace"         # Replace with sanitized version


@dataclass
class SlackUser:
    """Slack user with clearance mapping."""
    slack_id: str
    display_name: str
    clearance: SecurityLevel
    email: Optional[str] = None

    def to_user(self) -> User:
        """Convert to Clearance User model."""
        return User(
            id=self.slack_id,
            name=self.display_name,
            clearance=self.clearance
        )


@dataclass
class SlackMessageEvent:
    """Represents a Slack message event."""
    channel: str
    sender_id: str
    text: str
    timestamp: str
    thread_ts: Optional[str] = None
    is_dm: bool = False
    mentioned_users: list[str] = field(default_factory=list)


@dataclass
class InterceptResult:
    """Result of message interception."""
    allowed: bool
    original_message: str
    modified_message: Optional[str] = None
    check_result: Optional[CheckResult] = None
    action_taken: Optional[str] = None


class UserStoreProtocol(Protocol):
    """Protocol for user store implementations."""

    def get(self, slack_id: str) -> Optional[SlackUser]:
        """Get user by Slack ID."""
        ...

    def get_by_email(self, email: str) -> Optional[SlackUser]:
        """Get user by email."""
        ...

    def set_clearance(self, slack_id: str, clearance: SecurityLevel) -> bool:
        """Set user's clearance level."""
        ...


class InMemoryUserStore:
    """In-memory user store for development/testing."""

    def __init__(self) -> None:
        self._users: dict[str, SlackUser] = {}
        self._by_email: dict[str, str] = {}  # email -> slack_id

    def add(self, user: SlackUser) -> None:
        """Add a user to the store."""
        self._users[user.slack_id] = user
        if user.email:
            self._by_email[user.email.lower()] = user.slack_id

    def get(self, slack_id: str) -> Optional[SlackUser]:
        """Get user by Slack ID."""
        return self._users.get(slack_id)

    def get_by_email(self, email: str) -> Optional[SlackUser]:
        """Get user by email."""
        slack_id = self._by_email.get(email.lower())
        if slack_id:
            return self._users.get(slack_id)
        return None

    def set_clearance(self, slack_id: str, clearance: SecurityLevel) -> bool:
        """Set user's clearance level."""
        user = self._users.get(slack_id)
        if user:
            user.clearance = clearance
            return True
        return False

    def list_all(self) -> list[SlackUser]:
        """List all users."""
        return list(self._users.values())


class ClearanceSlackBot:
    """
    Slack bot with BLP security enforcement.

    Intercepts messages before they're sent and applies Clearance checks.
    Can block, modify, or notify based on configuration.

    Example:
        checker = create_checker({"revenue": SecurityLevel.EXECUTIVE})
        user_store = InMemoryUserStore()
        user_store.add(SlackUser("U123", "CEO", SecurityLevel.EXECUTIVE))
        user_store.add(SlackUser("U456", "Staff", SecurityLevel.STAFF))

        bot = ClearanceSlackBot(
            checker=checker,
            user_store=user_store,
            slack_token="xoxb-your-token",
            block_mode=BlockMode.NOTIFY_SENDER
        )
    """

    def __init__(
        self,
        checker: ClearanceChecker,
        user_store: UserStoreProtocol,
        slack_token: Optional[str] = None,
        block_mode: BlockMode = BlockMode.NOTIFY_SENDER,
        admin_channel: Optional[str] = None,
        default_clearance: SecurityLevel = SecurityLevel.PUBLIC,
        _skip_sdk_check: bool = False,
    ) -> None:
        """
        Initialize the Slack bot.

        Args:
            checker: ClearanceChecker instance for BLP checks
            user_store: Store for user-clearance mappings
            slack_token: Slack Bot OAuth token
            block_mode: How to handle blocked messages
            admin_channel: Channel ID for admin notifications
            default_clearance: Default clearance for unknown users
            _skip_sdk_check: Internal flag for testing without slack-sdk
        """
        if not SLACK_AVAILABLE and not _skip_sdk_check:
            raise ImportError(
                "slack-sdk is required for Slack integration. "
                "Install with: pip install slack-sdk"
            )

        self.checker = checker
        self.user_store = user_store
        self.block_mode = block_mode
        self.admin_channel = admin_channel
        self.default_clearance = default_clearance

        self._client: Optional[WebClient] = None
        if slack_token:
            self._client = WebClient(token=slack_token)

        self._message_handlers: list[Callable[[SlackMessageEvent, InterceptResult], None]] = []
        self._violation_handlers: list[Callable[[SlackMessageEvent, CheckResult], None]] = []

    def set_client(self, client: WebClient) -> None:
        """Set the Slack WebClient (for testing or custom setup)."""
        self._client = client

    def on_message(self, handler: Callable[[SlackMessageEvent, InterceptResult], None]) -> None:
        """Register a handler for processed messages."""
        self._message_handlers.append(handler)

    def on_violation(self, handler: Callable[[SlackMessageEvent, CheckResult], None]) -> None:
        """Register a handler for security violations."""
        self._violation_handlers.append(handler)

    def get_user_clearance(self, slack_id: str) -> SecurityLevel:
        """Get clearance level for a Slack user."""
        user = self.user_store.get(slack_id)
        if user:
            return user.clearance
        return self.default_clearance

    def get_recipient_from_channel(self, channel: str, mentioned_users: list[str]) -> Optional[User]:
        """
        Determine the recipient(s) from channel and mentions.

        For DMs, the recipient is the other user.
        For channels, we use the lowest clearance of mentioned users,
        or the channel's effective clearance.
        """
        if mentioned_users:
            # Get the lowest clearance among mentioned users
            min_clearance = SecurityLevel.EXECUTIVE
            min_user = None

            for user_id in mentioned_users:
                user = self.user_store.get(user_id)
                if user and user.clearance < min_clearance:
                    min_clearance = user.clearance
                    min_user = user

            if min_user:
                return min_user.to_user()

        # Default to public for channel messages without mentions
        return User(id=channel, name=f"Channel {channel}", clearance=SecurityLevel.PUBLIC)

    def intercept_message(self, event: SlackMessageEvent) -> InterceptResult:
        """
        Intercept and check a message before sending.

        Args:
            event: The Slack message event

        Returns:
            InterceptResult with check outcome and any modifications
        """
        sender = self.user_store.get(event.sender_id)
        if not sender:
            sender = SlackUser(
                slack_id=event.sender_id,
                display_name="Unknown User",
                clearance=self.default_clearance
            )

        # Determine recipient
        recipient = self.get_recipient_from_channel(event.channel, event.mentioned_users)
        if not recipient:
            return InterceptResult(allowed=True, original_message=event.text)

        # Perform BLP check
        result = self.checker.check_write(event.text, recipient)

        if result.allowed:
            intercept_result = InterceptResult(
                allowed=True,
                original_message=event.text,
                check_result=result
            )
        else:
            # Handle violation
            self._handle_violation(event, result)
            intercept_result = InterceptResult(
                allowed=False,
                original_message=event.text,
                check_result=result,
                action_taken=self.block_mode.value
            )

        # Call message handlers
        for handler in self._message_handlers:
            try:
                handler(event, intercept_result)
            except Exception as e:
                logger.error(f"Message handler error: {e}")

        return intercept_result

    def _handle_violation(self, event: SlackMessageEvent, result: CheckResult) -> None:
        """Handle a security violation based on block_mode."""
        # Call registered violation handlers
        for handler in self._violation_handlers:
            try:
                handler(event, result)
            except Exception as e:
                logger.error(f"Violation handler error: {e}")

        if not self._client:
            return

        try:
            if self.block_mode in (BlockMode.NOTIFY_SENDER, BlockMode.NOTIFY_ADMIN):
                self._notify_sender(event, result)

            if self.block_mode == BlockMode.NOTIFY_ADMIN and self.admin_channel:
                self._notify_admin(event, result)

        except SlackApiError as e:
            logger.error(f"Slack API error: {e}")

    def _notify_sender(self, event: SlackMessageEvent, result: CheckResult) -> None:
        """Send DM to sender about blocked message."""
        if not self._client:
            return

        blocks = [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": ":lock: *Message Blocked - Security Policy*"
                }
            },
            {
                "type": "section",
                "fields": [
                    {
                        "type": "mrkdwn",
                        "text": f"*Violation:*\n{result.violation}"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Message Level:*\n{result.message_level.name if result.message_level else 'N/A'}"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Recipient Clearance:*\n{result.recipient_clearance.name if result.recipient_clearance else 'N/A'}"
                    }
                ]
            },
            {
                "type": "context",
                "elements": [
                    {
                        "type": "mrkdwn",
                        "text": f"Your message contained information that cannot be shared with the recipient. "
                                f"Please rephrase or contact an administrator for declassification."
                    }
                ]
            }
        ]

        self._client.chat_postMessage(
            channel=event.sender_id,
            blocks=blocks,
            text="Message blocked due to security policy"
        )

    def _notify_admin(self, event: SlackMessageEvent, result: CheckResult) -> None:
        """Notify admin channel about violation."""
        if not self._client or not self.admin_channel:
            return

        self._client.chat_postMessage(
            channel=self.admin_channel,
            text=f":warning: Security violation by <@{event.sender_id}> in <#{event.channel}>: {result.violation}",
            blocks=[
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f":warning: *Security Violation Detected*\n"
                                f"*User:* <@{event.sender_id}>\n"
                                f"*Channel:* <#{event.channel}>\n"
                                f"*Violation:* {result.violation}\n"
                                f"*Time:* {datetime.now().isoformat()}"
                    }
                }
            ]
        )

    async def process_event(self, event_data: dict) -> Optional[InterceptResult]:
        """
        Process a raw Slack event.

        Args:
            event_data: Raw event data from Slack Events API

        Returns:
            InterceptResult if message was processed, None otherwise
        """
        event_type = event_data.get("type")
        if event_type != "message":
            return None

        # Skip bot messages and message changes
        if event_data.get("subtype") in ("bot_message", "message_changed", "message_deleted"):
            return None

        # Parse mentions
        text = event_data.get("text", "")
        mentioned_users = []
        import re
        for match in re.finditer(r'<@([A-Z0-9]+)>', text):
            mentioned_users.append(match.group(1))

        event = SlackMessageEvent(
            channel=event_data.get("channel", ""),
            sender_id=event_data.get("user", ""),
            text=text,
            timestamp=event_data.get("ts", ""),
            thread_ts=event_data.get("thread_ts"),
            is_dm=event_data.get("channel_type") == "im",
            mentioned_users=mentioned_users
        )

        result = self.intercept_message(event)

        # Call message handlers
        for handler in self._message_handlers:
            try:
                handler(event, result)
            except Exception as e:
                logger.error(f"Message handler error: {e}")

        return result


class MockSlackClient:
    """Mock Slack client for testing without actual Slack connection."""

    def __init__(self) -> None:
        self.messages: list[dict] = []

    def chat_postMessage(self, **kwargs) -> dict:
        """Record message for testing."""
        self.messages.append(kwargs)
        return {"ok": True, "ts": "1234567890.123456"}

    def get_sent_messages(self) -> list[dict]:
        """Get all sent messages."""
        return self.messages

    def clear(self) -> None:
        """Clear recorded messages."""
        self.messages.clear()
