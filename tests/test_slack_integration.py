"""Tests for integrations.slack.bot"""

import pytest

from integrations.slack.bot import (
    ClearanceSlackBot,
    SlackUser,
    SlackMessageEvent,
    InMemoryUserStore,
    BlockMode,
    MockSlackClient,
)
from clearance.models import SecurityLevel, User
from clearance.checker import create_checker


class TestSlackUser:
    """Tests for SlackUser."""

    def test_to_user(self):
        """Test conversion to Clearance User."""
        slack_user = SlackUser(
            slack_id="U123",
            display_name="Test User",
            clearance=SecurityLevel.MANAGER,
            email="test@example.com",
        )

        user = slack_user.to_user()

        assert user.id == "U123"
        assert user.name == "Test User"
        assert user.clearance == SecurityLevel.MANAGER


class TestInMemoryUserStore:
    """Tests for InMemoryUserStore."""

    def test_add_and_get(self):
        """Test adding and getting users."""
        store = InMemoryUserStore()

        user = SlackUser(
            slack_id="U123",
            display_name="Test",
            clearance=SecurityLevel.STAFF,
            email="test@example.com",
        )
        store.add(user)

        retrieved = store.get("U123")
        assert retrieved is not None
        assert retrieved.display_name == "Test"

    def test_get_by_email(self):
        """Test getting user by email."""
        store = InMemoryUserStore()

        user = SlackUser(
            slack_id="U123",
            display_name="Test",
            clearance=SecurityLevel.STAFF,
            email="test@example.com",
        )
        store.add(user)

        retrieved = store.get_by_email("test@example.com")
        assert retrieved is not None
        assert retrieved.slack_id == "U123"

        # Case insensitive
        retrieved = store.get_by_email("TEST@EXAMPLE.COM")
        assert retrieved is not None

    def test_set_clearance(self):
        """Test setting user clearance."""
        store = InMemoryUserStore()

        user = SlackUser(
            slack_id="U123",
            display_name="Test",
            clearance=SecurityLevel.STAFF,
        )
        store.add(user)

        result = store.set_clearance("U123", SecurityLevel.MANAGER)
        assert result is True

        retrieved = store.get("U123")
        assert retrieved.clearance == SecurityLevel.MANAGER

    def test_list_all(self):
        """Test listing all users."""
        store = InMemoryUserStore()

        store.add(SlackUser("U1", "User 1", SecurityLevel.STAFF))
        store.add(SlackUser("U2", "User 2", SecurityLevel.MANAGER))

        all_users = store.list_all()
        assert len(all_users) == 2


class TestClearanceSlackBot:
    """Tests for ClearanceSlackBot."""

    @pytest.fixture
    def checker(self):
        """Create a checker with test keywords."""
        return create_checker({
            "revenue": SecurityLevel.EXECUTIVE,
            "budget": SecurityLevel.MANAGER,
            "internal": SecurityLevel.STAFF,
        })

    @pytest.fixture
    def user_store(self):
        """Create a user store with test users."""
        store = InMemoryUserStore()
        store.add(SlackUser("U_CEO", "CEO", SecurityLevel.EXECUTIVE))
        store.add(SlackUser("U_MGR", "Manager", SecurityLevel.MANAGER))
        store.add(SlackUser("U_STAFF", "Staff", SecurityLevel.STAFF))
        store.add(SlackUser("U_PUB", "External", SecurityLevel.PUBLIC))
        return store

    @pytest.fixture
    def bot(self, checker, user_store):
        """Create a bot instance."""
        return ClearanceSlackBot(
            checker=checker,
            user_store=user_store,
            block_mode=BlockMode.SILENT,
            _skip_sdk_check=True,
        )

    def test_intercept_allowed_message(self, bot):
        """Test intercepting an allowed message."""
        event = SlackMessageEvent(
            channel="C123",
            sender_id="U_MGR",
            text="Hello everyone!",
            timestamp="123.456",
            mentioned_users=["U_CEO"],
        )

        result = bot.intercept_message(event)

        assert result.allowed is True

    def test_intercept_blocked_message(self, bot):
        """Test intercepting a blocked message."""
        event = SlackMessageEvent(
            channel="C123",
            sender_id="U_MGR",
            text="Q3 revenue exceeded expectations",
            timestamp="123.456",
            mentioned_users=["U_STAFF"],
        )

        result = bot.intercept_message(event)

        assert result.allowed is False
        assert result.check_result.violation == "NO_WRITE_DOWN"

    def test_get_user_clearance_known(self, bot):
        """Test getting clearance for known user."""
        clearance = bot.get_user_clearance("U_CEO")
        assert clearance == SecurityLevel.EXECUTIVE

    def test_get_user_clearance_unknown(self, bot):
        """Test getting clearance for unknown user."""
        clearance = bot.get_user_clearance("U_UNKNOWN")
        assert clearance == SecurityLevel.PUBLIC  # Default

    def test_violation_handler(self, bot):
        """Test violation handler callback."""
        violations = []

        def handler(event, result):
            violations.append((event, result))

        bot.on_violation(handler)

        event = SlackMessageEvent(
            channel="C123",
            sender_id="U_MGR",
            text="Check the revenue numbers",
            timestamp="123.456",
            mentioned_users=["U_STAFF"],
        )

        bot.intercept_message(event)

        assert len(violations) == 1
        assert violations[0][1].violation == "NO_WRITE_DOWN"

    def test_message_handler(self, bot):
        """Test message handler callback."""
        messages = []

        def handler(event, result):
            messages.append((event, result))

        bot.on_message(handler)

        event = SlackMessageEvent(
            channel="C123",
            sender_id="U_MGR",
            text="Hello!",
            timestamp="123.456",
        )

        bot.intercept_message(event)

        assert len(messages) == 1


class TestMockSlackClient:
    """Tests for MockSlackClient."""

    def test_send_message(self):
        """Test sending mock message."""
        client = MockSlackClient()

        result = client.chat_postMessage(
            channel="U123",
            text="Hello",
            blocks=[]
        )

        assert result["ok"] is True
        assert len(client.get_sent_messages()) == 1

    def test_clear(self):
        """Test clearing sent messages."""
        client = MockSlackClient()
        client.chat_postMessage(channel="U123", text="Hello")

        client.clear()

        assert len(client.get_sent_messages()) == 0
