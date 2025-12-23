"""Tests for clearance.checker"""

import pytest
from clearance.checker import ClearanceChecker, create_checker
from clearance.analyzer import MessageAnalyzer
from clearance.label_store import LabelStore
from clearance.models import Label, SecurityLevel, User


class TestClearanceChecker:
    """Tests for ClearanceChecker class."""

    @pytest.fixture
    def store(self):
        """Create a label store with test keywords."""
        store = LabelStore()
        store.add_keyword("revenue", Label(level=SecurityLevel.EXECUTIVE))
        store.add_keyword("profit", Label(level=SecurityLevel.EXECUTIVE))
        store.add_keyword("budget", Label(level=SecurityLevel.MANAGER))
        store.add_keyword("salary", Label(level=SecurityLevel.MANAGER))
        store.add_keyword("internal", Label(level=SecurityLevel.STAFF))
        return store

    @pytest.fixture
    def checker(self, store):
        """Create a checker with the test store."""
        analyzer = MessageAnalyzer(store)
        return ClearanceChecker(store, analyzer)

    @pytest.fixture
    def users(self):
        """Create test users at different clearance levels."""
        return {
            "ceo": User("ceo", "CEO Kim", SecurityLevel.EXECUTIVE),
            "manager": User("mgr", "Manager Lee", SecurityLevel.MANAGER),
            "staff": User("staff", "Staff Park", SecurityLevel.STAFF),
            "public": User("pub", "Public User", SecurityLevel.PUBLIC),
        }

    # No Write Down Tests

    def test_executive_to_executive_allowed(self, checker, users):
        """Executive info can be sent to executive users."""
        result = checker.check_write(
            "Q3 revenue exceeded expectations",
            users["ceo"]
        )
        assert result.allowed
        assert result.message_level == SecurityLevel.EXECUTIVE

    def test_executive_to_manager_blocked(self, checker, users):
        """Executive info cannot be sent to manager users."""
        result = checker.check_write(
            "Q3 revenue exceeded expectations",
            users["manager"]
        )
        assert not result.allowed
        assert result.violation == "NO_WRITE_DOWN"
        assert result.message_level == SecurityLevel.EXECUTIVE
        assert result.recipient_clearance == SecurityLevel.MANAGER

    def test_executive_to_staff_blocked(self, checker, users):
        """Executive info cannot be sent to staff users."""
        result = checker.check_write(
            "The profit margin is excellent",
            users["staff"]
        )
        assert not result.allowed
        assert result.violation == "NO_WRITE_DOWN"

    def test_manager_to_manager_allowed(self, checker, users):
        """Manager info can be sent to manager users."""
        result = checker.check_write(
            "Review the budget proposal",
            users["manager"]
        )
        assert result.allowed

    def test_manager_to_executive_allowed(self, checker, users):
        """Manager info can be sent to executive users."""
        result = checker.check_write(
            "Salary adjustments are ready",
            users["ceo"]
        )
        assert result.allowed

    def test_manager_to_staff_blocked(self, checker, users):
        """Manager info cannot be sent to staff users."""
        result = checker.check_write(
            "Review the salary data",
            users["staff"]
        )
        assert not result.allowed
        assert result.violation == "NO_WRITE_DOWN"

    def test_staff_to_staff_allowed(self, checker, users):
        """Staff info can be sent to staff users."""
        result = checker.check_write(
            "This is internal only",
            users["staff"]
        )
        assert result.allowed

    def test_staff_to_public_blocked(self, checker, users):
        """Staff info cannot be sent to public users."""
        result = checker.check_write(
            "Internal memo attached",
            users["public"]
        )
        assert not result.allowed
        assert result.violation == "NO_WRITE_DOWN"

    def test_public_to_public_allowed(self, checker, users):
        """Public info can be sent to anyone."""
        result = checker.check_write(
            "Hello, how are you?",
            users["public"]
        )
        assert result.allowed
        assert result.message_level == SecurityLevel.PUBLIC

    def test_result_includes_reason(self, checker, users):
        """Check result includes human-readable reason."""
        result = checker.check_write(
            "Check the revenue numbers",
            users["staff"]
        )
        assert not result.allowed
        assert result.reason is not None
        assert "EXECUTIVE" in result.reason
        assert "STAFF" in result.reason

    def test_result_includes_violating_labels(self, checker, users):
        """Check result includes violating labels."""
        result = checker.check_write(
            "Revenue and profit look good",
            users["manager"]
        )
        assert not result.allowed
        assert len(result.violating_labels) > 0
        assert all(l.level > users["manager"].clearance
                   for l in result.violating_labels)

    # No Read Up Tests

    def test_check_read_same_level(self, checker, users):
        """User can read content at same level."""
        result = checker.check_read(
            SecurityLevel.MANAGER,
            users["manager"]
        )
        assert result.allowed

    def test_check_read_lower_level(self, checker, users):
        """User can read content below their level."""
        result = checker.check_read(
            SecurityLevel.STAFF,
            users["manager"]
        )
        assert result.allowed

    def test_check_read_higher_level_blocked(self, checker, users):
        """User cannot read content above their level."""
        result = checker.check_read(
            SecurityLevel.EXECUTIVE,
            users["manager"]
        )
        assert not result.allowed
        assert result.violation == "NO_READ_UP"

    # Helper Method Tests

    def test_get_allowed_recipients(self, checker, users):
        """Test filtering allowed recipients."""
        all_users = list(users.values())

        # Executive message - only executive can receive
        allowed = checker.get_allowed_recipients(
            "Q3 revenue is $10M",
            all_users
        )
        assert len(allowed) == 1
        assert allowed[0].id == "ceo"

        # Manager message - manager and above
        allowed = checker.get_allowed_recipients(
            "Review the budget",
            all_users
        )
        assert len(allowed) == 2
        assert all(u.clearance >= SecurityLevel.MANAGER for u in allowed)

        # Public message - everyone
        allowed = checker.get_allowed_recipients(
            "Hello everyone!",
            all_users
        )
        assert len(allowed) == 4

    def test_get_minimum_clearance(self, checker):
        """Test getting minimum required clearance."""
        level = checker.get_minimum_clearance("Check the revenue")
        assert level == SecurityLevel.EXECUTIVE

        level = checker.get_minimum_clearance("Budget review needed")
        assert level == SecurityLevel.MANAGER

        level = checker.get_minimum_clearance("Internal update")
        assert level == SecurityLevel.STAFF

        level = checker.get_minimum_clearance("Hello!")
        assert level == SecurityLevel.PUBLIC

    def test_with_context(self, checker, users):
        """Test check_write with additional context."""
        context = [Label(
            level=SecurityLevel.EXECUTIVE,
            topics=["project-x"]
        )]

        # Without context - allowed
        result = checker.check_write(
            "How is project-x going?",
            users["staff"]
        )
        assert result.allowed

        # With context - blocked
        result = checker.check_write(
            "How is project-x going?",
            users["staff"],
            context=context
        )
        assert not result.allowed


class TestCreateChecker:
    """Tests for create_checker factory function."""

    def test_create_empty_checker(self):
        """Test creating checker with no keywords."""
        checker = create_checker()
        user = User("u1", "Test", SecurityLevel.PUBLIC)

        result = checker.check_write("Hello world", user)
        assert result.allowed

    def test_create_with_keywords(self):
        """Test creating checker with keywords dict."""
        checker = create_checker({
            "secret": SecurityLevel.EXECUTIVE,
            "confidential": SecurityLevel.MANAGER,
        })

        staff = User("s1", "Staff", SecurityLevel.STAFF)
        exec = User("e1", "Exec", SecurityLevel.EXECUTIVE)

        # Secret blocked for staff
        result = checker.check_write("This is secret", staff)
        assert not result.allowed

        # Secret allowed for exec
        result = checker.check_write("This is secret", exec)
        assert result.allowed

    def test_create_checker_returns_functional_checker(self):
        """Test that created checker is fully functional."""
        checker = create_checker({
            "revenue": SecurityLevel.EXECUTIVE,
        })

        users = [
            User("e", "Exec", SecurityLevel.EXECUTIVE),
            User("m", "Mgr", SecurityLevel.MANAGER),
            User("s", "Staff", SecurityLevel.STAFF),
        ]

        # Test get_allowed_recipients
        allowed = checker.get_allowed_recipients("Revenue report", users)
        assert len(allowed) == 1
        assert allowed[0].id == "e"

        # Test get_minimum_clearance
        level = checker.get_minimum_clearance("Revenue is up")
        assert level == SecurityLevel.EXECUTIVE
