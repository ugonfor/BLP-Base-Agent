"""Tests for clearance.label_store"""

import pytest
from clearance.label_store import LabelStore
from clearance.models import Label, SecurityLevel


class TestLabelStore:
    """Tests for LabelStore class."""

    def test_add_and_get_by_content(self):
        """Test adding and retrieving by content."""
        store = LabelStore()
        label = Label(
            level=SecurityLevel.EXECUTIVE,
            source="q3_report",
            topics=["revenue"]
        )

        content = "Q3 revenue is $10M"
        content_hash = store.add(content, label)

        assert content_hash  # Non-empty hash
        retrieved = store.get_by_content(content)
        assert retrieved is not None
        assert retrieved.level == SecurityLevel.EXECUTIVE
        assert retrieved.source == "q3_report"

    def test_get_by_hash(self):
        """Test retrieving by hash."""
        store = LabelStore()
        label = Label(level=SecurityLevel.MANAGER)
        content_hash = store.add("test content", label)

        retrieved = store.get_by_hash(content_hash)
        assert retrieved is not None
        assert retrieved.level == SecurityLevel.MANAGER

    def test_get_nonexistent(self):
        """Test getting non-existent content."""
        store = LabelStore()
        assert store.get_by_content("not stored") is None
        assert store.get_by_hash("fake_hash") is None

    def test_get_by_source(self):
        """Test retrieving labels by source."""
        store = LabelStore()

        store.add("content1", Label(
            level=SecurityLevel.EXECUTIVE,
            source="meeting_notes"
        ))
        store.add("content2", Label(
            level=SecurityLevel.MANAGER,
            source="meeting_notes"
        ))
        store.add("content3", Label(
            level=SecurityLevel.STAFF,
            source="other_source"
        ))

        meeting_labels = store.get_by_source("meeting_notes")
        assert len(meeting_labels) == 2

        other_labels = store.get_by_source("other_source")
        assert len(other_labels) == 1

        empty_labels = store.get_by_source("nonexistent")
        assert len(empty_labels) == 0

    def test_get_by_topic(self):
        """Test retrieving labels by topic."""
        store = LabelStore()

        store.add("revenue info", Label(
            level=SecurityLevel.EXECUTIVE,
            topics=["revenue", "financial"]
        ))
        store.add("budget info", Label(
            level=SecurityLevel.MANAGER,
            topics=["budget", "financial"]
        ))

        financial = store.get_by_topic("financial")
        assert len(financial) == 2

        revenue = store.get_by_topic("revenue")
        assert len(revenue) == 1

        # Case insensitive
        financial_upper = store.get_by_topic("FINANCIAL")
        assert len(financial_upper) == 2

    def test_add_keyword(self):
        """Test adding keywords."""
        store = LabelStore()
        label = Label(level=SecurityLevel.EXECUTIVE)

        store.add_keyword("confidential", label)
        store.add_keyword("secret", label)

        keywords = store.get_keywords()
        assert "confidential" in keywords
        assert "secret" in keywords

    def test_find_matching_keywords(self):
        """Test finding matching keywords in text."""
        store = LabelStore()
        store.add_keyword("revenue", Label(level=SecurityLevel.EXECUTIVE))
        store.add_keyword("budget", Label(level=SecurityLevel.MANAGER))
        store.add_keyword("internal", Label(level=SecurityLevel.STAFF))

        # Match executive keyword
        matches = store.find_matching_keywords("Q3 revenue looks good")
        assert len(matches) == 1
        assert matches[0][0] == "revenue"
        assert matches[0][1].level == SecurityLevel.EXECUTIVE

        # Match multiple keywords
        matches = store.find_matching_keywords("Internal budget and revenue report")
        assert len(matches) == 3

        # No matches
        matches = store.find_matching_keywords("Hello world")
        assert len(matches) == 0

        # Case insensitive matching
        matches = store.find_matching_keywords("REVENUE increased")
        assert len(matches) == 1

    def test_get_max_keyword_level(self):
        """Test getting maximum keyword level."""
        store = LabelStore()
        store.add_keyword("revenue", Label(level=SecurityLevel.EXECUTIVE))
        store.add_keyword("budget", Label(level=SecurityLevel.MANAGER))
        store.add_keyword("internal", Label(level=SecurityLevel.STAFF))

        # Single keyword
        level = store.get_max_keyword_level("Check the budget")
        assert level == SecurityLevel.MANAGER

        # Multiple keywords - returns max
        level = store.get_max_keyword_level("Revenue and budget report")
        assert level == SecurityLevel.EXECUTIVE

        # No keywords
        level = store.get_max_keyword_level("Hello world")
        assert level is None

    def test_clear(self):
        """Test clearing the store."""
        store = LabelStore()
        store.add("content", Label(level=SecurityLevel.STAFF))
        store.add_keyword("test", Label(level=SecurityLevel.MANAGER))

        assert len(store) == 1

        store.clear()

        assert len(store) == 0
        assert store.get_by_content("content") is None
        assert len(store.get_keywords()) == 0

    def test_len(self):
        """Test len() on store."""
        store = LabelStore()
        assert len(store) == 0

        store.add("content1", Label(level=SecurityLevel.STAFF))
        assert len(store) == 1

        store.add("content2", Label(level=SecurityLevel.MANAGER))
        assert len(store) == 2
