"""Tests for clearance.analyzer"""

import pytest
from clearance.analyzer import MessageAnalyzer, ContextAwareAnalyzer
from clearance.label_store import LabelStore
from clearance.models import Label, SecurityLevel


class TestMessageAnalyzer:
    """Tests for MessageAnalyzer class."""

    @pytest.fixture
    def store(self):
        """Create a label store with test keywords."""
        store = LabelStore()
        store.add_keyword("revenue", Label(
            level=SecurityLevel.EXECUTIVE,
            source="financial",
            topics=["money"]
        ))
        store.add_keyword("profit", Label(
            level=SecurityLevel.EXECUTIVE,
            source="financial"
        ))
        store.add_keyword("budget", Label(
            level=SecurityLevel.MANAGER,
            source="planning"
        ))
        store.add_keyword("salary", Label(
            level=SecurityLevel.MANAGER,
            source="hr"
        ))
        store.add_keyword("internal", Label(
            level=SecurityLevel.STAFF,
            source="general"
        ))
        return store

    @pytest.fixture
    def analyzer(self, store):
        """Create an analyzer with the test store."""
        return MessageAnalyzer(store)

    def test_analyze_public_message(self, analyzer):
        """Test analyzing message with no keywords."""
        level = analyzer.analyze("Hello, how are you today?")
        assert level == SecurityLevel.PUBLIC

    def test_analyze_executive_message(self, analyzer):
        """Test analyzing message with executive keywords."""
        level = analyzer.analyze("Q3 revenue exceeded expectations")
        assert level == SecurityLevel.EXECUTIVE

    def test_analyze_manager_message(self, analyzer):
        """Test analyzing message with manager keywords."""
        level = analyzer.analyze("Please review the budget proposal")
        assert level == SecurityLevel.MANAGER

    def test_analyze_staff_message(self, analyzer):
        """Test analyzing message with staff keywords."""
        level = analyzer.analyze("This is internal information")
        assert level == SecurityLevel.STAFF

    def test_analyze_multiple_keywords_returns_max(self, analyzer):
        """Test that multiple keywords return the max level."""
        # Contains both STAFF (internal) and EXECUTIVE (revenue)
        level = analyzer.analyze("Internal revenue report")
        assert level == SecurityLevel.EXECUTIVE

    def test_analyze_detailed_returns_labels(self, analyzer):
        """Test that analyze_detailed returns matching labels."""
        level, labels = analyzer.analyze_detailed("Q3 revenue and profit report")

        assert level == SecurityLevel.EXECUTIVE
        assert len(labels) == 2
        sources = [l.source for l in labels]
        assert "financial" in sources

    def test_analyze_with_context(self, analyzer):
        """Test analyzing with context labels."""
        # Add a context label with topic "project-x"
        context = [Label(
            level=SecurityLevel.EXECUTIVE,
            source="project",
            topics=["project-x"]
        )]

        # Message mentions the topic
        level = analyzer.analyze("How is project-x going?", context)
        assert level == SecurityLevel.EXECUTIVE

        # Message doesn't mention the topic
        level = analyzer.analyze("How is project-y going?", context)
        assert level == SecurityLevel.PUBLIC

    def test_analyze_detailed_with_context(self, analyzer):
        """Test analyze_detailed includes context matches."""
        context = [Label(
            level=SecurityLevel.MANAGER,
            source="meeting",
            topics=["alpha-initiative"]
        )]

        level, labels = analyzer.analyze_detailed(
            "Update on alpha-initiative",
            context
        )

        assert level == SecurityLevel.MANAGER
        assert any(l.source == "meeting" for l in labels)

    def test_case_insensitive_keyword_matching(self, analyzer):
        """Test that keyword matching is case insensitive."""
        level1 = analyzer.analyze("REVENUE increased")
        level2 = analyzer.analyze("Revenue increased")
        level3 = analyzer.analyze("revenue increased")

        assert level1 == level2 == level3 == SecurityLevel.EXECUTIVE


class TestContextAwareAnalyzer:
    """Tests for ContextAwareAnalyzer class."""

    @pytest.fixture
    def store(self):
        """Create a label store with test keywords."""
        store = LabelStore()
        store.add_keyword("secret", Label(level=SecurityLevel.EXECUTIVE))
        return store

    @pytest.fixture
    def analyzer(self, store):
        """Create a context-aware analyzer."""
        return ContextAwareAnalyzer(store)

    def test_maintains_conversation_context(self, analyzer):
        """Test that context is maintained across calls."""
        # Add to conversation context
        analyzer.add_to_context(Label(
            level=SecurityLevel.EXECUTIVE,
            topics=["alpha-project"]
        ))

        # First message doesn't mention it
        level1 = analyzer.analyze("Hello")
        assert level1 == SecurityLevel.PUBLIC

        # Second message references it
        level2 = analyzer.analyze("How about alpha-project?")
        assert level2 == SecurityLevel.EXECUTIVE

    def test_clear_context(self, analyzer):
        """Test clearing conversation context."""
        analyzer.add_to_context(Label(
            level=SecurityLevel.EXECUTIVE,
            topics=["alpha-project"]
        ))

        # Before clearing
        level = analyzer.analyze("Tell me about alpha-project")
        assert level == SecurityLevel.EXECUTIVE

        # After clearing
        analyzer.clear_context()
        level = analyzer.analyze("Tell me about alpha-project")
        assert level == SecurityLevel.PUBLIC

    def test_combines_provided_and_conversation_context(self, analyzer):
        """Test that both contexts are used."""
        analyzer.add_to_context(Label(
            level=SecurityLevel.MANAGER,
            topics=["topic-a"]
        ))

        extra_context = [Label(
            level=SecurityLevel.EXECUTIVE,
            topics=["topic-b"]
        )]

        # Only conversation context
        level = analyzer.analyze("About topic-a")
        assert level == SecurityLevel.MANAGER

        # With extra context
        level = analyzer.analyze("About topic-b", extra_context)
        assert level == SecurityLevel.EXECUTIVE

        # Both contexts
        level = analyzer.analyze("About topic-a and topic-b", extra_context)
        assert level == SecurityLevel.EXECUTIVE
