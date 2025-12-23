"""
Message Analyzer - Determines security level of message content.

Analyzes messages to determine what security level of information
they contain. This is crucial for BLP enforcement: we need to know
the classification of outgoing information to enforce No Write Down.

MVP Implementation: Keyword-based analysis
Future: LLM-based semantic analysis, RAG source tracking
"""

from typing import Protocol

from clearance.models import Label, SecurityLevel
from clearance.label_store import LabelStore


class AnalyzerProtocol(Protocol):
    """Protocol for message analyzers."""

    def analyze(self, message: str, context: list[Label]) -> SecurityLevel:
        """
        Analyze a message and determine its security level.

        Args:
            message: The message text to analyze
            context: Labels of information the sender has access to

        Returns:
            The highest security level of information in the message
        """
        ...

    def analyze_detailed(
        self, message: str, context: list[Label]
    ) -> tuple[SecurityLevel, list[Label]]:
        """
        Analyze a message with detailed label information.

        Args:
            message: The message text to analyze
            context: Labels of information the sender has access to

        Returns:
            Tuple of (security level, list of matching labels)
        """
        ...


class MessageAnalyzer:
    """
    Keyword-based message analyzer.

    Determines message security level by:
    1. Checking for registered keywords in the label store
    2. Matching against context labels' topics
    3. Taking the maximum level found

    Example:
        store = LabelStore()
        store.add_keyword("revenue", Label(SecurityLevel.EXECUTIVE, source="financial"))
        store.add_keyword("confidential", Label(SecurityLevel.MANAGER))

        analyzer = MessageAnalyzer(store)
        level = analyzer.analyze("Q3 revenue looks good")
        # Returns SecurityLevel.EXECUTIVE
    """

    def __init__(self, label_store: LabelStore) -> None:
        """
        Initialize analyzer with a label store.

        Args:
            label_store: Store containing keyword-label mappings
        """
        self.label_store = label_store

    def analyze(self, message: str, context: list[Label] | None = None) -> SecurityLevel:
        """
        Analyze a message and determine its security level.

        Args:
            message: The message text to analyze
            context: Optional labels of information the sender has access to

        Returns:
            The highest security level of information in the message
        """
        level, _ = self.analyze_detailed(message, context or [])
        return level

    def analyze_detailed(
        self, message: str, context: list[Label] | None = None
    ) -> tuple[SecurityLevel, list[Label]]:
        """
        Analyze a message with detailed label information.

        Args:
            message: The message text to analyze
            context: Optional labels of information the sender has access to

        Returns:
            Tuple of (security level, list of matching labels)
        """
        context = context or []
        matching_labels: list[Label] = []
        max_level = SecurityLevel.PUBLIC

        # Check registered keywords
        keyword_matches = self.label_store.find_matching_keywords(message)
        for keyword, label in keyword_matches:
            matching_labels.append(label)
            if label.level > max_level:
                max_level = label.level

        # Check context labels' topics
        message_lower = message.lower()
        for label in context:
            for topic in label.topics:
                if topic.lower() in message_lower:
                    matching_labels.append(label)
                    if label.level > max_level:
                        max_level = label.level
                    break  # Don't double-count same label

        return max_level, matching_labels


class ContextAwareAnalyzer(MessageAnalyzer):
    """
    Extended analyzer that tracks conversation context.

    Maintains a running context of information that has been
    introduced in the conversation, automatically elevating
    security level when sensitive information is referenced.
    """

    def __init__(self, label_store: LabelStore) -> None:
        super().__init__(label_store)
        self._conversation_context: list[Label] = []

    def add_to_context(self, label: Label) -> None:
        """Add a label to the conversation context."""
        self._conversation_context.append(label)

    def clear_context(self) -> None:
        """Clear the conversation context."""
        self._conversation_context.clear()

    def analyze(self, message: str, context: list[Label] | None = None) -> SecurityLevel:
        """Analyze using both provided and conversation context."""
        full_context = list(self._conversation_context)
        if context:
            full_context.extend(context)
        return super().analyze(message, full_context)

    def analyze_detailed(
        self, message: str, context: list[Label] | None = None
    ) -> tuple[SecurityLevel, list[Label]]:
        """Analyze with details using both provided and conversation context."""
        full_context = list(self._conversation_context)
        if context:
            full_context.extend(context)
        return super().analyze_detailed(message, full_context)
