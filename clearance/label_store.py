"""
Label Store - Information-to-Label mapping storage.

Maintains the mapping between content/information and their security labels.
This is the foundation for tracking what information has what classification.
"""

import hashlib
from typing import Optional

from clearance.models import Label, SecurityLevel


class LabelStore:
    """
    In-memory storage for information-label mappings.

    Stores labels indexed by:
    - Content hash: for exact content matching
    - Source: for retrieving all labels from a source
    - Topic: for topic-based queries

    Example:
        store = LabelStore()
        store.add("Q3 revenue is $10M", Label(
            level=SecurityLevel.EXECUTIVE,
            source="ceo_meeting_2024_q3",
            topics=["revenue", "financial"]
        ))

        # Later, when checking a message
        label = store.get_by_content("Q3 revenue is $10M")
        # Returns the EXECUTIVE label
    """

    def __init__(self) -> None:
        self._by_hash: dict[str, Label] = {}
        self._by_source: dict[str, list[Label]] = {}
        self._by_topic: dict[str, list[Label]] = {}
        self._keywords: dict[str, Label] = {}

    @staticmethod
    def _hash_content(content: str) -> str:
        """Generate a hash for content."""
        return hashlib.sha256(content.encode()).hexdigest()

    def add(self, content: str, label: Label) -> str:
        """
        Add a content-label mapping.

        Args:
            content: The information content
            label: Security label for this content

        Returns:
            Content hash for reference
        """
        content_hash = self._hash_content(content)
        self._by_hash[content_hash] = label

        # Index by source
        if label.source:
            if label.source not in self._by_source:
                self._by_source[label.source] = []
            self._by_source[label.source].append(label)

        # Index by topics
        for topic in label.topics:
            topic_lower = topic.lower()
            if topic_lower not in self._by_topic:
                self._by_topic[topic_lower] = []
            self._by_topic[topic_lower].append(label)

        return content_hash

    def add_keyword(self, keyword: str, label: Label) -> None:
        """
        Register a keyword that indicates a security level.

        Any message containing this keyword will be flagged
        with at least this security level.

        Args:
            keyword: The keyword to watch for
            label: Security label associated with this keyword
        """
        self._keywords[keyword.lower()] = label

    def get_by_hash(self, content_hash: str) -> Optional[Label]:
        """Get label by content hash."""
        return self._by_hash.get(content_hash)

    def get_by_content(self, content: str) -> Optional[Label]:
        """Get label by exact content match."""
        content_hash = self._hash_content(content)
        return self._by_hash.get(content_hash)

    def get_by_source(self, source: str) -> list[Label]:
        """Get all labels from a specific source."""
        return self._by_source.get(source, [])

    def get_by_topic(self, topic: str) -> list[Label]:
        """Get all labels for a topic."""
        return self._by_topic.get(topic.lower(), [])

    def get_keywords(self) -> dict[str, Label]:
        """Get all registered keywords and their labels."""
        return self._keywords.copy()

    def find_matching_keywords(self, text: str) -> list[tuple[str, Label]]:
        """
        Find all keywords present in the given text.

        Args:
            text: Text to search for keywords

        Returns:
            List of (keyword, label) tuples for matches found
        """
        text_lower = text.lower()
        matches = []
        for keyword, label in self._keywords.items():
            if keyword in text_lower:
                matches.append((keyword, label))
        return matches

    def get_max_keyword_level(self, text: str) -> Optional[SecurityLevel]:
        """
        Get the highest security level from keywords in text.

        Args:
            text: Text to analyze

        Returns:
            Highest security level found, or None if no keywords match
        """
        matches = self.find_matching_keywords(text)
        if not matches:
            return None
        return max(label.level for _, label in matches)

    def clear(self) -> None:
        """Clear all stored labels."""
        self._by_hash.clear()
        self._by_source.clear()
        self._by_topic.clear()
        self._keywords.clear()

    def __len__(self) -> int:
        """Return number of stored content-label mappings."""
        return len(self._by_hash)
