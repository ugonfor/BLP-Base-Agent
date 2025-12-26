"""
LLM-based Message Analyzer.

Uses Large Language Models to semantically analyze messages and determine
their security classification. More sophisticated than keyword matching,
can understand context, paraphrases, and implicit information disclosure.

Supports multiple LLM backends:
- OpenAI (GPT-4, GPT-3.5)
- Anthropic (Claude)
- Local models via Ollama

Requirements:
    pip install openai anthropic httpx
"""

import json
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional

from clearance.models import Label, SecurityLevel
from clearance.label_store import LabelStore


logger = logging.getLogger(__name__)


# Classification prompt template
CLASSIFICATION_PROMPT = """You are a security classification system. Analyze the following message and determine its security level based on the information it contains.

Security Levels (from lowest to highest):
- PUBLIC (0): General information anyone can access
- STAFF (1): Internal company information for employees only
- MANAGER (2): Sensitive information for management (budgets, salaries, HR matters)
- EXECUTIVE (3): Highly confidential information (M&A, financials, strategic plans)

Sensitive Keywords to Watch:
{keywords}

Message to Analyze:
"{message}"

Context (if any):
{context}

Respond with a JSON object:
{{
    "level": <0-3>,
    "level_name": "<PUBLIC|STAFF|MANAGER|EXECUTIVE>",
    "confidence": <0.0-1.0>,
    "reasoning": "<brief explanation>",
    "detected_topics": ["<topic1>", "<topic2>"]
}}

Only respond with the JSON object, no other text."""


@dataclass
class LLMClassification:
    """Result of LLM classification."""
    level: SecurityLevel
    confidence: float
    reasoning: str
    detected_topics: list[str]
    raw_response: Optional[str] = None


class LLMBackend(ABC):
    """Abstract base class for LLM backends."""

    @abstractmethod
    def classify(self, prompt: str) -> str:
        """Send prompt to LLM and get response."""
        ...

    @abstractmethod
    def is_available(self) -> bool:
        """Check if this backend is available."""
        ...


class OpenAIBackend(LLMBackend):
    """OpenAI GPT backend."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        model: str = "gpt-4o-mini",
        temperature: float = 0.1,
    ) -> None:
        self.model = model
        self.temperature = temperature
        self._client = None

        try:
            import openai
            self._client = openai.OpenAI(api_key=api_key) if api_key else openai.OpenAI()
        except ImportError:
            logger.warning("openai package not installed")
        except Exception as e:
            logger.warning(f"Failed to initialize OpenAI client: {e}")

    def is_available(self) -> bool:
        return self._client is not None

    def classify(self, prompt: str) -> str:
        if not self._client:
            raise RuntimeError("OpenAI client not available")

        response = self._client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": "You are a security classification system."},
                {"role": "user", "content": prompt}
            ],
            temperature=self.temperature,
            max_tokens=500,
        )
        return response.choices[0].message.content or ""


class AnthropicBackend(LLMBackend):
    """Anthropic Claude backend."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        model: str = "claude-3-haiku-20240307",
        temperature: float = 0.1,
    ) -> None:
        self.model = model
        self.temperature = temperature
        self._client = None

        try:
            import anthropic
            self._client = anthropic.Anthropic(api_key=api_key) if api_key else anthropic.Anthropic()
        except ImportError:
            logger.warning("anthropic package not installed")
        except Exception as e:
            logger.warning(f"Failed to initialize Anthropic client: {e}")

    def is_available(self) -> bool:
        return self._client is not None

    def classify(self, prompt: str) -> str:
        if not self._client:
            raise RuntimeError("Anthropic client not available")

        response = self._client.messages.create(
            model=self.model,
            max_tokens=500,
            temperature=self.temperature,
            messages=[{"role": "user", "content": prompt}]
        )
        return response.content[0].text if response.content else ""


class OllamaBackend(LLMBackend):
    """Ollama local model backend."""

    def __init__(
        self,
        model: str = "llama3.2",
        base_url: str = "http://localhost:11434",
        temperature: float = 0.1,
    ) -> None:
        self.model = model
        self.base_url = base_url
        self.temperature = temperature
        self._httpx = None

        try:
            import httpx
            self._httpx = httpx
        except ImportError:
            logger.warning("httpx package not installed")

    def is_available(self) -> bool:
        if not self._httpx:
            return False
        try:
            response = self._httpx.get(f"{self.base_url}/api/tags", timeout=2.0)
            return response.status_code == 200
        except Exception:
            return False

    def classify(self, prompt: str) -> str:
        if not self._httpx:
            raise RuntimeError("httpx not available")

        response = self._httpx.post(
            f"{self.base_url}/api/generate",
            json={
                "model": self.model,
                "prompt": prompt,
                "stream": False,
                "options": {"temperature": self.temperature}
            },
            timeout=30.0
        )
        response.raise_for_status()
        return response.json().get("response", "")


class LLMAnalyzer:
    """
    LLM-powered message analyzer.

    Uses semantic understanding to classify messages, catching paraphrases
    and implicit information disclosure that keyword matching would miss.

    Example:
        analyzer = LLMAnalyzer(
            backend=OpenAIBackend(api_key="sk-..."),
            label_store=store
        )

        # This would be missed by keyword matching but caught by LLM
        level = analyzer.analyze("The company we're buying is worth fifty million")
        # Returns EXECUTIVE (understands this is acquisition info)
    """

    def __init__(
        self,
        backend: LLMBackend,
        label_store: Optional[LabelStore] = None,
        confidence_threshold: float = 0.7,
        fallback_to_keywords: bool = True,
    ) -> None:
        """
        Initialize the LLM analyzer.

        Args:
            backend: LLM backend to use
            label_store: Optional label store for keyword context
            confidence_threshold: Minimum confidence to trust LLM classification
            fallback_to_keywords: Use keyword matching if LLM fails/low confidence
        """
        self.backend = backend
        self.label_store = label_store
        self.confidence_threshold = confidence_threshold
        self.fallback_to_keywords = fallback_to_keywords

        # Import keyword analyzer for fallback
        from clearance.analyzer import MessageAnalyzer
        self._keyword_analyzer = MessageAnalyzer(label_store) if label_store else None

    def _build_prompt(self, message: str, context: list[Label] | None = None) -> str:
        """Build the classification prompt."""
        # Get keywords from label store
        keywords = ""
        if self.label_store:
            kw_list = []
            for kw, label in self.label_store.get_keywords().items():
                kw_list.append(f"- {kw}: {label.level.name}")
            keywords = "\n".join(kw_list) if kw_list else "None specified"
        else:
            keywords = "None specified"

        # Format context
        context_str = "None"
        if context:
            ctx_items = []
            for label in context:
                topics = ", ".join(label.topics) if label.topics else "N/A"
                ctx_items.append(f"- {label.level.name}: {topics}")
            context_str = "\n".join(ctx_items)

        return CLASSIFICATION_PROMPT.format(
            keywords=keywords,
            message=message,
            context=context_str
        )

    def _parse_response(self, response: str) -> Optional[LLMClassification]:
        """Parse LLM response into classification result."""
        try:
            # Try to extract JSON from response
            response = response.strip()
            if response.startswith("```"):
                # Remove markdown code blocks
                lines = response.split("\n")
                response = "\n".join(lines[1:-1])

            data = json.loads(response)

            level_value = data.get("level", 0)
            if isinstance(level_value, str):
                level_value = {"PUBLIC": 0, "STAFF": 1, "MANAGER": 2, "EXECUTIVE": 3}.get(level_value.upper(), 0)

            return LLMClassification(
                level=SecurityLevel(level_value),
                confidence=float(data.get("confidence", 0.5)),
                reasoning=data.get("reasoning", ""),
                detected_topics=data.get("detected_topics", []),
                raw_response=response
            )
        except (json.JSONDecodeError, KeyError, ValueError) as e:
            logger.warning(f"Failed to parse LLM response: {e}")
            return None

    def analyze(self, message: str, context: list[Label] | None = None) -> SecurityLevel:
        """
        Analyze a message and determine its security level.

        Args:
            message: The message text to analyze
            context: Optional labels of information the sender has access to

        Returns:
            The security level of the message
        """
        classification = self.analyze_detailed(message, context)
        return classification.level if classification else SecurityLevel.PUBLIC

    def analyze_detailed(
        self, message: str, context: list[Label] | None = None
    ) -> Optional[LLMClassification]:
        """
        Analyze a message with detailed classification info.

        Args:
            message: The message text to analyze
            context: Optional context labels

        Returns:
            LLMClassification with full details, or None if analysis failed
        """
        if not self.backend.is_available():
            logger.warning("LLM backend not available")
            if self.fallback_to_keywords and self._keyword_analyzer:
                level = self._keyword_analyzer.analyze(message, context)
                return LLMClassification(
                    level=level,
                    confidence=1.0,
                    reasoning="Fallback to keyword matching",
                    detected_topics=[]
                )
            return None

        try:
            prompt = self._build_prompt(message, context)
            response = self.backend.classify(prompt)
            classification = self._parse_response(response)

            if classification and classification.confidence < self.confidence_threshold:
                logger.info(f"Low confidence ({classification.confidence}), using fallback")
                if self.fallback_to_keywords and self._keyword_analyzer:
                    keyword_level = self._keyword_analyzer.analyze(message, context)
                    # Use higher of the two levels for safety
                    if keyword_level > classification.level:
                        classification.level = keyword_level
                        classification.reasoning += f" (keyword fallback: {keyword_level.name})"

            return classification

        except Exception as e:
            logger.error(f"LLM analysis failed: {e}")
            if self.fallback_to_keywords and self._keyword_analyzer:
                level = self._keyword_analyzer.analyze(message, context)
                return LLMClassification(
                    level=level,
                    confidence=1.0,
                    reasoning=f"Fallback due to error: {e}",
                    detected_topics=[]
                )
            return None


class CachedLLMAnalyzer(LLMAnalyzer):
    """
    LLM analyzer with caching for repeated messages.

    Caches classification results to reduce API calls and costs.
    """

    def __init__(
        self,
        backend: LLMBackend,
        label_store: Optional[LabelStore] = None,
        cache_size: int = 1000,
        **kwargs
    ) -> None:
        super().__init__(backend, label_store, **kwargs)
        self._cache: dict[str, LLMClassification] = {}
        self._cache_size = cache_size

    def _cache_key(self, message: str, context: list[Label] | None) -> str:
        """Generate cache key from message and context."""
        ctx_str = ""
        if context:
            ctx_str = "|".join(f"{l.level}:{','.join(l.topics)}" for l in context)
        return f"{message}||{ctx_str}"

    def analyze_detailed(
        self, message: str, context: list[Label] | None = None
    ) -> Optional[LLMClassification]:
        key = self._cache_key(message, context)

        if key in self._cache:
            return self._cache[key]

        result = super().analyze_detailed(message, context)

        if result:
            # Evict oldest if cache is full
            if len(self._cache) >= self._cache_size:
                oldest_key = next(iter(self._cache))
                del self._cache[oldest_key]
            self._cache[key] = result

        return result

    def clear_cache(self) -> None:
        """Clear the classification cache."""
        self._cache.clear()


def create_llm_analyzer(
    provider: str = "openai",
    api_key: Optional[str] = None,
    model: Optional[str] = None,
    label_store: Optional[LabelStore] = None,
    **kwargs
) -> LLMAnalyzer:
    """
    Factory function to create an LLM analyzer.

    Args:
        provider: LLM provider ("openai", "anthropic", "ollama")
        api_key: API key for the provider
        model: Model name (provider-specific)
        label_store: Optional label store for keyword context
        **kwargs: Additional arguments for the analyzer

    Returns:
        Configured LLMAnalyzer instance
    """
    if provider == "openai":
        backend = OpenAIBackend(
            api_key=api_key,
            model=model or "gpt-4o-mini"
        )
    elif provider == "anthropic":
        backend = AnthropicBackend(
            api_key=api_key,
            model=model or "claude-3-haiku-20240307"
        )
    elif provider == "ollama":
        backend = OllamaBackend(
            model=model or "llama3.2"
        )
    else:
        raise ValueError(f"Unknown provider: {provider}")

    return CachedLLMAnalyzer(backend, label_store, **kwargs)
