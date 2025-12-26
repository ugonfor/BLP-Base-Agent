# Core Components

각 핵심 컴포넌트의 내부 구현을 상세히 설명합니다.

## 1. LabelStore (`clearance/label_store.py`)

### 데이터 구조

```python
class LabelStore:
    _by_hash: dict[str, Label]           # content hash → label
    _by_source: dict[str, list[Label]]   # source → labels
    _by_topic: dict[str, list[Label]]    # topic → labels
    _keywords: dict[str, Label]          # keyword → label
```

### 해시 계산

```python
@staticmethod
def _hash_content(content: str) -> str:
    return hashlib.sha256(content.encode()).hexdigest()
```

**SHA-256 선택 이유:**
- 충돌 확률 극히 낮음
- 빠른 계산 속도
- 64자 고정 길이 (저장 효율)

### 키워드 매칭

```python
def find_matching_keywords(self, text: str) -> list[tuple[str, Label]]:
    text_lower = text.lower()
    matches = []
    for keyword, label in self._keywords.items():
        if keyword in text_lower:
            matches.append((keyword, label))
    return matches
```

**O(n*m) 복잡도:**
- n = 키워드 수
- m = 텍스트 길이

**최적화 가능:**
- Aho-Corasick 알고리즘 (O(m + k), k=매칭 수)
- Trie 기반 매칭

## 2. MessageAnalyzer (`clearance/analyzer.py`)

### 분석 프로세스

```python
def analyze_detailed(self, message, context) -> tuple[SecurityLevel, list[Label]]:
    matching_labels = []
    max_level = SecurityLevel.PUBLIC

    # Phase 1: 키워드 매칭
    for keyword, label in self.label_store.find_matching_keywords(message):
        matching_labels.append(label)
        max_level = max(max_level, label.level)

    # Phase 2: 컨텍스트 토픽 매칭
    message_lower = message.lower()
    for label in context:
        for topic in label.topics:
            if topic.lower() in message_lower:
                matching_labels.append(label)
                max_level = max(max_level, label.level)
                break  # 중복 방지

    return max_level, matching_labels
```

### ContextAwareAnalyzer

```python
class ContextAwareAnalyzer(MessageAnalyzer):
    _conversation_context: list[Label]  # 누적 컨텍스트

    def add_to_context(self, label: Label) -> None:
        self._conversation_context.append(label)

    def analyze(self, message, context=None) -> SecurityLevel:
        full_context = self._conversation_context + (context or [])
        return super().analyze(message, full_context)
```

**사용 시나리오:**
```python
analyzer = ContextAwareAnalyzer(store)

# 에이전트가 기밀 문서 읽음
analyzer.add_to_context(Label(EXECUTIVE, topics=["acquisition"]))

# 이후 메시지에서 "acquisition" 언급하면 EXECUTIVE로 분류
result = analyzer.analyze("How's the acquisition going?")
# result = EXECUTIVE
```

## 3. LLMAnalyzer (`clearance/llm_analyzer.py`)

### 백엔드 아키텍처

```python
class LLMBackend(ABC):
    @abstractmethod
    def classify(self, prompt: str) -> str: ...

    @abstractmethod
    def is_available(self) -> bool: ...

# 구현체
class OpenAIBackend(LLMBackend): ...
class AnthropicBackend(LLMBackend): ...
class OllamaBackend(LLMBackend): ...
```

### 프롬프트 구조

```python
CLASSIFICATION_PROMPT = """
Security Levels:
- PUBLIC (0): General information
- STAFF (1): Internal only
- MANAGER (2): Management (budgets, salaries)
- EXECUTIVE (3): Highly confidential (M&A, financials)

Keywords: {keywords}
Message: "{message}"
Context: {context}

Respond with JSON:
{{"level": <0-3>, "confidence": <0-1>, "reasoning": "...", "detected_topics": [...]}}
"""
```

### 응답 파싱

```python
def _parse_response(self, response: str) -> Optional[LLMClassification]:
    # Markdown 코드 블록 제거
    if response.startswith("```"):
        response = "\n".join(response.split("\n")[1:-1])

    data = json.loads(response)

    return LLMClassification(
        level=SecurityLevel(data["level"]),
        confidence=data["confidence"],
        reasoning=data["reasoning"],
        detected_topics=data["detected_topics"]
    )
```

### Fallback 로직

```python
def analyze(self, message, context) -> SecurityLevel:
    if not self.backend.is_available():
        return self._keyword_fallback(message, context)

    try:
        result = self._llm_classify(message, context)

        # 신뢰도 낮으면 키워드 결과와 비교
        if result.confidence < self.confidence_threshold:
            keyword_level = self._keyword_fallback(message, context)
            # 더 높은 레벨 선택 (안전 우선)
            return max(result.level, keyword_level)

        return result.level

    except Exception:
        return self._keyword_fallback(message, context)
```

### 캐싱

```python
class CachedLLMAnalyzer(LLMAnalyzer):
    _cache: dict[str, LLMClassification]
    _cache_size: int = 1000

    def _cache_key(self, message, context) -> str:
        ctx_str = "|".join(f"{l.level}:{','.join(l.topics)}" for l in context)
        return f"{message}||{ctx_str}"

    def analyze_detailed(self, message, context):
        key = self._cache_key(message, context)

        if key in self._cache:
            return self._cache[key]

        result = super().analyze_detailed(message, context)

        # LRU-like: 오래된 것 먼저 삭제
        if len(self._cache) >= self._cache_size:
            del self._cache[next(iter(self._cache))]

        self._cache[key] = result
        return result
```

## 4. ClearanceChecker (`clearance/checker.py`)

### 핵심 메서드

```python
def check_write(self, message, recipient, context=None) -> CheckResult:
    message_level, labels = self.analyzer.analyze_detailed(message, context or [])

    if message_level > recipient.clearance:
        return CheckResult(
            allowed=False,
            violation="NO_WRITE_DOWN",
            message_level=message_level,
            recipient_clearance=recipient.clearance,
            reason=f"{message_level.name} info → {recipient.name} ({recipient.clearance.name})",
            violating_labels=[l for l in labels if l.level > recipient.clearance]
        )

    return CheckResult(
        allowed=True,
        message_level=message_level,
        recipient_clearance=recipient.clearance
    )
```

### 유틸리티 메서드

```python
def get_allowed_recipients(self, message, potential_recipients, context=None):
    """메시지를 받을 수 있는 수신자 필터링"""
    return [r for r in potential_recipients
            if self.check_write(message, r, context).allowed]

def get_minimum_clearance(self, message, context=None):
    """메시지 수신에 필요한 최소 clearance"""
    return self.analyzer.analyze(message, context)
```

### Factory 함수

```python
def create_checker(keywords: dict[str, SecurityLevel] = None) -> ClearanceChecker:
    store = LabelStore()

    if keywords:
        for keyword, level in keywords.items():
            store.add_keyword(keyword, Label(level=level))

    analyzer = MessageAnalyzer(store)
    return ClearanceChecker(store, analyzer)
```

## 5. Declassifier (`clearance/declassifier.py`)

### 상태 머신

```
          ┌─────────────────────────────┐
          │                             │
          ▼                             │
      PENDING ──────┬──────► DENIED     │
          │         │                   │
          │    deny()                   │
          │                             │
     approve()                          │
          │                             │
          ▼                             │
      APPROVED ────┬────► REVOKED       │
          │        │                    │
          │   revoke()                  │
          │                             │
      expires                           │
          │                             │
          ▼                             │
      EXPIRED ◄─────────────────────────┘
```

### 승인 검증

```python
def approve(self, request_id, approver, expires_in=None) -> bool:
    request = self._requests.get(request_id)

    # 1. 요청 존재 확인
    if not request:
        return False

    # 2. PENDING 상태인지 확인
    if request.status != RequestStatus.PENDING:
        return False

    # 3. 승인권자 clearance 확인
    #    원본 레벨 이상이어야 승인 가능
    if approver.clearance < request.from_level:
        return False

    # 4. 승인 처리
    request.status = RequestStatus.APPROVED
    request.reviewed_by = approver
    request.reviewed_at = datetime.now()

    # 5. 만료 시간 설정
    if expires_in or self._default_expiration:
        request.expires_at = datetime.now() + (expires_in or self._default_expiration)

    # 6. 하향 라벨 생성
    self._declassified[request_id] = Label(
        level=request.to_level,
        source=f"declassified:{request_id}"
    )

    return True
```

### Sanitization

```python
def _sanitize_content(self, content, target_level) -> str:
    result = content

    for rule in self._sanitization_rules:
        # 규칙 레벨이 목표 레벨보다 높으면 적용
        if rule.level > target_level:
            result = re.sub(rule.pattern, rule.replacement, result)

    return result
```

**예시:**
```python
declassifier.add_sanitization_rule(
    pattern=r"\$[\d,]+M?",     # $10M, $1,000
    replacement="[AMOUNT]",
    level=EXECUTIVE
)

content = "Revenue: $10M, Growth: 20%"
sanitized = declassifier._sanitize_content(content, STAFF)
# "Revenue: [AMOUNT], Growth: 20%"
```

## 6. AuditLogger (`clearance/audit.py`)

### 이벤트 타입

```python
class AuditEventType(Enum):
    MESSAGE_ALLOWED = "message_allowed"
    MESSAGE_BLOCKED = "message_blocked"
    DECLASS_REQUESTED = "declassification_requested"
    DECLASS_APPROVED = "declassification_approved"
    DECLASS_DENIED = "declassification_denied"
    USER_CLEARANCE_CHANGED = "user_clearance_changed"
    SECURITY_VIOLATION = "security_violation"
```

### 백엔드 인터페이스

```python
class AuditBackend(ABC):
    @abstractmethod
    def log(self, event: AuditEvent) -> None: ...

    @abstractmethod
    def query(
        self,
        event_type=None,
        actor_id=None,
        start_time=None,
        end_time=None,
        limit=100
    ) -> list[AuditEvent]: ...
```

### File Backend

```python
class FileAuditBackend(AuditBackend):
    """JSON Lines 형식으로 파일에 기록"""

    def log(self, event):
        with self._lock:
            with open(self._path, "a") as f:
                f.write(json.dumps(event.to_dict()) + "\n")

    def query(self, **filters):
        results = []
        for line in open(self._path):
            event = AuditEvent.from_dict(json.loads(line))
            if self._matches_filters(event, filters):
                results.append(event)
        return sorted(results, key=lambda e: e.timestamp, reverse=True)[:limit]
```

### 통계 API

```python
def get_stats(self, start_time=None, end_time=None) -> dict:
    events = self.query(start_time=start_time, end_time=end_time, limit=10000)

    return {
        "total_events": len(events),
        "messages_allowed": count(MESSAGE_ALLOWED),
        "messages_blocked": count(MESSAGE_BLOCKED),
        "violations": count(MESSAGE_BLOCKED) + count(SECURITY_VIOLATION),
        "by_type": {type: count for type in EventType}
    }
```
