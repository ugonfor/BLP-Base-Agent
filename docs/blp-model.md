# Bell-LaPadula Model Implementation

Clearance에서 BLP 모델을 어떻게 구현했는지 설명합니다.

## BLP 모델 개요

### 원본 BLP (1973)

Bell-LaPadula 모델은 미군의 기밀 문서 관리를 위해 개발되었습니다.

**핵심 속성:**
1. **Simple Security (ss-property)**: No Read Up
   - 주체는 자신의 clearance보다 높은 객체를 읽을 수 없음

2. **Star Property (*-property)**: No Write Down
   - 주체는 자신이 접근한 최고 레벨보다 낮은 곳에 쓸 수 없음

**보안 레벨:**
```
TOP SECRET > SECRET > CONFIDENTIAL > UNCLASSIFIED
```

### Clearance의 확장

원본 BLP는 **주체(사람)**에 clearance를 부여합니다.
Clearance는 **정보 단위**에 라벨을 부여합니다.

**이유:**
- 팀장이 팀원에게 말은 해야 함
- 팀장 자체가 HIGH가 아니라, 팀장이 가진 "특정 정보"가 HIGH

```python
# 원본 BLP
manager.clearance = MANAGER  # 팀장은 항상 MANAGER 레벨

# Clearance
manager.clearance = MANAGER
message = "CEO가 인수합병 언급"  # 이 메시지가 EXECUTIVE 레벨
```

## 구현 상세

### SecurityLevel

```python
class SecurityLevel(IntEnum):
    PUBLIC = 0      # 누구나
    STAFF = 1       # 내부 직원
    MANAGER = 2     # 관리자
    EXECUTIVE = 3   # 경영진
```

**IntEnum 선택 이유:**
```python
# 자연스러운 비교 연산
EXECUTIVE > MANAGER  # True
STAFF >= PUBLIC      # True

# 산술 연산 방지 (의미 없음)
STAFF + MANAGER      # 가능하지만 사용 안 함
```

### No Read Up 구현

```python
# models.py
class SecurityLevel(IntEnum):
    def can_read(self, object_level: SecurityLevel) -> bool:
        return self >= object_level

# checker.py
def check_read(self, content_level, reader) -> CheckResult:
    if reader.clearance < content_level:
        return CheckResult(
            allowed=False,
            violation="NO_READ_UP"
        )
    return CheckResult(allowed=True)
```

### No Write Down 구현

```python
# checker.py
def check_write(self, message, recipient, context) -> CheckResult:
    # 1. 메시지의 보안 레벨 분석
    message_level, labels = self.analyzer.analyze_detailed(message, context)

    # 2. No Write Down 검증
    if message_level > recipient.clearance:
        return CheckResult(
            allowed=False,
            violation="NO_WRITE_DOWN",
            message_level=message_level,
            recipient_clearance=recipient.clearance,
            violating_labels=[l for l in labels if l.level > recipient.clearance]
        )

    return CheckResult(allowed=True)
```

### 정보 라벨링

```python
@dataclass
class Label:
    level: SecurityLevel    # 보안 레벨
    source: str            # 출처 (e.g., "ceo_meeting_2024")
    topics: list[str]      # 키워드 매칭용 토픽
```

**라벨 부착 시점:**
1. **명시적**: `label_store.add(content, label)`
2. **키워드**: `label_store.add_keyword("revenue", label)`
3. **컨텍스트**: 에이전트가 읽은 문서의 라벨 전파

### 메시지 보안 레벨 결정

```python
def analyze(message, context) -> SecurityLevel:
    max_level = PUBLIC

    # 1. 키워드 매칭
    for keyword, label in keywords.items():
        if keyword in message.lower():
            max_level = max(max_level, label.level)

    # 2. 컨텍스트 토픽 매칭
    for label in context:
        for topic in label.topics:
            if topic.lower() in message.lower():
                max_level = max(max_level, label.level)

    return max_level
```

**예시:**
```
keywords = {"revenue": EXECUTIVE, "budget": MANAGER}
context = [Label(EXECUTIVE, topics=["project-x"])]

message = "Project-x revenue is up"
         ↓
matches: "revenue" → EXECUTIVE
         "project-x" → EXECUTIVE (from context)
         ↓
result = EXECUTIVE
```

## 완화 메커니즘

### 1. Declassification (하향 전달)

엄격한 No Write Down은 실용적이지 않습니다. CEO가 팀원에게 아무 말도 못 하면 안 됩니다.

```python
# 승인된 하향 전달
request = declassifier.request(
    content="Q3 요약: 성장 순조",
    from_level=EXECUTIVE,
    to_level=STAFF,
    justification="CEO 승인"
)

# CEO가 승인
declassifier.approve(request.id, ceo, expires_in=timedelta(hours=24))

# 24시간 동안 유효
if declassifier.can_share(request.id):
    send_to_staff(declassifier.get_content(request.id))
```

### 2. Sanitization (내용 삭제)

민감한 부분만 제거하고 나머지 전달:

```python
declassifier.add_sanitization_rule(
    pattern=r"\$[\d,]+",          # 금액 패턴
    replacement="[REDACTED]",
    level=EXECUTIVE
)

# "Revenue is $10M" → "Revenue is [REDACTED]"
```

### 3. Context Reset

대화 컨텍스트를 명시적으로 리셋:

```python
analyzer = ContextAwareAnalyzer(store)

# 기밀 정보 접근
analyzer.add_to_context(Label(EXECUTIVE, topics=["acquisition"]))

# 기밀 대화 종료
analyzer.clear_context()

# 이제 일반 대화 가능
```

## 보안 속성 증명

### Theorem: No Downward Flow

주장: 승인 없이는 높은 레벨의 정보가 낮은 레벨로 흐르지 않는다.

**증명:**
1. 모든 메시지는 `check_write()`를 거침
2. `check_write()`는 `message_level > recipient.clearance`면 차단
3. `message_level`은 메시지 내 최고 레벨 (키워드/컨텍스트)
4. 따라서 높은 레벨 정보가 낮은 clearance로 전달 불가

**예외 조건:**
- `Declassifier`로 명시적 승인된 경우
- 키워드/토픽이 등록되지 않은 경우 (분석기 한계)

### Covert Channel 고려

**잠재적 우회:**
1. 키워드 변형 (revenue → r3v3nu3)
2. 암시적 표현 ("그 숫자")
3. 메타데이터 (응답 시간, 메시지 길이)

**대응:**
1. LLM Analyzer로 의미론적 분석
2. 컨텍스트 기반 분석
3. 이상 패턴 감사 로그 분석

## 한계점

1. **완전하지 않은 분석**: 키워드 기반은 우회 가능
2. **LLM 의존성**: LLM 분석도 100% 정확하지 않음
3. **컨텍스트 전파**: 에이전트가 읽은 모든 정보 추적 어려움
4. **성능 오버헤드**: 모든 메시지 분석 필요

**권장 사항:**
- Defense in depth: 여러 레이어 조합
- 감사 로그 모니터링
- 정기적 키워드/규칙 업데이트
- LLM + 키워드 하이브리드 사용
