# Architecture

Clearance의 전체 아키텍처를 설명합니다.

## 레이어 구조

### 1. Data Models Layer (`clearance/models.py`)

가장 기본적인 데이터 구조를 정의합니다.

```python
SecurityLevel(IntEnum)  # PUBLIC(0) < STAFF(1) < MANAGER(2) < EXECUTIVE(3)
Label                   # 정보 단위에 부착되는 보안 라벨
Message                 # 전송되는 메시지
User                    # 사용자/에이전트
CheckResult             # BLP 검증 결과
```

**설계 결정:**
- `SecurityLevel`을 `IntEnum`으로 구현하여 대소 비교가 자연스럽게 동작
- `Label`에 `topics`를 추가하여 키워드 매칭 지원
- `CheckResult`에 `violating_labels`를 포함하여 디버깅 용이

### 2. Storage Layer (`clearance/label_store.py`)

라벨 정보를 저장하고 조회합니다.

```python
class LabelStore:
    _by_hash: dict[str, Label]      # 컨텐츠 해시 → 라벨
    _by_source: dict[str, list]     # 출처 → 라벨 목록
    _by_topic: dict[str, list]      # 토픽 → 라벨 목록
    _keywords: dict[str, Label]     # 키워드 → 라벨
```

**인덱싱 전략:**
- 컨텐츠는 SHA-256 해시로 저장 (정확한 매칭)
- 키워드는 소문자로 정규화하여 저장 (대소문자 무시)
- 토픽은 역인덱스로 저장 (빠른 조회)

### 3. Analysis Layer

메시지의 보안 레벨을 분석합니다.

#### Keyword Analyzer (`clearance/analyzer.py`)

```python
class MessageAnalyzer:
    def analyze(message, context) -> SecurityLevel:
        # 1. 등록된 키워드 검색
        # 2. 컨텍스트 라벨의 토픽 매칭
        # 3. 최대 레벨 반환
```

**분석 로직:**
```
message = "Q3 revenue is excellent"
         ↓
keywords = {"revenue": EXECUTIVE}
         ↓
matches = [("revenue", EXECUTIVE)]
         ↓
result = EXECUTIVE
```

#### LLM Analyzer (`clearance/llm_analyzer.py`)

```python
class LLMAnalyzer:
    def analyze(message, context) -> SecurityLevel:
        # 1. 프롬프트 생성
        # 2. LLM 호출
        # 3. JSON 응답 파싱
        # 4. 신뢰도 낮으면 키워드 fallback
```

**LLM 프롬프트 구조:**
```
System: Security classification system
User:
  - Security level definitions
  - Registered keywords
  - Message to analyze
  - Context labels
Expected: JSON with level, confidence, reasoning
```

### 4. Enforcement Layer (`clearance/checker.py`)

BLP 정책을 실제로 적용합니다.

```python
class ClearanceChecker:
    def check_write(message, recipient, context) -> CheckResult:
        # 1. 메시지 분석 → message_level
        # 2. No Write Down 검증: message_level <= recipient.clearance
        # 3. 위반 시 상세 정보 포함한 CheckResult 반환
```

**검증 흐름:**
```
message = "Revenue is $10M"
recipient = User(clearance=STAFF)
         ↓
analyze(message) → EXECUTIVE
         ↓
EXECUTIVE > STAFF
         ↓
CheckResult(allowed=False, violation="NO_WRITE_DOWN")
```

### 5. Workflow Layer

#### Declassifier (`clearance/declassifier.py`)

하향 정보 전달을 위한 승인 워크플로우:

```
Request → Pending → [Approve/Deny] → [Approved/Denied]
                         ↓
                    [Expires] → Expired
                         ↓
                    [Revoke] → Revoked
```

#### Audit Logger (`clearance/audit.py`)

이벤트 기록 및 조회:

```python
AuditEvent:
    - event_type: MESSAGE_BLOCKED, DECLASS_APPROVED, etc.
    - timestamp, actor, target
    - message_level, clearances
    - violation details
```

### 6. Integration Layer

외부 시스템 연동:

```
┌─────────────┐     ┌─────────────┐
│  Slack Bot  │     │Email Gateway│
└──────┬──────┘     └──────┬──────┘
       │                   │
       └───────┬───────────┘
               │
        ┌──────▼──────┐
        │   Checker   │
        └─────────────┘
```

## 데이터 흐름

### 메시지 검증 흐름

```
1. 애플리케이션에서 메시지 전송 요청
         ↓
2. Integration Layer가 메시지 인터셉트
         ↓
3. Checker.check_write() 호출
         ↓
4. Analyzer가 메시지 보안 레벨 분석
         ↓
5. LabelStore에서 키워드/토픽 조회
         ↓
6. BLP 규칙 검증
         ↓
7. AuditLogger에 결과 기록
         ↓
8. CheckResult 반환
         ↓
9. Integration Layer가 허용/차단 결정
```

### 하향 전달 흐름

```
1. 요청자가 declassifier.request() 호출
         ↓
2. DeclassifyRequest 생성 (PENDING)
         ↓
3. 승인권자에게 알림 (callback)
         ↓
4. 승인권자가 approve/deny 호출
         ↓
5. 승인 시: 라벨 생성, 만료 시간 설정
         ↓
6. can_share()로 유효성 확인 후 전달
```

## 스레드 안전성

- `LabelStore`: 읽기는 스레드 안전, 쓰기는 단일 스레드 가정
- `AuditLogger`: `threading.Lock`으로 동시 쓰기 보호
- `Declassifier`: 단일 스레드 가정 (필요시 외부에서 동기화)

## 메모리 관리

- `LabelStore`: 제한 없음 (운영 환경에서는 Redis 등 외부 저장소 권장)
- `InMemoryAuditBackend`: `max_events` 파라미터로 제한
- `CachedLLMAnalyzer`: `cache_size` 파라미터로 LRU 캐시 크기 제한
