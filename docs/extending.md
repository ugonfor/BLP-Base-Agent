# Extending Clearance

Clearance를 확장하는 방법을 설명합니다.

## 1. 커스텀 Analyzer

### Protocol 구현

```python
from clearance.analyzer import AnalyzerProtocol

class MyCustomAnalyzer:
    """커스텀 분석기 구현"""

    def analyze(self, message: str, context: list[Label]) -> SecurityLevel:
        # 커스텀 로직
        if self._is_pii(message):
            return SecurityLevel.MANAGER
        if self._is_financial(message):
            return SecurityLevel.EXECUTIVE
        return SecurityLevel.PUBLIC

    def analyze_detailed(self, message, context) -> tuple[SecurityLevel, list[Label]]:
        level = self.analyze(message, context)
        labels = self._extract_labels(message)
        return level, labels

    def _is_pii(self, message):
        # 개인정보 탐지 로직
        ...

    def _is_financial(self, message):
        # 금융 정보 탐지 로직
        ...
```

### Checker에 연결

```python
from clearance.checker import ClearanceChecker

custom_analyzer = MyCustomAnalyzer()
checker = ClearanceChecker(label_store, custom_analyzer)
```

### 하이브리드 Analyzer

```python
class HybridAnalyzer:
    """키워드 + LLM + 커스텀 조합"""

    def __init__(self, keyword_analyzer, llm_analyzer, custom_analyzer):
        self.keyword = keyword_analyzer
        self.llm = llm_analyzer
        self.custom = custom_analyzer

    def analyze(self, message, context):
        levels = [
            self.keyword.analyze(message, context),
            self.llm.analyze(message, context),
            self.custom.analyze(message, context),
        ]
        # 가장 높은 레벨 반환 (안전 우선)
        return max(levels)
```

## 2. 커스텀 LLM Backend

### 새 Provider 추가

```python
from clearance.llm_analyzer import LLMBackend

class AzureOpenAIBackend(LLMBackend):
    """Azure OpenAI 백엔드"""

    def __init__(self, endpoint: str, api_key: str, deployment: str):
        self.endpoint = endpoint
        self.api_key = api_key
        self.deployment = deployment
        self._client = None

        try:
            from openai import AzureOpenAI
            self._client = AzureOpenAI(
                azure_endpoint=endpoint,
                api_key=api_key,
                api_version="2024-02-01"
            )
        except ImportError:
            pass

    def is_available(self) -> bool:
        return self._client is not None

    def classify(self, prompt: str) -> str:
        response = self._client.chat.completions.create(
            model=self.deployment,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.1
        )
        return response.choices[0].message.content
```

### 로컬 모델 래퍼

```python
class HuggingFaceBackend(LLMBackend):
    """로컬 HuggingFace 모델"""

    def __init__(self, model_name: str):
        from transformers import pipeline
        self.classifier = pipeline("text-classification", model=model_name)

    def is_available(self) -> bool:
        return self.classifier is not None

    def classify(self, prompt: str) -> str:
        # 모델 출력을 JSON 형식으로 변환
        result = self.classifier(prompt)[0]
        level = self._label_to_level(result["label"])

        return json.dumps({
            "level": level,
            "confidence": result["score"],
            "reasoning": f"Classified as {result['label']}"
        })
```

## 3. 커스텀 Audit Backend

### 데이터베이스 백엔드

```python
from clearance.audit import AuditBackend, AuditEvent

class PostgresAuditBackend(AuditBackend):
    """PostgreSQL 감사 로그 백엔드"""

    def __init__(self, connection_string: str):
        import psycopg2
        self.conn = psycopg2.connect(connection_string)
        self._ensure_table()

    def _ensure_table(self):
        with self.conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS audit_events (
                    id SERIAL PRIMARY KEY,
                    event_type VARCHAR(50),
                    timestamp TIMESTAMP,
                    actor_id VARCHAR(100),
                    target_id VARCHAR(100),
                    message_level INTEGER,
                    allowed BOOLEAN,
                    violation_type VARCHAR(50),
                    details JSONB
                )
            """)
        self.conn.commit()

    def log(self, event: AuditEvent) -> None:
        with self.conn.cursor() as cur:
            cur.execute(
                """INSERT INTO audit_events
                   (event_type, timestamp, actor_id, target_id, message_level, allowed, violation_type, details)
                   VALUES (%s, %s, %s, %s, %s, %s, %s, %s)""",
                (event.event_type.value, event.timestamp, event.actor_id,
                 event.target_id, event.message_level.value if event.message_level else None,
                 event.allowed, event.violation_type, json.dumps(event.details))
            )
        self.conn.commit()

    def query(self, event_type=None, actor_id=None, start_time=None, end_time=None, limit=100):
        conditions = []
        params = []

        if event_type:
            conditions.append("event_type = %s")
            params.append(event_type.value)
        if actor_id:
            conditions.append("actor_id = %s")
            params.append(actor_id)
        if start_time:
            conditions.append("timestamp >= %s")
            params.append(start_time)
        if end_time:
            conditions.append("timestamp <= %s")
            params.append(end_time)

        where = "WHERE " + " AND ".join(conditions) if conditions else ""
        params.append(limit)

        with self.conn.cursor() as cur:
            cur.execute(f"""
                SELECT * FROM audit_events {where}
                ORDER BY timestamp DESC LIMIT %s
            """, params)
            return [self._row_to_event(row) for row in cur.fetchall()]
```

### Elasticsearch 백엔드

```python
class ElasticsearchAuditBackend(AuditBackend):
    """Elasticsearch 감사 로그 백엔드"""

    def __init__(self, hosts: list[str], index: str = "clearance-audit"):
        from elasticsearch import Elasticsearch
        self.es = Elasticsearch(hosts)
        self.index = index

    def log(self, event: AuditEvent) -> None:
        self.es.index(
            index=self.index,
            document=event.to_dict()
        )

    def query(self, **filters):
        body = {"query": {"bool": {"must": []}}}

        if filters.get("event_type"):
            body["query"]["bool"]["must"].append(
                {"term": {"event_type": filters["event_type"].value}}
            )

        if filters.get("start_time"):
            body["query"]["bool"]["must"].append(
                {"range": {"timestamp": {"gte": filters["start_time"].isoformat()}}}
            )

        result = self.es.search(index=self.index, body=body, size=filters.get("limit", 100))
        return [AuditEvent.from_dict(hit["_source"]) for hit in result["hits"]["hits"]]
```

## 4. 커스텀 Integration

### 새 메시징 플랫폼 연동

```python
from clearance.checker import ClearanceChecker
from clearance.models import User

class TeamsIntegration:
    """Microsoft Teams 연동"""

    def __init__(self, checker: ClearanceChecker, teams_token: str):
        self.checker = checker
        self.teams = TeamsClient(teams_token)
        self._user_cache = {}

    async def on_message(self, event: TeamsMessageEvent):
        sender = self._get_user(event.sender_id)
        recipients = self._get_recipients(event)

        for recipient in recipients:
            result = self.checker.check_write(event.text, recipient)

            if not result.allowed:
                await self._block_message(event, result)
                return

        await self._allow_message(event)

    def _get_user(self, user_id: str) -> User:
        if user_id not in self._user_cache:
            teams_user = self.teams.get_user(user_id)
            clearance = self._map_role_to_clearance(teams_user.role)
            self._user_cache[user_id] = User(user_id, teams_user.name, clearance)
        return self._user_cache[user_id]

    def _map_role_to_clearance(self, role: str) -> SecurityLevel:
        mapping = {
            "CEO": SecurityLevel.EXECUTIVE,
            "Manager": SecurityLevel.MANAGER,
            "Employee": SecurityLevel.STAFF,
            "Guest": SecurityLevel.PUBLIC,
        }
        return mapping.get(role, SecurityLevel.PUBLIC)
```

### Webhook 기반 연동

```python
from flask import Flask, request

app = Flask(__name__)
checker = create_checker({"confidential": SecurityLevel.MANAGER})

@app.route("/webhook/message", methods=["POST"])
def handle_message():
    data = request.json

    sender = get_user(data["sender_id"])
    recipient = get_user(data["recipient_id"])

    result = checker.check_write(data["message"], recipient)

    if not result.allowed:
        return {
            "status": "blocked",
            "violation": result.violation,
            "reason": result.reason
        }, 403

    # 원본 시스템에 전달
    forward_message(data)
    return {"status": "sent"}, 200
```

## 5. 커스텀 Security Level

### 레벨 확장

```python
from enum import IntEnum

class ExtendedSecurityLevel(IntEnum):
    """확장된 보안 레벨"""
    PUBLIC = 0
    INTERNAL = 1
    CONFIDENTIAL = 2
    SECRET = 3
    TOP_SECRET = 4
    COMPARTMENTED = 5  # 특수 구획

# 기존 코드와 호환
from clearance.models import SecurityLevel
SecurityLevel = ExtendedSecurityLevel
```

### 카테고리 추가 (Compartmentalization)

```python
@dataclass
class CompartmentedLabel:
    """구획화된 보안 라벨 (BLP 확장)"""
    level: SecurityLevel
    compartments: set[str]  # e.g., {"PROJECT-X", "ALPHA"}
    source: str

    def can_access(self, user_clearance: SecurityLevel, user_compartments: set[str]) -> bool:
        # 레벨 충족
        if user_clearance < self.level:
            return False
        # 모든 구획 보유
        if not self.compartments.issubset(user_compartments):
            return False
        return True
```

## 6. 테스트 유틸리티

### Fixture Factory

```python
import pytest

@pytest.fixture
def clearance_env():
    """완전한 테스트 환경 제공"""
    store = LabelStore()
    store.add_keyword("secret", Label(SecurityLevel.EXECUTIVE))
    store.add_keyword("internal", Label(SecurityLevel.STAFF))

    analyzer = MessageAnalyzer(store)
    checker = ClearanceChecker(store, analyzer)
    audit = AuditLogger()

    users = {
        "exec": User("e1", "Exec", SecurityLevel.EXECUTIVE),
        "mgr": User("m1", "Manager", SecurityLevel.MANAGER),
        "staff": User("s1", "Staff", SecurityLevel.STAFF),
    }

    return {
        "store": store,
        "analyzer": analyzer,
        "checker": checker,
        "audit": audit,
        "users": users,
    }

def test_complex_scenario(clearance_env):
    checker = clearance_env["checker"]
    users = clearance_env["users"]

    result = checker.check_write("This is secret", users["staff"])
    assert not result.allowed
```

### Property-based Testing

```python
from hypothesis import given, strategies as st

@given(
    message=st.text(min_size=1, max_size=100),
    sender_level=st.sampled_from(list(SecurityLevel)),
    recipient_level=st.sampled_from(list(SecurityLevel)),
)
def test_blp_property(message, sender_level, recipient_level):
    """BLP 속성 검증: 높은 레벨 → 낮은 레벨 불가"""
    checker = create_checker()  # 키워드 없음

    sender = User("s", "Sender", sender_level)
    recipient = User("r", "Recipient", recipient_level)

    # 키워드가 없으면 모든 메시지는 PUBLIC
    result = checker.check_write(message, recipient)

    # PUBLIC은 항상 허용
    assert result.allowed
```
