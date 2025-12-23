# Integrations

외부 시스템 연동 구현을 설명합니다.

## 1. Slack Integration (`integrations/slack/bot.py`)

### 아키텍처

```
Slack Events API
      │
      ▼
┌─────────────────┐
│ ClearanceSlackBot│
│                 │
│  ┌───────────┐  │
│  │ UserStore │  │  ← 사용자-clearance 매핑
│  └───────────┘  │
│        │        │
│  ┌─────▼─────┐  │
│  │  Checker  │  │  ← BLP 검증
│  └───────────┘  │
│        │        │
│  ┌─────▼─────┐  │
│  │  Handlers │  │  ← 위반/메시지 핸들러
│  └───────────┘  │
└─────────────────┘
      │
      ▼
Slack WebClient
```

### User Store

```python
class InMemoryUserStore:
    _users: dict[str, SlackUser]      # slack_id → user
    _by_email: dict[str, str]         # email → slack_id

    def add(self, user: SlackUser):
        self._users[user.slack_id] = user
        if user.email:
            self._by_email[user.email.lower()] = user.slack_id
```

### 메시지 인터셉트

```python
def intercept_message(self, event: SlackMessageEvent) -> InterceptResult:
    # 1. 발신자 정보 조회
    sender = self.user_store.get(event.sender_id) or default_user

    # 2. 수신자 결정 (멘션 기반)
    recipient = self.get_recipient_from_channel(event.channel, event.mentioned_users)

    # 3. BLP 검증
    result = self.checker.check_write(event.text, recipient)

    # 4. 위반 처리
    if not result.allowed:
        self._handle_violation(event, result)

    # 5. 핸들러 호출
    for handler in self._message_handlers:
        handler(event, intercept_result)

    return intercept_result
```

### 수신자 결정 로직

```python
def get_recipient_from_channel(self, channel, mentioned_users):
    if mentioned_users:
        # 멘션된 사용자 중 가장 낮은 clearance
        min_clearance = EXECUTIVE
        min_user = None

        for user_id in mentioned_users:
            user = self.user_store.get(user_id)
            if user and user.clearance < min_clearance:
                min_clearance = user.clearance
                min_user = user

        return min_user.to_user() if min_user else None

    # 멘션 없으면 채널 = PUBLIC으로 가정
    return User(id=channel, name=f"Channel {channel}", clearance=PUBLIC)
```

### Block Modes

```python
class BlockMode(Enum):
    SILENT = "silent"           # 조용히 차단
    NOTIFY_SENDER = "notify"    # 발신자에게 알림
    NOTIFY_ADMIN = "admin"      # 발신자 + 관리자 알림
    REPLACE = "replace"         # 삭제된 버전으로 대체
```

### 알림 메시지

```python
def _notify_sender(self, event, result):
    blocks = [
        {
            "type": "section",
            "text": {"type": "mrkdwn", "text": ":lock: *Message Blocked*"}
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Violation:*\n{result.violation}"},
                {"type": "mrkdwn", "text": f"*Level:*\n{result.message_level.name}"},
            ]
        }
    ]

    self._client.chat_postMessage(
        channel=event.sender_id,  # DM으로 전송
        blocks=blocks
    )
```

## 2. Email Integration (`integrations/email/gateway.py`)

### 아키텍처

```
Application
    │
    ▼
┌─────────────────┐
│  EmailGateway   │
│                 │
│  ┌───────────┐  │
│  │ UserLookup│  │  ← 이메일→User 매핑
│  └───────────┘  │
│        │        │
│  ┌─────▼─────┐  │
│  │  Checker  │  │  ← BLP 검증
│  └───────────┘  │
│        │        │
│  ┌─────▼─────┐  │
│  │  Backend  │  │  ← SMTP/Mock
│  └───────────┘  │
└─────────────────┘
    │
    ▼
SMTP Server
```

### 이메일 검증 흐름

```python
def check(self, message: EmailMessage) -> EmailCheckResult:
    # 1. 메시지 보안 레벨 분석
    content = f"{message.subject}\n{message.body}"
    message_level = self.checker.get_minimum_clearance(content)

    allowed = []
    blocked = []

    # 2. 각 수신자 검증
    for email in message.all_recipients():
        user = self._user_lookup.get_by_email(email)
        if not user:
            user = User(id=email, name=email, clearance=self.default_clearance)

        result = self.checker.check_write(content, user)

        if result.allowed:
            allowed.append(email)
        else:
            blocked.append(email)

    # 3. 결과 반환
    return EmailCheckResult(
        allowed=len(allowed) > 0,
        allowed_recipients=allowed,
        blocked_recipients=blocked,
        message_level=message_level
    )
```

### 부분 전송

```python
def send(self, message, send_to_allowed_only=True):
    result = self.check(message)

    if not result.allowed and not send_to_allowed_only:
        return result

    # 허용된 수신자만으로 새 메시지 생성
    send_message = EmailMessage(
        subject=message.subject,
        body=message.body,
        sender=message.sender,
        recipients=[r for r in message.recipients if r in result.allowed_recipients],
        cc=[r for r in message.cc if r in result.allowed_recipients],
        bcc=[r for r in message.bcc if r in result.allowed_recipients],
    )

    # 보안 헤더 추가
    if self.add_security_header:
        send_message.headers["X-Security-Level"] = result.message_level.name

    success = self.backend.send(send_message)
    return EmailCheckResult(allowed=success, ...)
```

### Backend 인터페이스

```python
class EmailBackend(ABC):
    @abstractmethod
    def send(self, message: EmailMessage) -> bool: ...

    @abstractmethod
    def is_available(self) -> bool: ...


class SMTPEmailBackend(EmailBackend):
    def send(self, message):
        with smtplib.SMTP(self.host, self.port) as server:
            if self.use_tls:
                server.starttls()
            if self.username:
                server.login(self.username, self.password)
            server.sendmail(message.sender, message.all_recipients(), msg.as_string())


class MockEmailBackend(EmailBackend):
    _sent: list[EmailMessage]

    def send(self, message):
        self._sent.append(message)
        return True
```

## 통합 패턴

### 1. Middleware 패턴

```python
# 모든 아웃바운드 통신에 적용
class ClearanceMiddleware:
    def __init__(self, checker):
        self.checker = checker

    def send(self, channel, message, recipient):
        result = self.checker.check_write(message, recipient)

        if not result.allowed:
            raise SecurityViolation(result)

        return channel.send(message)
```

### 2. Decorator 패턴

```python
def clearance_checked(checker):
    def decorator(func):
        @wraps(func)
        def wrapper(message, recipient, *args, **kwargs):
            result = checker.check_write(message, recipient)
            if not result.allowed:
                raise SecurityViolation(result)
            return func(message, recipient, *args, **kwargs)
        return wrapper
    return decorator

@clearance_checked(checker)
def send_email(message, recipient):
    ...
```

### 3. Event-driven 패턴

```python
class MessageBus:
    def __init__(self, checker, audit_logger):
        self.checker = checker
        self.audit = audit_logger

    def publish(self, sender, recipient, message):
        result = self.checker.check_write(message, recipient)

        self.audit.log_message_check(sender, recipient, result)

        if result.allowed:
            self._dispatch(message, recipient)
        else:
            self._handle_violation(sender, result)
```

## 테스트 전략

### Mock 사용

```python
def test_slack_bot():
    checker = create_checker({"secret": EXECUTIVE})
    user_store = InMemoryUserStore()
    user_store.add(SlackUser("U1", "Staff", STAFF))

    bot = ClearanceSlackBot(
        checker=checker,
        user_store=user_store,
        _skip_sdk_check=True  # Slack SDK 없이 테스트
    )

    event = SlackMessageEvent(
        channel="C1",
        sender_id="U_MGR",
        text="This is secret info",
        mentioned_users=["U1"]
    )

    result = bot.intercept_message(event)
    assert not result.allowed
```

### Email Gateway 테스트

```python
def test_email_gateway():
    checker = create_checker({"confidential": MANAGER})
    backend = MockEmailBackend()

    gateway = EmailGateway(checker, backend)
    gateway.user_lookup.add("staff@co.com", User("s", "Staff", STAFF))

    result = gateway.send(EmailMessage(
        subject="Confidential",
        body="This is confidential",
        sender="agent@co.com",
        recipients=["staff@co.com"]
    ))

    assert not result.allowed
    assert len(backend.get_sent()) == 0  # 전송 안 됨
```
