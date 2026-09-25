from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.domain import User
from app.main import create_app


class FakeNotifier:
    """Test double: captura o código em vez de enviá-lo."""
    channel = "fake"

    def __init__(self) -> None:
        self.sent: list[tuple[str, str]] = []

    def send_code(self, user: User, code: str, ttl_s: int) -> str:
        self.sent.append((user.phone, code))
        return "+55******8888"

    @property
    def last_code(self) -> str:
        return self.sent[-1][1]


class FakeClock:
    def __init__(self) -> None:
        self.now = datetime(2026, 9, 25, 12, 0, tzinfo=timezone.utc)

    def __call__(self) -> datetime:
        return self.now

    def advance(self, seconds: int) -> None:
        self.now += timedelta(seconds=seconds)


def make_settings(**kw) -> Settings:
    base = dict(jwt_secret="test-jwt-secret-" + "x" * 40, otp_pepper="test-pepper-" + "y" * 40,
                database_url=":memory:", mfa_channel="console")
    base.update(kw)
    return Settings(**base)


@pytest.fixture
def notifier() -> FakeNotifier:
    return FakeNotifier()


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def client(notifier, clock) -> TestClient:
    return TestClient(create_app(make_settings(), notifier=notifier, clock=clock))


PHONE = "+5562999998888"
PWD = "cavalo-bateria-grampo-correto"


def register(client, username="ana", password=PWD, phone=PHONE, email=None):
    return client.post("/users", json={"username": username, "password": password,
                                       "phone": phone, "email": email})


def login(client, username="ana", password=PWD):
    return client.post("/auth/token", data={"username": username, "password": password})


def bearer(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def enroll(client, notifier, clock, username="ana") -> None:
    """Cadastro completo: registra, faz login sem MFA e confirma o telefone."""
    assert register(client, username=username).status_code == 201
    token = login(client, username).json()["access_token"]
    assert client.post("/me/phone/verification", headers=bearer(token)).status_code == 200
    r = client.post("/me/phone/verification/confirm", json={"code": notifier.last_code},
                    headers=bearer(token))
    assert r.status_code == 200 and r.json()["mfa_enabled"] is True
    clock.advance(61)   # passa o cooldown de reenvio


def full_login(client, notifier, username="ana") -> str:
    r = login(client, username)
    assert r.status_code == 200 and r.json()["mfa_required"] is True
    r = client.post("/auth/mfa/verify", json={"mfa_token": r.json()["mfa_token"],
                                              "code": notifier.last_code})
    assert r.status_code == 200, r.text
    return r.json()["access_token"]
