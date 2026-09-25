"""Testes dos canais reais de entrega, sem depender de internet."""
import json
import socket
import time

import httpx
import pytest
from aiosmtpd.controller import Controller

from app.domain import Role, User
from app.notifications import DeliveryError, EmailNotifier, TelegramGatewayNotifier, build_notifier

from .conftest import make_settings

USER = User(id="u1", username="ana", password_hash="x", role=Role.VIEWER,
            phone="+5562999998888", email="ana@exemplo.com")


# ---------------------------- Telegram Gateway ----------------------------
def test_telegram_gateway_sends_code_to_phone():
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["url"] = str(request.url)
        seen["auth"] = request.headers["Authorization"]
        seen["body"] = json.loads(request.content)
        return httpx.Response(200, json={"ok": True, "result": {"request_id": "abc"}})

    n = TelegramGatewayNotifier("TOKEN123", client=httpx.Client(transport=httpx.MockTransport(handler)))
    masked = n.send_code(USER, "482913", 300)
    assert seen["url"] == "https://gatewayapi.telegram.org/sendVerificationMessage"
    assert seen["auth"] == "Bearer TOKEN123"
    assert seen["body"] == {"phone_number": "+5562999998888", "code": "482913", "ttl": 300}
    assert masked == "+55*******8888" and "9999" not in masked


def test_telegram_gateway_error_becomes_delivery_error():
    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"ok": False, "error": "PHONE_NUMBER_INVALID"})

    n = TelegramGatewayNotifier("T", client=httpx.Client(transport=httpx.MockTransport(handler)))
    with pytest.raises(DeliveryError):
        n.send_code(USER, "123456", 300)


# ---------------------------- E-mail (servidor SMTP local real) ----------------------------
class Inbox:
    def __init__(self) -> None:
        self.messages: list[str] = []

    async def handle_DATA(self, server, session, envelope):
        self.messages.append(envelope.content.decode())
        return "250 OK"


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def test_email_notifier_delivers_via_smtp():
    inbox, port = Inbox(), _free_port()
    ctl = Controller(inbox, hostname="127.0.0.1", port=port)
    ctl.start()
    try:
        n = EmailNotifier("127.0.0.1", port, "", "", "aula@unievangelica.local", use_tls=False)
        masked = n.send_code(USER, "731055", 300)
        time.sleep(0.2)
    finally:
        ctl.stop()
    assert masked == "an***@exemplo.com"
    assert len(inbox.messages) == 1 and "731055" in inbox.messages[0]


def test_email_notifier_requires_user_email():
    n = EmailNotifier("127.0.0.1", 1, "", "", "x@y.z", use_tls=False)
    with pytest.raises(DeliveryError):
        n.send_code(User(id="u", username="b", password_hash="x", role=Role.VIEWER,
                         phone="+5562999998888"), "123456", 300)


# ---------------------------- Factory ----------------------------
def test_factory_picks_strategy_and_fails_fast_without_secrets():
    assert build_notifier(make_settings()).channel == "console"
    assert build_notifier(make_settings(mfa_channel="telegram_gateway",
                                        telegram_gateway_token="t")).channel == "telegram_gateway"
    with pytest.raises(RuntimeError):
        build_notifier(make_settings(mfa_channel="email"))
