"""Canais de entrega do código (Strategy + Factory).

Todos implementam a mesma interface `Notifier`; trocar de canal é só mudar AUTH_MFA_CHANNEL.
  - console           : imprime no terminal (desenvolvimento e testes)
  - telegram_gateway  : envia o código ao NÚMERO DE TELEFONE via Telegram Gateway
                        (gratuito quando o destino é o seu próprio número)
  - email             : SMTP (Gmail com senha de app, Brevo etc.)
"""
import logging
import smtplib
from email.message import EmailMessage
from typing import Protocol

import httpx

from .config import Settings
from .domain import User

log = logging.getLogger("mfa")


class DeliveryError(Exception):
    """O canal não conseguiu entregar o código."""


class Notifier(Protocol):
    channel: str

    def send_code(self, user: User, code: str, ttl_s: int) -> str:
        """Envia o código e devolve o destino mascarado (ex.: +55******8888)."""
        ...


def mask_phone(phone: str) -> str:
    return phone[:3] + "*" * (len(phone) - 7) + phone[-4:]


def mask_email(email: str) -> str:
    name, _, domain = email.partition("@")
    return f"{name[:2]}***@{domain}"


class ConsoleNotifier:
    channel = "console"

    def send_code(self, user: User, code: str, ttl_s: int) -> str:
        # Apenas para desenvolvimento: NUNCA registre códigos em log em produção.
        print(f"\n[MFA] código para {user.username} ({user.phone}): {code} "
              f"(expira em {ttl_s // 60} min)\n", flush=True)
        return mask_phone(user.phone)


class TelegramGatewayNotifier:
    """https://core.telegram.org/gateway/api — entrega por número de telefone (E.164)."""
    channel = "telegram_gateway"
    URL = "https://gatewayapi.telegram.org/sendVerificationMessage"

    def __init__(self, token: str, client: httpx.Client | None = None) -> None:
        self._client = client or httpx.Client(timeout=10.0)
        self._headers = {"Authorization": f"Bearer {token}"}

    def send_code(self, user: User, code: str, ttl_s: int) -> str:
        payload = {"phone_number": user.phone, "code": code, "ttl": ttl_s}
        try:
            resp = self._client.post(self.URL, json=payload, headers=self._headers)
            data = resp.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise DeliveryError("telegram gateway unreachable") from exc
        if not data.get("ok"):
            log.warning("telegram gateway error: %s", data.get("error"))
            raise DeliveryError(str(data.get("error", "unknown error")))
        return mask_phone(user.phone)


class EmailNotifier:
    channel = "email"

    def __init__(self, host: str, port: int, username: str, password: str,
                 sender: str, use_tls: bool = True) -> None:
        self._host, self._port = host, port
        self._username, self._password = username, password
        self._sender, self._use_tls = sender, use_tls

    def send_code(self, user: User, code: str, ttl_s: int) -> str:
        if not user.email:
            raise DeliveryError("user has no e-mail")
        msg = EmailMessage()
        msg["From"], msg["To"] = self._sender, user.email
        msg["Subject"] = f"{code} é o seu código de verificação"
        msg.set_content(
            f"Olá, {user.username}!\n\nSeu código de verificação é: {code}\n"
            f"Ele expira em {ttl_s // 60} minutos. Não compartilhe este código.\n\n"
            "Se você não tentou entrar, troque sua senha imediatamente.")
        try:
            with smtplib.SMTP(self._host, self._port, timeout=10) as smtp:
                if self._use_tls:
                    smtp.starttls()                  # nunca envie credenciais sem TLS
                if self._username:
                    smtp.login(self._username, self._password)
                smtp.send_message(msg)
        except (smtplib.SMTPException, OSError) as exc:
            raise DeliveryError("smtp failure") from exc
        return mask_email(user.email)


def build_notifier(s: Settings) -> Notifier:
    """Factory: escolhe a estratégia de entrega a partir da configuração."""
    if s.mfa_channel == "telegram_gateway":
        if not s.telegram_gateway_token:
            raise RuntimeError("Defina AUTH_TELEGRAM_GATEWAY_TOKEN")
        return TelegramGatewayNotifier(s.telegram_gateway_token.get_secret_value())
    if s.mfa_channel == "email":
        if not (s.smtp_user and s.smtp_password and s.smtp_sender):
            raise RuntimeError("Defina AUTH_SMTP_USER, AUTH_SMTP_PASSWORD e AUTH_SMTP_SENDER")
        return EmailNotifier(s.smtp_host, s.smtp_port, s.smtp_user,
                             s.smtp_password.get_secret_value(), s.smtp_sender)
    return ConsoleNotifier()
