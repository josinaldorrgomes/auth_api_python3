"""Códigos de uso único (OTP) enviados fora de banda: geração, armazenamento e verificação."""
import hashlib
import hmac
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Callable

from .config import Settings
from .domain import OtpChallenge, OtpPurpose
from .repositories import OtpRepository

Clock = Callable[[], datetime]


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class OtpError(Exception):
    """Código inválido, expirado, já usado ou com tentativas esgotadas."""


class OtpCooldownError(Exception):
    def __init__(self, retry_after_s: int) -> None:
        super().__init__(f"retry after {retry_after_s}s")
        self.retry_after_s = retry_after_s


class OtpService:
    def __init__(self, repo: OtpRepository, settings: Settings,
                 clock: Clock = utc_now) -> None:
        self._repo, self._s, self._now = repo, settings, clock
        self._pepper = settings.otp_pepper.get_secret_value().encode()

    def _hash(self, challenge_id: str, code: str) -> str:
        # HMAC com "pepper" do servidor: 10^6 códigos são poucos, então um hash simples
        # vazado do banco seria quebrado instantaneamente. Sem o pepper, não é.
        return hmac.new(self._pepper, f"{challenge_id}:{code}".encode(),
                        hashlib.sha256).hexdigest()

    def issue(self, user_id: str, purpose: OtpPurpose) -> str:
        now = self._now()
        last = self._repo.latest(user_id, purpose)
        if last is not None:
            elapsed = (now - last.created_at).total_seconds()
            if elapsed < self._s.otp_resend_cooldown_s:      # anti-spam / anti-custo
                raise OtpCooldownError(int(self._s.otp_resend_cooldown_s - elapsed) + 1)

        code = f"{secrets.randbelow(10 ** self._s.otp_length):0{self._s.otp_length}d}"
        challenge_id = str(uuid.uuid4())
        self._repo.add(OtpChallenge(
            id=challenge_id, user_id=user_id, purpose=purpose,
            code_hash=self._hash(challenge_id, code), created_at=now,
            expires_at=now + timedelta(seconds=self._s.otp_ttl_s)))
        return code                         # só o canal de entrega vê o código em claro

    def verify(self, user_id: str, purpose: OtpPurpose, code: str) -> None:
        ch = self._repo.latest(user_id, purpose)   # só o desafio mais recente vale
        if ch is None or ch.consumed or self._now() >= ch.expires_at:
            raise OtpError("no active challenge")
        if ch.attempts >= self._s.otp_max_attempts:
            raise OtpError("too many attempts")
        self._repo.increment_attempts(ch.id)       # conta ANTES de comparar
        if not hmac.compare_digest(ch.code_hash, self._hash(ch.id, code.strip())):
            raise OtpError("wrong code")
        self._repo.mark_consumed(ch.id)            # uso único
