"""Primitivas de segurança: hashing de senha, JWT e API keys."""
import hashlib
import hmac
import secrets
import uuid
from datetime import datetime, timedelta, timezone

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError

from .config import Settings
from .domain import ApiKey, Principal


class AuthError(Exception):
    """Erro genérico de autenticação: nunca revela o motivo exato ao cliente."""


class PasswordService:
    """Argon2id — vencedor da Password Hashing Competition, recomendado pela OWASP."""

    def __init__(self) -> None:
        self._ph = PasswordHasher()  # salt aleatório + parâmetros seguros por padrão

    def hash(self, password: str) -> str:
        return self._ph.hash(password)

    def verify(self, password_hash: str, password: str) -> bool:
        try:
            return self._ph.verify(password_hash, password)
        except (VerifyMismatchError, InvalidHashError):
            return False


class TokenService:
    """Emite e valida JWT (RFC 7519). O claim 'token_use' separa os tipos de token."""

    ACCESS = "access"
    MFA_PENDING = "mfa_pending"

    def __init__(self, settings: Settings) -> None:
        self._s = settings

    def issue(self, subject: str, scopes: frozenset[str], amr: frozenset[str],
              token_use: str = ACCESS) -> str:
        ttl = (self._s.access_token_ttl_min if token_use == self.ACCESS
               else self._s.mfa_token_ttl_min)
        now = datetime.now(timezone.utc)
        claims = {
            "sub": subject,
            "iss": self._s.jwt_issuer,
            "aud": self._s.jwt_audience,
            "iat": now,
            "nbf": now,
            "exp": now + timedelta(minutes=ttl),
            "jti": str(uuid.uuid4()),           # permite revogação por denylist
            "token_use": token_use,
            "scope": " ".join(sorted(scopes)),
            "amr": sorted(amr),                 # métodos usados: ["otp", "pwd"]
        }
        return jwt.encode(claims, self._s.jwt_secret.get_secret_value(),
                          algorithm=self._s.jwt_algorithm)

    def verify(self, token: str, expected_use: str = ACCESS) -> Principal:
        try:
            claims = jwt.decode(
                token,
                self._s.jwt_secret.get_secret_value(),
                algorithms=[self._s.jwt_algorithm],   # lista fixa: bloqueia "alg=none"
                audience=self._s.jwt_audience,
                issuer=self._s.jwt_issuer,
                options={"require": ["exp", "iat", "sub", "aud", "iss"]},
            )
        except jwt.PyJWTError as exc:
            raise AuthError("invalid token") from exc
        if claims.get("token_use") != expected_use:   # mfa_token não vale como acesso
            raise AuthError("wrong token type")
        return Principal(subject=claims["sub"],
                         scopes=frozenset(claims.get("scope", "").split()),
                         auth_method="jwt",
                         amr=frozenset(claims.get("amr", [])))


class ApiKeyService:
    """API keys no formato <prefixo><key_id>.<segredo>; só o hash do segredo é salvo."""

    def __init__(self, settings: Settings) -> None:
        self._prefix = settings.api_key_prefix

    @staticmethod
    def _digest(secret: str) -> str:
        # Segredo tem 256 bits de entropia: SHA-256 basta (não é senha humana)
        return hashlib.sha256(secret.encode()).hexdigest()

    def generate(self, owner_id: str, scopes: frozenset[str]) -> tuple[str, ApiKey]:
        key_id = secrets.token_hex(8)
        secret = secrets.token_urlsafe(32)          # CSPRNG, nunca random.random()
        plaintext = f"{self._prefix}{key_id}.{secret}"
        record = ApiKey(key_id=key_id, secret_hash=self._digest(secret),
                        owner_id=owner_id, scopes=scopes)
        return plaintext, record                    # plaintext é exibido UMA única vez

    def parse(self, presented: str) -> tuple[str, str]:
        if not presented.startswith(self._prefix) or "." not in presented:
            raise AuthError("malformed key")
        key_id, secret = presented.removeprefix(self._prefix).split(".", 1)
        return key_id, secret

    def matches(self, record: ApiKey, secret: str) -> bool:
        # Comparação em tempo constante: evita ataque de timing
        return hmac.compare_digest(record.secret_hash, self._digest(secret))
