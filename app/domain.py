"""Modelos de domínio: independentes de framework e de banco (Arquitetura Hexagonal)."""
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum


class Role(str, Enum):
    ADMIN = "admin"
    DATA_SCIENTIST = "data_scientist"
    VIEWER = "viewer"


# RBAC: cada papel recebe um conjunto de permissões (scopes)
ROLE_SCOPES: dict[Role, frozenset[str]] = {
    Role.ADMIN: frozenset({"models:read", "models:predict", "models:deploy", "keys:create"}),
    Role.DATA_SCIENTIST: frozenset({"models:read", "models:predict", "keys:create"}),
    Role.VIEWER: frozenset({"models:read"}),
}


class OtpPurpose(str, Enum):
    ENROLL = "enroll"   # confirmar a posse do telefone no cadastro
    LOGIN = "login"     # segundo fator no login


@dataclass(frozen=True)
class User:
    id: str
    username: str
    password_hash: str
    role: Role
    phone: str                      # formato E.164, ex.: +5562999998888
    email: str | None = None
    phone_verified: bool = False
    mfa_enabled: bool = False
    active: bool = True


@dataclass(frozen=True)
class OtpChallenge:
    id: str
    user_id: str
    purpose: OtpPurpose
    code_hash: str                  # nunca guardamos o código em texto claro
    created_at: datetime
    expires_at: datetime
    attempts: int = 0
    consumed: bool = False


@dataclass(frozen=True)
class ApiKey:
    key_id: str                     # parte pública (lookup)
    secret_hash: str                # só o hash do segredo é armazenado
    owner_id: str
    scopes: frozenset[str]
    revoked: bool = False


@dataclass(frozen=True)
class Principal:
    """Quem está chamando a API, após autenticação — seja usuário ou máquina."""
    subject: str
    scopes: frozenset[str] = field(default_factory=frozenset)
    auth_method: str = "unknown"
    amr: frozenset[str] = field(default_factory=frozenset)   # RFC 8176: pwd, otp...

    def has(self, *required: str) -> bool:
        return set(required).issubset(self.scopes)

    @property
    def mfa(self) -> bool:
        return "otp" in self.amr
