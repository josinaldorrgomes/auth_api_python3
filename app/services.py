"""Casos de uso (camada de aplicação): cadastro, verificação de telefone, login com MFA."""
import re
import uuid
from dataclasses import dataclass, replace
from typing import Protocol

from .config import Settings
from .domain import ROLE_SCOPES, OtpPurpose, Principal, Role, User
from .notifications import Notifier
from .otp import OtpService
from .repositories import ApiKeyRepository, UserRepository
from .security import ApiKeyService, AuthError, PasswordService, TokenService

E164 = re.compile(r"^\+[1-9]\d{7,14}$")            # ex.: +5562999998888
COMMON_PASSWORDS = {"123456789012345", "senhasenhasenha", "qwertyuiopasdfg",
                    "passwordpassword", "unievangelica123"}   # em produção: lista de vazadas


class ValidationError(Exception):
    pass


@dataclass(frozen=True)
class LoginResult:
    access_token: str | None = None      # login concluído
    mfa_token: str | None = None         # senha OK, falta o segundo fator
    sent_to: str | None = None


class AccountService:
    def __init__(self, users: UserRepository, passwords: PasswordService, otp: OtpService,
                 notifier: Notifier, settings: Settings) -> None:
        self._users, self._passwords, self._otp = users, passwords, otp
        self._notifier, self._s = notifier, settings

    def register(self, username: str, password: str, phone: str, email: str | None) -> User:
        if not E164.match(phone):
            raise ValidationError("Telefone deve estar no formato E.164, ex.: +5562999998888")
        if len(password) < self._s.password_min_length:
            raise ValidationError(f"Senha deve ter ao menos {self._s.password_min_length} caracteres")
        if password.lower() in COMMON_PASSWORDS or username.lower() in password.lower():
            raise ValidationError("Senha muito comum ou contém o nome de usuário")
        user = User(id=str(uuid.uuid4()), username=username,
                    password_hash=self._passwords.hash(password),
                    role=Role(self._s.default_role), phone=phone, email=email)
        self._users.add(user)
        return user

    def start_phone_verification(self, user_id: str) -> str:
        user = self._require(user_id)
        code = self._otp.issue(user.id, OtpPurpose.ENROLL)
        return self._notifier.send_code(user, code, self._s.otp_ttl_s)

    def confirm_phone(self, user_id: str, code: str) -> User:
        user = self._require(user_id)
        self._otp.verify(user.id, OtpPurpose.ENROLL, code)
        updated = replace(user, phone_verified=True, mfa_enabled=True)
        self._users.update(updated)
        return updated

    def _require(self, user_id: str) -> User:
        user = self._users.by_id(user_id)
        if user is None or not user.active:
            raise AuthError("unknown user")
        return user


# Hash "isca": verificar mesmo quando o usuário não existe iguala o tempo de resposta
_DUMMY_HASH = PasswordService().hash("dummy-password-for-timing")


class LoginService:
    def __init__(self, users: UserRepository, passwords: PasswordService, tokens: TokenService,
                 otp: OtpService, notifier: Notifier, settings: Settings) -> None:
        self._users, self._passwords, self._tokens = users, passwords, tokens
        self._otp, self._notifier, self._s = otp, notifier, settings

    def login(self, username: str, password: str) -> LoginResult:
        user = self._users.by_username(username)
        ok = self._passwords.verify(user.password_hash if user else _DUMMY_HASH, password)
        if not (user and ok and user.active):
            raise AuthError("invalid credentials")        # mesma mensagem para tudo

        if not user.mfa_enabled:                           # ainda não cadastrou o 2º fator
            return LoginResult(access_token=self._access(user, {"pwd"}))

        code = self._otp.issue(user.id, OtpPurpose.LOGIN)
        sent_to = self._notifier.send_code(user, code, self._s.otp_ttl_s)
        mfa_token = self._tokens.issue(user.id, frozenset(), frozenset({"pwd"}),
                                       token_use=TokenService.MFA_PENDING)
        return LoginResult(mfa_token=mfa_token, sent_to=sent_to)

    def verify_mfa(self, mfa_token: str, code: str) -> str:
        pending = self._tokens.verify(mfa_token, expected_use=TokenService.MFA_PENDING)
        user = self._users.by_id(pending.subject)
        if user is None or not user.active:
            raise AuthError("unknown user")
        self._otp.verify(user.id, OtpPurpose.LOGIN, code)
        return self._access(user, {"pwd", "otp"})

    def _access(self, user: User, amr: set[str]) -> str:
        return self._tokens.issue(user.id, ROLE_SCOPES[user.role], frozenset(amr))


class Authenticator(Protocol):
    """Strategy: cada mecanismo de autenticação implementa a mesma interface."""
    def authenticate(self, credential: str) -> Principal: ...


class JwtAuthenticator:
    def __init__(self, tokens: TokenService) -> None:
        self._tokens = tokens

    def authenticate(self, credential: str) -> Principal:
        return self._tokens.verify(credential)


class ApiKeyAuthenticator:
    def __init__(self, keys: ApiKeyRepository, service: ApiKeyService) -> None:
        self._keys, self._service = keys, service

    def authenticate(self, credential: str) -> Principal:
        key_id, secret = self._service.parse(credential)
        record = self._keys.get(key_id)
        valid = record is not None and not record.revoked
        if not (valid and self._service.matches(record, secret)):
            raise AuthError("invalid api key")
        return Principal(subject=f"key:{record.key_id}", scopes=record.scopes,
                         auth_method="api_key")


def authorize(principal: Principal, *required: str, mfa: bool = False) -> None:
    """Política de autorização central (Policy Decision Point simplificado)."""
    if not principal.has(*required):
        raise PermissionError("missing scopes")
    if mfa and not principal.mfa:                  # step-up: ação sensível exige 2º fator
        raise PermissionError("mfa required")
