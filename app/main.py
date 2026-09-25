"""Camada HTTP (adaptador): FastAPI + Composition Root.

Execute com:  uvicorn app.main:create_app --factory --reload
"""
from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException, Request, Security, status
from fastapi.responses import JSONResponse
from fastapi.security import (APIKeyHeader, HTTPAuthorizationCredentials, HTTPBearer,
                              OAuth2PasswordRequestForm)
from pydantic import BaseModel, EmailStr, Field

from .config import Settings, get_settings
from .domain import Principal
from .notifications import DeliveryError, Notifier, build_notifier
from .otp import Clock, OtpCooldownError, OtpError, OtpService, utc_now
from .repositories import (Database, DuplicateError, SqliteApiKeyRepository,
                           SqliteOtpRepository, SqliteUserRepository)
from .security import ApiKeyService, AuthError, PasswordService, TokenService
from .services import (AccountService, ApiKeyAuthenticator, JwtAuthenticator, LoginService,
                       ValidationError, authorize)


# ------------------------------- Schemas (DTOs) -------------------------------
class RegisterIn(BaseModel):
    username: str = Field(min_length=3, max_length=32, pattern=r"^[a-z0-9_.]+$")
    password: str = Field(max_length=128)
    phone: str = Field(examples=["+5562999998888"])
    email: EmailStr | None = None


class UserOut(BaseModel):
    id: str
    username: str
    phone_verified: bool
    mfa_enabled: bool


class CodeIn(BaseModel):
    code: str = Field(pattern=r"^\d{4,8}$")


class MfaVerifyIn(CodeIn):
    mfa_token: str


class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int


class MfaChallengeOut(BaseModel):
    mfa_required: bool = True
    mfa_token: str
    sent_to: str
    expires_in: int


class SentOut(BaseModel):
    sent_to: str
    expires_in: int


class ApiKeyOut(BaseModel):
    api_key: str
    note: str = "Guarde agora: esta chave não será exibida novamente."


class PredictIn(BaseModel):
    features: list[float] = Field(min_length=1, max_length=100)


# ------------------------------- Composition Root -----------------------------
def create_app(settings: Settings | None = None, notifier: Notifier | None = None,
               clock: Clock = utc_now) -> FastAPI:
    s = settings or get_settings()
    db = Database(s.database_url)
    users, api_keys = SqliteUserRepository(db), SqliteApiKeyRepository(db)
    passwords, tokens, key_service = PasswordService(), TokenService(s), ApiKeyService(s)
    otp = OtpService(SqliteOtpRepository(db), s, clock)
    notifier = notifier or build_notifier(s)
    accounts = AccountService(users, passwords, otp, notifier, s)
    logins = LoginService(users, passwords, tokens, otp, notifier, s)
    jwt_auth, key_auth = JwtAuthenticator(tokens), ApiKeyAuthenticator(api_keys, key_service)

    app = FastAPI(title="IA Model API — AuthN, MFA e AuthZ",
                  description=f"Canal de MFA ativo: **{notifier.channel}**")
    bearer = HTTPBearer(auto_error=False)
    api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

    # ---- Tradução centralizada de erros de domínio para HTTP ----
    @app.exception_handler(AuthError)
    def _auth(_: Request, __: AuthError):
        return JSONResponse({"detail": "Não autenticado"}, status.HTTP_401_UNAUTHORIZED,
                            headers={"WWW-Authenticate": "Bearer"})

    @app.exception_handler(OtpError)
    def _otp(_: Request, __: OtpError):
        return JSONResponse({"detail": "Código inválido ou expirado"}, status.HTTP_400_BAD_REQUEST)

    @app.exception_handler(OtpCooldownError)
    def _cooldown(_: Request, exc: OtpCooldownError):
        return JSONResponse({"detail": "Aguarde para pedir um novo código"},
                            status.HTTP_429_TOO_MANY_REQUESTS,
                            headers={"Retry-After": str(exc.retry_after_s)})

    @app.exception_handler(DeliveryError)
    def _delivery(_: Request, __: DeliveryError):
        return JSONResponse({"detail": "Não foi possível enviar o código"}, status.HTTP_502_BAD_GATEWAY)

    @app.exception_handler(ValidationError)
    def _validation(_: Request, exc: ValidationError):
        return JSONResponse({"detail": str(exc)}, 422)

    # ---- Dependências de segurança ----
    def current_principal(
        bearer_cred: Annotated[HTTPAuthorizationCredentials | None, Security(bearer)],
        api_key: Annotated[str | None, Security(api_key_header)],
    ) -> Principal:
        """Autenticação: aceita Bearer JWT (humanos) ou X-API-Key (máquinas)."""
        if bearer_cred:
            return jwt_auth.authenticate(bearer_cred.credentials)
        if api_key:
            return key_auth.authenticate(api_key)
        raise AuthError("missing credentials")

    def require(*scopes: str, mfa: bool = False):
        """Autorização declarativa por rota (menor privilégio + step-up MFA)."""
        def checker(p: Annotated[Principal, Depends(current_principal)]) -> Principal:
            try:
                authorize(p, *scopes, mfa=mfa)
            except PermissionError as exc:
                raise HTTPException(status.HTTP_403_FORBIDDEN, str(exc))
            return p
        return checker

    def human(p: Annotated[Principal, Depends(current_principal)]) -> Principal:
        if p.auth_method != "jwt":
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Rota exclusiva para usuários")
        return p

    # ---- Rotas: cadastro e verificação de telefone ----
    @app.post("/users", response_model=UserOut, status_code=201, tags=["1. Cadastro"])
    def register(body: RegisterIn) -> UserOut:
        try:
            u = accounts.register(body.username, body.password, body.phone, body.email)
        except DuplicateError:
            raise HTTPException(status.HTTP_409_CONFLICT, "Usuário já existe")
        return UserOut(id=u.id, username=u.username, phone_verified=False, mfa_enabled=False)

    @app.post("/me/phone/verification", response_model=SentOut, tags=["1. Cadastro"])
    def start_phone_verification(p: Annotated[Principal, Depends(human)]) -> SentOut:
        return SentOut(sent_to=accounts.start_phone_verification(p.subject),
                       expires_in=s.otp_ttl_s)

    @app.post("/me/phone/verification/confirm", response_model=UserOut, tags=["1. Cadastro"])
    def confirm_phone(body: CodeIn, p: Annotated[Principal, Depends(human)]) -> UserOut:
        u = accounts.confirm_phone(p.subject, body.code)
        return UserOut(id=u.id, username=u.username, phone_verified=u.phone_verified,
                       mfa_enabled=u.mfa_enabled)

    # ---- Rotas: login em duas etapas ----
    @app.post("/auth/token", response_model=TokenOut | MfaChallengeOut, tags=["2. Login"])
    def login(form: Annotated[OAuth2PasswordRequestForm, Depends()]):
        r = logins.login(form.username, form.password)
        if r.access_token:
            return TokenOut(access_token=r.access_token, expires_in=s.access_token_ttl_min * 60)
        return MfaChallengeOut(mfa_token=r.mfa_token, sent_to=r.sent_to, expires_in=s.otp_ttl_s)

    @app.post("/auth/mfa/verify", response_model=TokenOut, tags=["2. Login"])
    def verify_mfa(body: MfaVerifyIn) -> TokenOut:
        token = logins.verify_mfa(body.mfa_token, body.code)
        return TokenOut(access_token=token, expires_in=s.access_token_ttl_min * 60)

    @app.get("/me", tags=["2. Login"])
    def me(p: Annotated[Principal, Depends(current_principal)]) -> dict:
        return {"subject": p.subject, "scopes": sorted(p.scopes), "via": p.auth_method,
                "amr": sorted(p.amr), "mfa": p.mfa}

    # ---- Rotas: recursos protegidos ----
    @app.post("/api-keys", response_model=ApiKeyOut, status_code=201, tags=["3. Modelo"])
    def create_api_key(p: Annotated[Principal, Depends(require("keys:create", mfa=True))]):
        scopes = frozenset({"models:predict"}) & p.scopes   # chave nunca excede o dono
        plaintext, record = key_service.generate(p.subject, scopes)
        api_keys.add(record)
        return ApiKeyOut(api_key=plaintext)

    @app.post("/models/churn/predict", tags=["3. Modelo"])
    def predict(body: PredictIn,
                p: Annotated[Principal, Depends(require("models:predict"))]) -> dict:
        score = min(1.0, max(0.0, sum(body.features) / len(body.features)))
        return {"churn_probability": round(score, 3), "caller": p.subject}

    @app.post("/models/churn/deploy", tags=["3. Modelo"])
    def deploy(p: Annotated[Principal, Depends(require("models:deploy", mfa=True))]) -> dict:
        return {"status": "deployed", "by": p.subject}

    return app
