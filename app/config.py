"""Configuração centralizada (12-Factor App: config vem do ambiente, nunca do código)."""
from functools import lru_cache
from typing import Literal

from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="AUTH_", env_file=".env", extra="ignore")

    # --- Segredos obrigatórios: a aplicação não sobe sem eles ---
    jwt_secret: SecretStr
    otp_pepper: SecretStr                  # chave do HMAC que protege os códigos OTP

    # --- Tokens ---
    jwt_algorithm: str = "HS256"
    jwt_issuer: str = "https://auth.unievangelica.local"
    jwt_audience: str = "ia-api"
    access_token_ttl_min: int = 15
    mfa_token_ttl_min: int = 5             # token intermediário "senha OK, falta o código"
    api_key_prefix: str = "uev_live_"

    # --- Política de OTP ---
    otp_length: int = 6
    otp_ttl_s: int = 300                   # código vale 5 minutos
    otp_max_attempts: int = 5              # depois disso o código é invalidado
    otp_resend_cooldown_s: int = 60        # intervalo mínimo entre envios

    # --- Senhas (NIST SP 800-63B-4) ---
    password_min_length: int = 15

    # --- Canal de entrega do código: console | telegram_gateway | email ---
    mfa_channel: Literal["console", "telegram_gateway", "email"] = "console"
    telegram_gateway_token: SecretStr | None = None
    smtp_host: str = "smtp.gmail.com"
    smtp_port: int = 587
    smtp_user: str | None = None
    smtp_password: SecretStr | None = None
    smtp_sender: str | None = None

    # --- Persistência ---
    database_url: str = "auth.db"           # arquivo SQLite (":memory:" nos testes)
    default_role: str = "data_scientist"    # papel de quem se cadastra (em produção: definido por admin)


@lru_cache
def get_settings() -> Settings:
    return Settings()
