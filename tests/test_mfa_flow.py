import jwt

from .conftest import PHONE, bearer, enroll, full_login, login, register


# ---------------------------- Cadastro ----------------------------
def test_register_validates_phone_and_password(client):
    assert register(client, phone="62999998888").status_code == 422          # sem +DDI
    assert register(client, password="curta").status_code == 422              # < 15 chars
    assert register(client, password="ana-ana-ana-ana-ana").status_code == 422  # contém username
    assert register(client).status_code == 201
    assert register(client).status_code == 409                                # duplicado


def test_phone_enrollment_enables_mfa(client, notifier, clock):
    enroll(client, notifier, clock)
    assert notifier.sent[0][0] == PHONE
    assert login(client).json()["mfa_required"] is True


# ---------------------------- Login com MFA ----------------------------
def test_full_login_gives_token_with_otp_in_amr(client, notifier, clock):
    enroll(client, notifier, clock)
    token = full_login(client, notifier)
    me = client.get("/me", headers=bearer(token)).json()
    assert me["mfa"] is True and me["amr"] == ["otp", "pwd"]


def test_wrong_code_rejected(client, notifier, clock):
    enroll(client, notifier, clock)
    mfa_token = login(client).json()["mfa_token"]
    wrong = "000000" if notifier.last_code != "000000" else "111111"
    r = client.post("/auth/mfa/verify", json={"mfa_token": mfa_token, "code": wrong})
    assert r.status_code == 400


def test_code_locked_after_max_attempts(client, notifier, clock):
    enroll(client, notifier, clock)
    mfa_token = login(client).json()["mfa_token"]
    good = notifier.last_code
    wrong = "000000" if good != "000000" else "111111"
    for _ in range(5):
        client.post("/auth/mfa/verify", json={"mfa_token": mfa_token, "code": wrong})
    r = client.post("/auth/mfa/verify", json={"mfa_token": mfa_token, "code": good})
    assert r.status_code == 400          # nem o código certo vale mais: força bruta barrada


def test_code_expires(client, notifier, clock):
    enroll(client, notifier, clock)
    mfa_token = login(client).json()["mfa_token"]
    clock.advance(301)
    r = client.post("/auth/mfa/verify", json={"mfa_token": mfa_token, "code": notifier.last_code})
    assert r.status_code == 400


def test_code_is_single_use(client, notifier, clock):
    enroll(client, notifier, clock)
    r = login(client).json()
    body = {"mfa_token": r["mfa_token"], "code": notifier.last_code}
    assert client.post("/auth/mfa/verify", json=body).status_code == 200
    assert client.post("/auth/mfa/verify", json=body).status_code == 400    # replay


def test_resend_cooldown_returns_429(client, notifier, clock):
    enroll(client, notifier, clock)
    assert login(client).status_code == 200
    r = login(client)
    assert r.status_code == 429 and int(r.headers["Retry-After"]) > 0


def test_mfa_token_is_not_an_access_token(client, notifier, clock):
    enroll(client, notifier, clock)
    mfa_token = login(client).json()["mfa_token"]
    assert client.get("/me", headers=bearer(mfa_token)).status_code == 401


def test_wrong_password_and_unknown_user_look_identical(client):
    register(client)
    a, b = login(client, password="senha-errada-errada"), login(client, username="ninguem")
    assert a.status_code == b.status_code == 401 and a.json() == b.json()


# ---------------------------- Autorização ----------------------------
def test_api_key_requires_mfa_step_up(client):
    register(client)
    token = login(client).json()["access_token"]           # só senha (amr = pwd)
    r = client.post("/api-keys", headers=bearer(token))
    assert r.status_code == 403 and r.json()["detail"] == "mfa required"


def test_api_key_flow_after_mfa(client, notifier, clock):
    enroll(client, notifier, clock)
    token = full_login(client, notifier)
    key = client.post("/api-keys", headers=bearer(token)).json()["api_key"]
    r = client.post("/models/churn/predict", json={"features": [0.4, 0.6]},
                    headers={"X-API-Key": key})
    assert r.status_code == 200 and r.json()["churn_probability"] == 0.5
    assert client.post("/api-keys", headers={"X-API-Key": key}).status_code == 403
    tampered = key[:-2] + ("zz" if not key.endswith("zz") else "yy")
    assert client.get("/me", headers={"X-API-Key": tampered}).status_code == 401


def test_data_scientist_cannot_deploy(client, notifier, clock):
    enroll(client, notifier, clock)
    token = full_login(client, notifier)
    assert client.post("/models/churn/deploy", headers=bearer(token)).status_code == 403


def test_api_key_cannot_start_phone_verification(client, notifier, clock):
    enroll(client, notifier, clock)
    key = client.post("/api-keys", headers=bearer(full_login(client, notifier))).json()["api_key"]
    r = client.post("/me/phone/verification", headers={"X-API-Key": key})
    assert r.status_code == 403


# ---------------------------- Ataques a JWT ----------------------------
def test_alg_none_token_rejected(client):
    forged = jwt.encode({"sub": "x", "scope": "models:deploy", "amr": ["otp"],
                         "token_use": "access"}, key=None, algorithm="none")
    assert client.get("/me", headers=bearer(forged)).status_code == 401


def test_token_signed_with_other_secret_rejected(client):
    forged = jwt.encode({"sub": "x", "aud": "ia-api", "iss": "https://auth.unievangelica.local",
                         "exp": 9999999999, "iat": 0, "scope": "models:deploy",
                         "amr": ["otp", "pwd"], "token_use": "access"},
                        "segredo-do-atacante-" + "z" * 20, algorithm="HS256")
    assert client.post("/models/churn/deploy", headers=bearer(forged)).status_code == 401
