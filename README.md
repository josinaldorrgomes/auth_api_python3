# IA Model API: autenticação, MFA por telefone e controle de acesso

Material prático da aula de Segurança da Informação (Bacharelado em Inteligência Artificial, UniEVANGÉLICA).

A API expõe um "modelo de churn" protegido por:

- **Cadastro com número de telefone** (formato E.164) e senha (Argon2id, mínimo de 15 caracteres, NIST SP 800-63B-4)
- **Confirmação do telefone por código de uso único (OTP)** entregue por um canal **gratuito**
- **Login em duas etapas**: senha → `mfa_token` → código → `access_token` (JWT com `amr: ["otp","pwd"]`)
- **Step-up MFA**: criar API keys e fazer deploy exigem um token obtido com o segundo fator
- **API keys** para integrações máquina-a-máquina (só o hash é armazenado)
- **RBAC com scopes** (`models:read`, `models:predict`, `models:deploy`, `keys:create`)

## Fluxo

```
1. POST /users                          {username, password, phone, email?}  → 201
2. POST /auth/token                     (sem MFA ainda)                       → access_token (amr: pwd)
3. POST /me/phone/verification          envia o código ao telefone            → {sent_to: "+55*******8888"}
4. POST /me/phone/verification/confirm  {code}                                → mfa_enabled: true
5. POST /auth/token                     agora exige o 2º fator                → {mfa_required, mfa_token}
6. POST /auth/mfa/verify                {mfa_token, code}                     → access_token (amr: otp, pwd)
7. POST /api-keys                       exige MFA (step-up)                   → uev_live_....
8. POST /models/churn/predict           com X-API-Key                         → previsão
```

## Estrutura (arquitetura hexagonal)

```
app/
  config.py         Settings via variáveis de ambiente / .env (12-Factor)
  domain.py         User, OtpChallenge, ApiKey, Principal, Role → scopes (RBAC)
  security.py       PasswordService (Argon2id), TokenService (JWT), ApiKeyService
  otp.py            OtpService: gera, guarda o HMAC, expira, limita tentativas e reenvio
  notifications.py  Notifier (Strategy) + build_notifier (Factory):
                    ConsoleNotifier | TelegramGatewayNotifier | EmailNotifier
  repositories.py   Padrão Repository com SQLite (stdlib, sem instalação)
  services.py       Casos de uso: AccountService, LoginService, Authenticators, authorize()
  main.py           Adaptador HTTP FastAPI + Composition Root (create_app)
tests/              21 testes: fluxo MFA, força bruta no código, expiração, replay,
                    cooldown, step-up, alg=none, canais Telegram (simulado) e SMTP (servidor local)
```

## Como executar

```bash
python -m venv .venv
source .venv/bin/activate            # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env                 # Windows: copy .env.example .env
# gere os dois segredos e cole no .env:
python -c "import secrets; print(secrets.token_urlsafe(48))"
uvicorn app.main:create_app --factory --reload
```

Abra **http://localhost:8000/docs**: o Swagger permite fazer todo o fluxo pelo navegador
(o botão *Authorize* aceita o token Bearer ou a API key).

Com `AUTH_MFA_CHANNEL=console` (padrão), o código aparece no terminal do uvicorn. É o modo
para desenvolver sem depender de nenhum serviço externo.

## Escolhendo um canal gratuito

### Opção A: Telegram Gateway (recomendado: o código chega pelo número de telefone)

O [Telegram Gateway](https://core.telegram.org/gateway) entrega códigos de verificação
**para um número de telefone**, no app do Telegram. Segundo a documentação oficial, o envio é
**gratuito quando o destino é o seu próprio número**, que é exatamente o cenário do laboratório:
cada estudante roda a API na sua máquina, com o seu token.

1. Instale o Telegram no celular e crie a conta com o seu número.
2. Acesse **https://gateway.telegram.org**, clique em *Log in* e informe o mesmo número;
   confirme o login pelo app.
3. Aceite os termos e copie o token em **API → Copy Token**.
4. No `.env`:
   ```
   AUTH_MFA_CHANNEL=telegram_gateway
   AUTH_TELEGRAM_GATEWAY_TOKEN=<seu token>
   ```
5. Cadastre-se na API com **o mesmo número** usado no Telegram, no formato E.164
   (ex.: `+5562999998888`). O código chega na conversa *Verification Codes* do Telegram.

> Enviar para números de outras pessoas é cobrado e exige saldo na conta do Gateway.

### Opção B: e-mail pelo Gmail

1. Ative a **verificação em duas etapas** na sua conta Google.
2. Crie uma **senha de app** em https://myaccount.google.com/apppasswords.
3. Preencha o bloco "Opção B" do `.env.example` e cadastre o usuário com o campo `email`.

### Opção C: e-mail pelo Brevo (servidor único para a turma inteira)

O plano gratuito do [Brevo](https://www.brevo.com/pricing/) permite 300 e-mails por dia via
SMTP (`smtp-relay.brevo.com:587`). É útil quando o professor sobe **uma** API para todos.
Use o login e a chave SMTP do painel e um remetente verificado.

> **Atenção (discussão de aula):** o NIST SP 800-63B-4 diz que *e-mail não deve ser usado
> como autenticador fora de banda*, porque a caixa de e-mail costuma ser protegida só por
> senha e a mensagem pode ser interceptada. Aqui o e-mail é usado apenas para fins didáticos.
> SMS também é classificado como autenticador *restrito*. O ideal em produção são passkeys/FIDO2.

### Por que não SMS?

Não há serviço de SMS gratuito e confiável para enviar códigos a números quaisquer: cada SMS
tem custo de operadora, e as ofertas "grátis" são alvo de fraude. O trial da Twilio, por
exemplo, só envia modelos de mensagem pré-definidos, para até 5 números verificados, e expira
em 30 dias. Para acrescentar SMS em produção, basta escrever um novo `Notifier`: nenhuma
outra parte do código muda (princípio Aberto/Fechado).

## Testes

```bash
pytest -q
```

## Exercícios sugeridos

1. Criar um `SmsNotifier` para um provedor pago, sem alterar `services.py`.
2. Adicionar *rate limiting* por IP no `/auth/token` e no `/auth/mfa/verify`.
3. Implementar revogação de JWT por `jti` (denylist).
4. Gerar códigos de recuperação (backup codes) no momento da ativação do MFA.
5. Registrar logs de auditoria estruturados de cada decisão de acesso, sem expor códigos nem tokens.
6. Trocar o OTP por TOTP (RFC 6238) com app autenticador e comparar a segurança dos dois.
