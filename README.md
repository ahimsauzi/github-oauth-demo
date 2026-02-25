# GitHub OAuth 2.0 + PKCE Demo

A minimal Python web app (zero frameworks, stdlib only) that demonstrates
the **OAuth 2.0 Authorization Code Grant** flow with **PKCE**, using GitHub
as the Authorization Server.

## What it demonstrates

| Concept                                 | Where you'll see it                                  |
| --------------------------------------- | ---------------------------------------------------- |
| Authorization Code Grant                | `/login` → GitHub → `/callback` redirect chain       |
| `state` parameter (CSRF)                | Generated at `/login`, validated at `/callback`      |
| PKCE `code_challenge` / `code_verifier` | Shown in the callback results page                   |
| Scope-based delegated authorization     | Scope table on the results page                      |
| Access Token (opaque bearer)            | Token response section                               |
| Resource Server call (UserInfo)         | `/user` API call with Bearer token                   |
| OIDC claim mapping                      | Table comparing GitHub fields → OIDC standard claims |
| OAuth vs OIDC gap                       | Comparison table (no ID Token from GitHub)           |

## Setup

### 1. Register a GitHub OAuth App

1. Go to **GitHub → Settings → Developer settings → OAuth Apps → New OAuth App**
2. Set **Authorization callback URL** to exactly: `http://127.0.0.1:8080/callback`
3. Click **Register**, then **Generate a new client secret**

### 2. Configure credentials

```bash
cp .env.example .env
# Edit .env and fill in GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET
```

### 3. Set up pyenv virtual environment & run

```bash
# Ensure the Python version is installed (only needed once)
pyenv install           # reads .python-version automatically

# Create and activate a virtualenv (pyenv-virtualenv plugin)
pyenv virtualenv 3.11 github-oauth-demo
pyenv local github-oauth-demo   # pins this dir to the virtualenv

# Install dependency and run
pip install -r requirements.txt
python app.py
```

> If you don't use the pyenv-virtualenv plugin, a plain venv works too:
>
> ```bash
> python -m venv .venv && source .venv/bin/activate
> pip install -r requirements.txt
> ```

### 4. Open the app

Navigate to http://127.0.0.1:8080 and click **Start OAuth Flow →**

## Security notes (shift-left)

- **PKCE (RFC 7636)** — protects against authorization code interception; the
  `code_verifier` never leaves the server
- **`state` parameter** — one-time random token stored in memory, validated on
  callback to prevent CSRF
- **Loopback IP** (`127.0.0.1`) — preferred over `localhost` per OAuth RFC
- **No secrets in browser** — `client_secret` and tokens only handled server-side
- **Security headers** — `X-Content-Type-Options`, `X-Frame-Options`,
  `Referrer-Policy` set on every response
- **Token prefix awareness** — `gho_` vs `ghu_` vs `ghp_` token types identified

## Why GitHub doesn't issue OIDC ID Tokens

GitHub's OAuth app issues **opaque access tokens**, not JWTs. To see a real
OIDC ID Token (signed JWT with `sub`, `iss`, `exp`, `nonce` claims), use an
OIDC-compliant provider: Google, Auth0, Okta, or Keycloak — with scope
`openid profile email`.

The results page includes a comparison table showing exactly what's present
vs. what a full OIDC flow would add.

Client ID
Ov23lizoInvMTs3ZfM8T

Client secret
7ff6726ef8f9b08a1eb513f164b8ed3773b69332
