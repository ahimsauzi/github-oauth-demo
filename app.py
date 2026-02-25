"""
GitHub OAuth 2.0 / OIDC Flow Demo
----------------------------------
Demonstrates the full Authorization Code Grant flow with:
  - state parameter (CSRF protection)
  - PKCE (code_challenge / code_verifier) [shift-left security]
  - Authorization Code exchange for Access Token
  - Token introspection via GitHub /user endpoint
  - Configurable scopes, code-expiry tracking, and simulated ID Token

Usage:
  1. Copy .env.example to .env and fill in CLIENT_ID / CLIENT_SECRET
  2. pip install -r requirements.txt
  3. python app.py
  4. Open http://127.0.0.1:8080 in your browser

────────────────────────────────────────────────────────────────────────────
Optional configuration (all have safe defaults — nothing is required):

  GITHUB_SCOPES
      Space-separated GitHub OAuth scopes to request.
      Default: "read:user user:email"
      Example: "read:user user:email repo read:org"

  CODE_MAX_AGE_SECONDS
      How long (in seconds) your app will accept an authorization code
      before treating it as expired on our side. GitHub's own hard limit
      is 600 s (10 min); setting this lower adds a stricter local guard.
      Default: 600  (matches GitHub's limit)
      Example: 30   (very strict — useful for demo purposes)

  SIMULATE_ID_TOKEN
      Set to "true" to construct a synthetic ID Token (JWT-shaped JSON)
      from the /user response, illustrating what a real OIDC ID Token
      would look like. Clearly labelled as simulated in the UI.
      NOTE: GitHub OAuth Apps do NOT issue real OIDC ID Tokens. The
      'openid' scope is silently ignored by GitHub. For a real ID Token
      use an OIDC-compliant provider (Google, Auth0, Okta, Keycloak).
      Default: false
────────────────────────────────────────────────────────────────────────────
"""

import base64
import hashlib
import hmac
import html
import json
import os
import secrets
import time
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer

# ── Load .env ─────────────────────────────────────────────────────────────
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# ── Required credentials ──────────────────────────────────────────────────
CLIENT_ID     = os.environ.get("GITHUB_CLIENT_ID", "")
CLIENT_SECRET = os.environ.get("GITHUB_CLIENT_SECRET", "")
REDIRECT_URI  = "http://127.0.0.1:8080/callback"

# ── Optional configuration ────────────────────────────────────────────────

# Scopes — space-separated list; extend freely with valid GitHub scopes.
# ref: https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/scopes-for-oauth-apps
SCOPES = os.environ.get("GITHUB_SCOPES", "read:user user:email").strip()

# Client-side code expiry guard (seconds). GitHub hard-expires codes at
# 600 s. Set lower to demonstrate what happens when a code is too old.
_raw_max_age = os.environ.get("CODE_MAX_AGE_SECONDS", "600")
try:
    CODE_MAX_AGE = max(1, int(_raw_max_age))
except ValueError:
    CODE_MAX_AGE = 600

# Simulate an OIDC ID Token from the /user response.
SIMULATE_ID_TOKEN = os.environ.get("SIMULATE_ID_TOKEN", "false").lower() == "true"

# ── GitHub endpoints ──────────────────────────────────────────────────────
AUTHORIZE_URL = "https://github.com/login/oauth/authorize"
TOKEN_URL     = "https://github.com/login/oauth/access_token"
USERINFO_URL  = "https://api.github.com/user"
EMAILS_URL    = "https://api.github.com/user/emails"
REVOKE_URL    = f"https://api.github.com/applications/{{}}/token"  # .format(CLIENT_ID)

# ── Session store  {state: {verifier, challenge, issued_at}} ──────────────
_sessions: dict[str, dict] = {}

# ── Last issued access token (held in memory for revocation) ──────────────
# Only the most recent token is stored — sufficient for a single-user demo.
_last_token: dict[str, str] = {}   # keys: "access_token", "login"

# ── PKCE helpers ──────────────────────────────────────────────────────────

def generate_pkce_pair() -> tuple[str, str]:
    """Return (code_verifier, code_challenge) using S256 method."""
    verifier  = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode()
    digest    = hashlib.sha256(verifier.encode()).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
    return verifier, challenge

# ── Simulated ID Token ────────────────────────────────────────────────────

def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def build_simulated_id_token(user: dict, primary_email: str, verified: bool) -> dict:
    """
    Construct a JWT-shaped structure that mirrors what a real OIDC ID Token
    would contain, populated from GitHub's /user response.

    This is NOT cryptographically signed with a real key pair — the signature
    is an HMAC-SHA256 over a dummy secret to illustrate the structure only.
    A real ID Token would be signed with the provider's RS256 private key and
    verifiable against their JWKS endpoint.
    """
    now = int(time.time())
    header = {"alg": "HS256", "typ": "JWT", "kid": "simulated-demo-key"}
    payload = {
        # Standard OIDC required claims
        "iss":                "https://github.com/login/oauth [SIMULATED]",
        "sub":                str(user.get("id", "")),   # stable unique identifier
        "aud":                CLIENT_ID,                  # must match client_id
        "iat":                now,                        # issued at
        "exp":                now + 3600,                 # expires in 1 hour
        # Standard OIDC profile claims
        "name":               user.get("name") or user.get("login", ""),
        "preferred_username": user.get("login", ""),
        "picture":            user.get("avatar_url", ""),
        "profile":            user.get("html_url", ""),
        # Standard OIDC email claims
        "email":              primary_email,
        "email_verified":     verified,
        # Non-standard — GitHub-specific extras shown for demo purposes
        "github_id":          user.get("id"),
        "github_login":       user.get("login"),
    }
    h_enc = _b64url(json.dumps(header,  separators=(",", ":")).encode())
    p_enc = _b64url(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{h_enc}.{p_enc}".encode()
    sig = hmac.new(b"demo-secret-not-real", signing_input, hashlib.sha256).digest()
    token_str = f"{h_enc}.{p_enc}.{_b64url(sig)}"
    return {"token": token_str, "header": header, "payload": payload}

# ── HTTP helpers ──────────────────────────────────────────────────────────

def _get(url: str, token: str) -> dict | list:
    req = urllib.request.Request(
        url,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
            "User-Agent": "OAuth-Demo/1.0",
        },
    )
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read())


def _post_form(url: str, data: dict) -> dict:
    body = urllib.parse.urlencode(data).encode()
    req  = urllib.request.Request(
        url,
        data=body,
        headers={
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": "OAuth-Demo/1.0",
        },
    )
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read())


def _delete_json(url: str, basic_user: str, basic_pass: str, body: dict) -> int:
    """
    Send a DELETE request with HTTP Basic Auth and a JSON body.
    Returns the HTTP status code.
    GitHub's DELETE /applications/{client_id}/token expects:
      - Basic auth: client_id : client_secret
      - Body: {"access_token": "<token>"}
    """
    credentials = base64.b64encode(f"{basic_user}:{basic_pass}".encode()).decode()
    data        = json.dumps(body).encode()
    req = urllib.request.Request(
        url,
        data=data,
        method="DELETE",
        headers={
            "Authorization":  f"Basic {credentials}",
            "Accept":         "application/vnd.github+json",
            "Content-Type":   "application/json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent":     "OAuth-Demo/1.0",
        },
    )
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.status
    except urllib.error.HTTPError as exc:
        return exc.code

# ── Shared CSS ────────────────────────────────────────────────────────────

_CSS = """
<style>
  body{font-family:'Segoe UI',system-ui,sans-serif;background:#0d0f14;color:#e8eaf0;
       margin:0;padding:2rem;line-height:1.6}
  h1{color:#00d4aa;font-size:1.6rem;margin-bottom:0.2rem}
  h2{color:#3b7dd8;font-size:1.1rem;margin:1.6rem 0 0.6rem}
  a{color:#00d4aa}
  .card{background:#161923;border:1px solid #252d3d;border-radius:10px;
        padding:1.4rem 1.8rem;margin:1rem 0;max-width:800px}
  .card.sim-card{border-color:#3b7dd8;background:#101828}
  pre{background:#0a0c10;border:1px solid #252d3d;border-radius:6px;
      padding:1rem;overflow-x:auto;font-size:0.78rem;color:#a8b4c8;white-space:pre-wrap}
  .btn{display:inline-block;padding:0.7rem 1.6rem;background:rgba(0,212,170,0.12);
       border:1px solid #00d4aa;color:#00d4aa;border-radius:6px;
       text-decoration:none;font-size:0.9rem;cursor:pointer}
  .btn:hover{background:rgba(0,212,170,0.22)}
  .btn-danger{background:rgba(224,92,92,0.1);border-color:#e05c5c;color:#e05c5c}
  .btn-danger:hover{background:rgba(224,92,92,0.22)}
  .btn[disabled]{opacity:0.35;cursor:not-allowed}
  .label{color:#7a8298;font-size:0.78rem;font-family:monospace}
  table{border-collapse:collapse;width:100%}
  td,th{padding:0.4rem 0.8rem;text-align:left;border-bottom:1px solid #252d3d;font-size:0.85rem}
  th{color:#7a8298;font-weight:normal;font-family:monospace;font-size:0.72rem;
     text-transform:uppercase;letter-spacing:0.06em}
  code{font-family:monospace;font-size:0.85em;background:#1a2035;
       padding:0.1em 0.35em;border-radius:3px}
  .ok{color:#00d4aa} .warn{color:#e0b55c} .err{color:#e05c5c}
  .step{background:#1e2a3a;border-left:3px solid #00d4aa;padding:0.6rem 1rem;
        margin:0.4rem 0;border-radius:0 6px 6px 0;font-size:0.85rem}
  .badge-sim{display:inline-block;background:#1a2a44;border:1px solid #3b7dd8;
             color:#3b7dd8;font-size:0.68rem;font-family:monospace;padding:0.1rem 0.5rem;
             border-radius:3px;text-transform:uppercase;letter-spacing:0.06em;
             vertical-align:middle;margin-left:0.4rem}
</style>
"""


def _page(title: str, body: str) -> str:
    return (f'<!DOCTYPE html><html lang="en"><head>\n'
            f'<meta charset="UTF-8"><title>{title}</title>{_CSS}</head>\n'
            f'<body>{body}</body></html>')

# ── Home page ─────────────────────────────────────────────────────────────

def _home_page() -> str:
    cred_status = (
        f'<p class="ok">✓ Client ID loaded: <code>{CLIENT_ID[:8]}…</code></p>'
        if CLIENT_ID else
        '<p class="err">⚠ GITHUB_CLIENT_ID not set — edit your .env file and restart.</p>'
    )
    scope_list    = " ".join(f"<code>{html.escape(s)}</code>" for s in SCOPES.split())
    code_age_note = (
        f'<span class="ok">{CODE_MAX_AGE} s</span> '
        f'{"(matches GitHub hard limit)" if CODE_MAX_AGE == 600 else "(stricter than GitHub — good for demos)"}'
    )
    id_token_note = (
        '<span class="ok">enabled</span> — simulated JWT shown after auth'
        if SIMULATE_ID_TOKEN else
        '<span class="warn">disabled</span> — set <code>SIMULATE_ID_TOKEN=true</code> to enable'
    )

    # Revoke button — only shown when a token is held in memory
    if _last_token:
        login        = html.escape(_last_token.get("login", "unknown"))
        revoke_block = f"""
<form method="POST" action="/revoke" style="display:inline">
  <button class="btn btn-danger" type="submit"
    title="Revoke token for {login} — GitHub will show the consent screen on next auth">
    Revoke Token ({login}) ↺
  </button>
</form>"""
    else:
        revoke_block = (
            '<button class="btn btn-danger" disabled '
            'title="No token held in memory — complete a flow first">'
            'Revoke Token ↺</button>'
        )

    return _page("OAuth 2.0 Demo", f"""
<h1>OAuth 2.0 + PKCE Demo</h1>
<p class="label">Authorization Code Grant with PKCE · GitHub as Authorization Server</p>
{cred_status}

<div class="card">
  <h2>Active Configuration</h2>
  <table>
    <tr><th>Setting</th><th>Value</th><th>Env var</th></tr>
    <tr>
      <td>Scopes</td>
      <td>{scope_list}</td>
      <td><code>GITHUB_SCOPES</code></td>
    </tr>
    <tr>
      <td>Code max age</td>
      <td>{code_age_note}</td>
      <td><code>CODE_MAX_AGE_SECONDS</code></td>
    </tr>
    <tr>
      <td>Simulated ID Token</td>
      <td>{id_token_note}</td>
      <td><code>SIMULATE_ID_TOKEN</code></td>
    </tr>
  </table>
</div>

<div class="card">
  <h2>How this works</h2>
  <div class="step">① Browser redirects to GitHub's <strong>Authorization Endpoint</strong>
    with <code>client_id</code>, <code>scope</code>, <code>state</code> (CSRF token),
    and a PKCE <code>code_challenge</code>. The <strong>issued_at</strong> timestamp
    is recorded server-side at this moment.</div>
  <div class="step">② GitHub authenticates you and shows a consent screen for
    the requested <strong>scopes</strong>.</div>
  <div class="step">③ GitHub redirects back with a short-lived <strong>authorization code</strong>.
    GitHub hard-expires codes after <strong>600 s (10 min)</strong>. This app also
    enforces <strong>CODE_MAX_AGE_SECONDS</strong> as a local guard.</div>
  <div class="step">④ The server exchanges the code for an <strong>Access Token</strong>
    using the <code>code_verifier</code> (PKCE) and <code>client_secret</code>.</div>
  <div class="step">⑤ The Access Token calls <code>/user</code> and <code>/user/emails</code>
    on the GitHub Resource Server — the OIDC UserInfo equivalent.</div>
  {"<div class='step'>⑥ A <strong>simulated ID Token JWT</strong> is constructed from the /user response to illustrate OIDC structure. Clearly labelled — not cryptographically valid.</div>" if SIMULATE_ID_TOKEN else ""}
  <div class="step{'last'}"
    style="border-left-color:#e05c5c;background:#1e1014">
    <strong>Revoke Token</strong> — calls
    <code>DELETE /applications/&#123;client_id&#125;/token</code> on GitHub.
    This destroys the stored token and clears GitHub's grant, so the
    <strong>next auth flow will show the consent screen again</strong>.
    Use this whenever you want to demo the full authorization experience.
  </div>
</div>

<br>
<div style="display:flex;gap:1rem;align-items:center;flex-wrap:wrap">
  <a class="btn" href="/login">Start OAuth Flow →</a>
  {revoke_block}
</div>
<p style="margin-top:2rem;font-size:0.75rem;color:#7a8298">
  Callback: <code>{REDIRECT_URI}</code>
</p>
""")

# ── Callback result page ──────────────────────────────────────────────────

def _callback_page(
    auth_code: str,
    state: str,
    token_resp: dict,
    user: dict,
    emails: list,
    auth_url: str,
    verifier: str,
    challenge: str,
    code_age: float,
    code_expired_locally: bool,
) -> str:
    def _j(obj): return html.escape(json.dumps(obj, indent=2))

    access_token = token_resp.get("access_token", "")
    token_type   = token_resp.get("token_type", "")
    scope        = token_resp.get("scope", "")

    prefix_map = {"gho_": "OAuth App Token", "ghu_": "GitHub App User Token", "ghp_": "PAT"}
    token_kind = next((v for k, v in prefix_map.items() if access_token.startswith(k)), "Unknown")

    primary_email = next((e["email"] for e in emails if e.get("primary")), "—")
    verified      = next((e["verified"] for e in emails if e.get("primary")), False)

    # Scope comparison — requested vs granted
    requested  = set(SCOPES.split())
    granted    = {s.strip() for s in scope.split(",") if s.strip()}
    all_scopes = sorted(requested | granted)
    scope_rows = ""
    for s in all_scopes:
        in_req = "✓" if s in requested else "—"
        in_gnt = (
            '<span class="ok">✓ granted</span>' if s in granted
            else '<span class="warn">✗ not granted</span>'
        )
        scope_rows += f"<tr><td><code>{html.escape(s)}</code></td><td>{in_req}</td><td>{in_gnt}</td></tr>"

    # Code age display
    age_colour = "ok" if code_age <= CODE_MAX_AGE else "err"
    age_label  = f'<span class="{age_colour}">{code_age:.1f} s</span>'
    if code_expired_locally:
        age_banner = (
            f'<p class="err">⚠ Code age ({code_age:.1f} s) exceeded CODE_MAX_AGE_SECONDS '
            f'({CODE_MAX_AGE} s). In production this request would be rejected before the '
            f'exchange attempt. The exchange was attempted here to demonstrate GitHub\'s '
            f'own 600 s hard limit separately.</p>'
        )
    else:
        age_banner = (
            f'<p class="ok">✓ Code age {age_label} is within the {CODE_MAX_AGE} s '
            f'local limit (GitHub hard limit: 600 s).</p>'
        )

    # Simulated ID Token section
    id_token_html = ""
    if SIMULATE_ID_TOKEN:
        sim        = build_simulated_id_token(user, primary_email, verified)
        claim_rows = "".join(
            f"<tr><td><code>{html.escape(k)}</code></td>"
            f"<td><code>{html.escape(str(v))}</code></td></tr>"
            for k, v in sim["payload"].items()
        )
        id_token_html = f"""
<div class="card sim-card">
  <h2>⑥ Simulated ID Token <span class="badge-sim">simulated · not valid</span></h2>
  <p class="warn">⚠ GitHub OAuth Apps do <strong>not</strong> issue OIDC ID Tokens —
  the <code>openid</code> scope is silently ignored. This JWT is constructed
  server-side from the <code>/user</code> response to illustrate what a real
  ID Token would contain. It is signed with a dummy HMAC key and is
  <strong>not cryptographically valid</strong>. Paste it into
  <a href="https://jwt.io" target="_blank">jwt.io</a> to inspect the structure.</p>

  <h2>Encoded token <span class="badge-sim">header.payload.signature</span></h2>
  <pre style="word-break:break-all">{html.escape(sim['token'])}</pre>

  <h2>Decoded header</h2>
  <pre>{_j(sim['header'])}</pre>

  <h2>Decoded payload — ID Token claims</h2>
  <table>
    <tr><th>Claim</th><th>Value</th></tr>
    {claim_rows}
  </table>
  <p class="label" style="margin-top:1rem">
    A real ID Token would also include: <code>nonce</code> (replay protection),
    <code>at_hash</code> (access token hash), <code>acr</code>, <code>amr</code>,
    and be RS256-signed — verifiable against the provider's
    <code>/.well-known/jwks.json</code>.
  </p>
</div>"""

    step_offset   = 1 if SIMULATE_ID_TOKEN else 0
    user_step     = f"⑥" if not SIMULATE_ID_TOKEN else "⑦"
    compare_step  = f"⑦" if not SIMULATE_ID_TOKEN else "⑧"
    id_token_row  = (
        '<span class="warn">✗ Not issued — simulated above</span>'
        if SIMULATE_ID_TOKEN else
        '<span class="err">✗ Not issued</span>'
    )

    return _page("OAuth Callback Result", f"""
<h1>OAuth Flow Complete ✓</h1>
<p class="label">Authorization Code Grant with PKCE</p>

<!-- ── Authorization request ── -->
<div class="card">
  <h2>① Authorization Request URL</h2>
  <pre>{html.escape(auth_url)}</pre>
  <table>
    <tr><th>Parameter</th><th>Value</th><th>Purpose</th></tr>
    <tr><td>client_id</td><td><code>{html.escape(CLIENT_ID)}</code></td>
        <td>Identifies your app</td></tr>
    <tr><td>scope</td><td><code>{html.escape(SCOPES)}</code></td>
        <td>Permissions requested (from <code>GITHUB_SCOPES</code>)</td></tr>
    <tr><td>state</td><td><code>{html.escape(state[:16])}…</code></td>
        <td>CSRF token — one-time random value</td></tr>
    <tr><td>code_challenge</td><td><code>{html.escape(challenge[:20])}…</code></td>
        <td>PKCE: SHA-256 of verifier</td></tr>
    <tr><td>code_challenge_method</td><td><code>S256</code></td>
        <td>PKCE hash method</td></tr>
  </table>
</div>

<!-- ── Authorization code + expiry ── -->
<div class="card">
  <h2>② Authorization Code &amp; Expiry</h2>
  <pre>{html.escape(auth_code)}</pre>
  {age_banner}
  <table>
    <tr><th>Limit</th><th>Value</th><th>Source</th></tr>
    <tr>
      <td>GitHub hard expiry</td>
      <td><span class="warn">600 s (10 min)</span></td>
      <td>Fixed by GitHub — cannot be changed from the app</td>
    </tr>
    <tr>
      <td>Local app guard</td>
      <td><span class="{'ok' if CODE_MAX_AGE <= 600 else 'warn'}">{CODE_MAX_AGE} s</span></td>
      <td><code>CODE_MAX_AGE_SECONDS</code> env var</td>
    </tr>
    <tr>
      <td>This code's age at callback</td>
      <td>{age_label}</td>
      <td>Measured from <code>issued_at</code> recorded at <code>/login</code></td>
    </tr>
  </table>
  <p class="label" style="margin-top:0.8rem">
    ℹ If your code appeared valid for ~24 hours, it was the <strong>access token</strong>
    that remained active — not the authorization code. Authorization codes are
    one-time use and consumed on first exchange. GitHub OAuth App access tokens have
    no built-in expiry (unlike GitHub App user tokens which expire after 8 h).
  </p>
</div>

<!-- ── PKCE ── -->
<div class="card">
  <h2>③ PKCE Code Verifier</h2>
  <table>
    <tr><th>Field</th><th>Value</th></tr>
    <tr><td>code_verifier</td><td><code>{html.escape(verifier)}</code></td></tr>
    <tr><td>code_challenge (SHA-256 / base64url)</td><td><code>{html.escape(challenge)}</code></td></tr>
  </table>
  <p class="label">The verifier never leaves the server. GitHub verified that
  SHA-256(verifier) == challenge before issuing the token.</p>
</div>

<!-- ── Token response ── -->
<div class="card">
  <h2>④ Token Response</h2>
  <pre>{_j(token_resp)}</pre>
  <table>
    <tr><th>Field</th><th>Value</th><th>Note</th></tr>
    <tr><td>access_token</td><td><code>{html.escape(access_token[:12])}…</code></td>
        <td>Opaque bearer — treat as a secret</td></tr>
    <tr><td>token_type</td><td><code>{html.escape(token_type)}</code></td>
        <td>Send as <code>Authorization: Bearer &lt;token&gt;</code></td></tr>
    <tr><td>scope</td><td><code>{html.escape(scope)}</code></td>
        <td>Scopes actually granted (may differ from requested)</td></tr>
    <tr><td>token kind</td><td><span class="ok">{html.escape(token_kind)}</span></td>
        <td>Inferred from token prefix</td></tr>
    <tr><td>expiry</td><td><span class="warn">none</span></td>
        <td>GitHub OAuth App tokens do not expire; GitHub App user tokens expire after 8 h</td></tr>
  </table>
</div>

<!-- ── Scopes ── -->
<div class="card">
  <h2>⑤ Scope Comparison — Requested vs Granted</h2>
  <table>
    <tr><th>Scope</th><th>Requested</th><th>Granted</th></tr>
    {scope_rows}
  </table>
  <p class="label">Users can grant fewer scopes than requested. Always check the
  <code>scope</code> field in the token response, not just what you asked for.</p>
</div>

{id_token_html}

<!-- ── UserInfo ── -->
<div class="card">
  <h2>{user_step} Resource Server — /user (UserInfo equivalent)</h2>
  <table>
    <tr><th>GitHub field</th><th>Value</th><th>OIDC claim equivalent</th></tr>
    <tr><td>id</td><td><code>{html.escape(str(user.get('id','')))}</code></td>
        <td><code>sub</code></td></tr>
    <tr><td>login</td><td><code>{html.escape(user.get('login',''))}</code></td>
        <td><code>preferred_username</code></td></tr>
    <tr><td>name</td><td><code>{html.escape(user.get('name') or '—')}</code></td>
        <td><code>name</code></td></tr>
    <tr><td>primary email</td><td><code>{html.escape(primary_email)}</code></td>
        <td><code>email</code></td></tr>
    <tr><td>email_verified</td>
        <td><span class="{'ok' if verified else 'err'}">{verified}</span></td>
        <td><code>email_verified</code></td></tr>
    <tr><td>avatar_url</td>
        <td><code>{html.escape((user.get('avatar_url') or '')[:55])}…</code></td>
        <td><code>picture</code></td></tr>
  </table>
  <h2>Raw /user JSON</h2>
  <pre>{_j(user)}</pre>
</div>

<!-- ── OAuth vs OIDC comparison ── -->
<div class="card">
  <h2>{compare_step} OAuth 2.0 vs OIDC — What GitHub Provides</h2>
  <table>
    <tr><th>Feature</th><th>This demo (GitHub OAuth App)</th><th>Full OIDC</th></tr>
    <tr><td>Access Token format</td><td>Opaque string (<code>gho_…</code>)</td>
        <td>Opaque or JWT</td></tr>
    <tr><td>ID Token</td><td>{id_token_row}</td>
        <td class="ok">✓ Signed JWT</td></tr>
    <tr><td>Identity verification</td>
        <td>Extra <code>/user</code> API round-trip required</td>
        <td>Verify ID Token signature locally via JWKS</td></tr>
    <tr><td>Nonce / replay protection</td><td class="err">✗ Not available</td>
        <td class="ok">✓ <code>nonce</code> claim in ID Token</td></tr>
    <tr><td>Token expiry in token</td><td class="err">✗ Opaque, no <code>exp</code></td>
        <td class="ok">✓ <code>exp</code> claim in JWT</td></tr>
    <tr><td>Access token lifetime</td>
        <td>No expiry (OAuth App) · 8 h (GitHub App)</td>
        <td>Provider-defined, typically 1 h</td></tr>
    <tr><td>Auth code lifetime</td>
        <td><span class="warn">600 s — fixed, not configurable</span></td>
        <td>Provider-defined (spec recommends ≤ 10 min)</td></tr>
    <tr><td>Discovery endpoint</td><td class="err">✗ None</td>
        <td class="ok">✓ <code>/.well-known/openid-configuration</code></td></tr>
    <tr><td><code>openid</code> scope</td>
        <td class="err">✗ Silently ignored by GitHub</td>
        <td class="ok">✓ Triggers ID Token issuance</td></tr>
  </table>
</div>

<br>
<div style="display:flex;gap:1rem;align-items:center;flex-wrap:wrap">
  <a class="btn" href="/">← Start Over</a>
  <form method="POST" action="/revoke" style="display:inline">
    <button class="btn btn-danger" type="submit"
      title="Revoke this token so the next flow shows the consent screen again">
      Revoke This Token ↺
    </button>
  </form>
</div>
""")

# ── Revoke result page ────────────────────────────────────────────────────

def _revoke_result_page(success: bool, message: str, login: str) -> str:
    icon    = "✓" if success else "⚠"
    cls     = "ok" if success else "err"
    heading = "Token Revoked" if success else "Revocation Failed"
    next_step = (
        '<p>The stored grant has been deleted from GitHub. '
        'Click <strong>Start OAuth Flow</strong> to run a fresh authorization — '
        'GitHub will present the consent screen again.</p>'
        if success else
        '<p>The token in memory has been left unchanged. '
        'Try running the flow again to obtain a fresh token, then retry revocation.</p>'
    )
    return _page("Token Revocation", f"""
<h1><span class="{cls}">{icon}</span> {heading}</h1>
<div class="card">
  <p class="{cls}">{html.escape(message)}</p>
  {next_step}
  <h2>What just happened</h2>
  <p>This called <code>DELETE https://api.github.com/applications/&#123;client_id&#125;/token</code>
  using <strong>HTTP Basic Auth</strong> (client_id : client_secret) with the access token
  in the request body. This is the correct server-side revocation endpoint — it requires
  the client secret and is <strong>not</strong> exposed to the browser.</p>
  <table>
    <tr><th>Field</th><th>Value</th></tr>
    <tr><td>Endpoint</td>
        <td><code>DELETE /applications/&#123;client_id&#125;/token</code></td></tr>
    <tr><td>Auth method</td>
        <td>HTTP Basic — <code>client_id:client_secret</code></td></tr>
    <tr><td>Body</td>
        <td><code>{{"access_token": "…"}}</code></td></tr>
    <tr><td>Success response</td>
        <td><code>204 No Content</code></td></tr>
    <tr><td>Token owner</td>
        <td><code>{html.escape(login) or "—"}</code></td></tr>
  </table>
</div>
<br>
<a class="btn" href="/">← Back to Home</a>
""")


# ── Request handler ───────────────────────────────────────────────────────

class OAuthHandler(BaseHTTPRequestHandler):

    def log_message(self, fmt, *args):
        print(f"  {self.path}  →  {args[1] if len(args) > 1 else ''}")

    def _send_html(self, body: str, status: int = 200):
        encoded = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.end_headers()
        self.wfile.write(encoded)

    def _redirect(self, url: str):
        self.send_response(302)
        self.send_header("Location", url)
        self.end_headers()

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path   = parsed.path
        params = dict(urllib.parse.parse_qsl(parsed.query))

        if path == "/":
            self._send_html(_home_page())
        elif path == "/login":
            self._handle_login()
        elif path == "/callback":
            self._handle_callback(params)
        else:
            self._send_html("<h1>404</h1>", 404)

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/revoke":
            self._handle_revoke()
        else:
            self._send_html("<h1>404</h1>", 404)

    def _handle_revoke(self):
        if not _last_token:
            self._send_html(_revoke_result_page(
                success=False,
                message="No token held in memory. Complete an OAuth flow first.",
                login="",
            ))
            return

        token = _last_token.get("access_token", "")
        login = _last_token.get("login", "")
        url   = f"https://api.github.com/applications/{CLIENT_ID}/token"

        print(f"[✕] Revoking token for {login}…")
        status = _delete_json(url, CLIENT_ID, CLIENT_SECRET, {"access_token": token})

        if status == 204:
            # Success — clear the in-memory store
            _last_token.clear()
            print(f"[✓] Token revoked (HTTP {status}). Next auth will show consent screen.")
            self._send_html(_revoke_result_page(
                success=True,
                message="Token revoked successfully. GitHub will show the consent screen on the next authorization.",
                login=login,
            ))
        else:
            print(f"[⚠] Revoke returned HTTP {status}")
            self._send_html(_revoke_result_page(
                success=False,
                message=f"GitHub returned HTTP {status}. The token may already be invalid or the client credentials may be wrong.",
                login=login,
            ))

    def _handle_login(self):
        if not CLIENT_ID:
            self._send_html('<p style="color:red">Set GITHUB_CLIENT_ID in .env</p>', 500)
            return

        state              = secrets.token_urlsafe(24)
        verifier, challenge = generate_pkce_pair()
        _sessions[state]   = {
            "verifier":  verifier,
            "challenge": challenge,
            "issued_at": time.monotonic(),  # recorded for code-age tracking
        }

        params = {
            "client_id":             CLIENT_ID,
            "redirect_uri":          REDIRECT_URI,
            "scope":                 SCOPES,
            "state":                 state,
            "code_challenge":        challenge,
            "code_challenge_method": "S256",
        }
        auth_url = AUTHORIZE_URL + "?" + urllib.parse.urlencode(params)
        print(f"\n[→] Redirecting to GitHub:\n    {auth_url}\n")
        self._redirect(auth_url)

    def _handle_callback(self, params: dict):
        # ── CSRF check ────────────────────────────────────────────────────
        state   = params.get("state", "")
        session = _sessions.pop(state, None)
        if not session:
            self._send_html(
                '<p style="color:#e05c5c">Invalid or missing state — possible CSRF attack.</p>',
                400,
            )
            return

        if "error" in params:
            err  = html.escape(params.get("error", ""))
            desc = html.escape(params.get("error_description", ""))
            self._send_html(f'<p style="color:#e05c5c">Error: {err} — {desc}</p>', 400)
            return

        auth_code = params.get("code", "")
        if not auth_code:
            self._send_html('<p style="color:#e05c5c">No code in callback.</p>', 400)
            return

        verifier  = session["verifier"]
        challenge = session["challenge"]

        # ── Code age check ────────────────────────────────────────────────
        code_age             = time.monotonic() - session["issued_at"]
        code_expired_locally = code_age > CODE_MAX_AGE
        if code_expired_locally:
            print(
                f"[⚠] Code age {code_age:.1f} s exceeds CODE_MAX_AGE_SECONDS={CODE_MAX_AGE} — "
                f"proceeding to demonstrate GitHub's own 600 s limit"
            )

        # ── Reconstruct auth URL for display ──────────────────────────────
        auth_url = AUTHORIZE_URL + "?" + urllib.parse.urlencode({
            "client_id":             CLIENT_ID,
            "redirect_uri":          REDIRECT_URI,
            "scope":                 SCOPES,
            "state":                 state,
            "code_challenge":        challenge,
            "code_challenge_method": "S256",
        })

        # ── Token exchange ────────────────────────────────────────────────
        print("[↔] Exchanging code for token…")
        try:
            token_resp = _post_form(TOKEN_URL, {
                "client_id":     CLIENT_ID,
                "client_secret": CLIENT_SECRET,
                "code":          auth_code,
                "redirect_uri":  REDIRECT_URI,
                "code_verifier": verifier,
            })
        except Exception as exc:
            self._send_html(
                f'<pre style="color:#e05c5c">Token exchange failed: {html.escape(str(exc))}</pre>',
                500,
            )
            return

        access_token = token_resp.get("access_token", "")
        if not access_token:
            self._send_html(
                f'<pre style="color:#e05c5c">No access_token:\n'
                f'{html.escape(json.dumps(token_resp, indent=2))}</pre>',
                400,
            )
            return

        # ── Resource server calls ─────────────────────────────────────────
        print("[→] Fetching /user and /user/emails…")
        try:
            user   = _get(USERINFO_URL, access_token)
            emails = _get(EMAILS_URL,   access_token)
        except Exception as exc:
            self._send_html(
                f'<pre style="color:#e05c5c">Resource Server error: {html.escape(str(exc))}</pre>',
                500,
            )
            return

        print(f"[✓] Authenticated as: {user.get('login')}  (code age: {code_age:.1f} s)")

        # Store token in memory so the home page Revoke button can use it
        _last_token["access_token"] = access_token
        _last_token["login"]        = user.get("login", "")

        self._send_html(_callback_page(
            auth_code, state, token_resp, user, emails,
            auth_url, verifier, challenge, code_age, code_expired_locally,
        ))

# ── Entry point ───────────────────────────────────────────────────────────

if __name__ == "__main__":
    port = 8080

    print("\n── GitHub OAuth 2.0 Demo ─────────────────────────────────")
    if not CLIENT_ID or not CLIENT_SECRET:
        print("⚠  GITHUB_CLIENT_ID or GITHUB_CLIENT_SECRET not set.")
        print("   Copy .env.example → .env and fill in your credentials.")
    else:
        print(f"✓  Client ID:          {CLIENT_ID[:8]}…")

    print(f"   Scopes:            {SCOPES}")
    print(f"   Code max age:      {CODE_MAX_AGE} s  (GitHub hard limit: 600 s)")
    print(f"   Simulate ID Token: {SIMULATE_ID_TOKEN}")
    print(f"\n🚀  http://127.0.0.1:{port}")
    print(f"    Callback: {REDIRECT_URI}")
    print("──────────────────────────────────────────────────────────\n")

    server = HTTPServer(("127.0.0.1", port), OAuthHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
