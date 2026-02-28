"""
GitHub OAuth 2.0 / OIDC Flow Demo
----------------------------------
Demonstrates the full Authorization Code Grant flow with:
  - state parameter (CSRF protection)
  - PKCE (code_challenge / code_verifier) [shift-left security]
  - Authorization Code exchange for Access Token
  - Token introspection via GitHub /user endpoint
  - Live configuration via /config GUI (no restart required)
  - Token revocation via DELETE /applications/{client_id}/token

Design
------
State is managed through three single-instance classes defined near the top
of this file. Each is self-contained and clearly marked as extractable to
its own module when the project grows:

  Config        — runtime settings (scopes, code_max_age, feature flags)
  SessionStore  — in-flight PKCE sessions keyed by OAuth state token
  TokenStore    — most recently issued access token (for revocation)
  FlowStore     — intermediate state between step-through pause points
  StepRenderer  — HTML renderers for the four step-through pause pages

Module-level singletons (cfg, session_store, token_store) are shared across
all request handlers via module scope.

Usage
-----
  1. Copy .env.example to .env and fill in CLIENT_ID / CLIENT_SECRET
  2. pip install -r requirements.txt
  3. python app.py
  4. Open http://127.0.0.1:8080

Optional env vars (all configurable live via /config):
  GITHUB_SCOPES          Space-separated scopes   (default: "read:user user:email")
  CODE_MAX_AGE_SECONDS   Local code expiry guard  (default: 600, max: 600)
  SIMULATE_ID_TOKEN      Show simulated JWT        (default: false)
  SHOW_RAW_JSON          Show raw /user JSON       (default: true)
  STEP_THROUGH           Pause at each flow stage  (default: false)
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

# ── GitHub endpoints ──────────────────────────────────────────────────────
AUTHORIZE_URL = "https://github.com/login/oauth/authorize"
TOKEN_URL     = "https://github.com/login/oauth/access_token"
USERINFO_URL  = "https://api.github.com/user"
EMAILS_URL    = "https://api.github.com/user/emails"


# ─────────────────────────────────────────────────────────────────────────
# Config
# ─────────────────────────────────────────────────────────────────────────
# Seeded from environment variables on startup.
# All values are mutable at runtime via the /config GUI — no restart needed.
# Extractable to config.py when the project grows into multiple modules.
# ─────────────────────────────────────────────────────────────────────────

class Config:
    """
    Runtime configuration for the OAuth demo app.

    Attributes map 1-to-1 with environment variables and the /config form
    fields. Adding a new setting requires:
      1. A default in DEFAULTS
      2. A line in __init__ to read from env
      3. A line in update() to accept the new value
      4. A field in the /config page template
    """

    DEFAULTS: dict = {
        "scopes":            "read:user user:email",
        "code_max_age":      600,
        "simulate_id_token": False,
        "show_raw_json":     True,
        "step_through":      False,
    }

    # ref: https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/scopes-for-oauth-apps
    KNOWN_SCOPES: list[tuple[str, str]] = [
        ("read:user",     "Read public profile data"),
        ("user",          "Read/write all profile data"),
        ("user:email",    "Access email addresses"),
        ("user:follow",   "Follow/unfollow users"),
        ("repo",          "Full access to repositories"),
        ("public_repo",   "Read/write public repositories"),
        ("read:org",      "Read org membership & teams"),
        ("admin:org",     "Full org admin access"),
        ("gist",          "Create/edit gists"),
        ("notifications", "Access notifications"),
    ]

    def __init__(self) -> None:
        self.scopes            = os.environ.get("GITHUB_SCOPES",   self.DEFAULTS["scopes"]).strip()
        self.code_max_age      = self._parse_max_age(os.environ.get("CODE_MAX_AGE_SECONDS", "600"))
        self.simulate_id_token = os.environ.get("SIMULATE_ID_TOKEN", "false").lower() == "true"
        self.show_raw_json     = os.environ.get("SHOW_RAW_JSON",   "true").lower()  != "false"
        self.step_through      = os.environ.get("STEP_THROUGH",    "false").lower() == "true"

    # ── Mutation ──────────────────────────────────────────────────────────

    def update(self, *,
               scopes: str | None             = None,
               code_max_age: int | None       = None,
               simulate_id_token: bool | None = None,
               show_raw_json: bool | None     = None,
               step_through: bool | None      = None) -> None:
        """Apply one or more setting changes. Unspecified values are unchanged."""
        if scopes            is not None: self.scopes            = scopes.strip() or self.DEFAULTS["scopes"]
        if code_max_age      is not None: self.code_max_age      = self._parse_max_age(str(code_max_age))
        if simulate_id_token is not None: self.simulate_id_token = simulate_id_token
        if show_raw_json     is not None: self.show_raw_json     = show_raw_json
        if step_through      is not None: self.step_through      = step_through

    def reset(self) -> None:
        """Restore all settings to their compile-time defaults."""
        self.scopes            = self.DEFAULTS["scopes"]
        self.code_max_age      = self.DEFAULTS["code_max_age"]
        self.simulate_id_token = self.DEFAULTS["simulate_id_token"]
        self.show_raw_json     = self.DEFAULTS["show_raw_json"]
        self.step_through      = self.DEFAULTS["step_through"]

    def as_dict(self) -> dict:
        """Snapshot of current values — useful for logging and templates."""
        return {
            "scopes":            self.scopes,
            "code_max_age":      self.code_max_age,
            "simulate_id_token": self.simulate_id_token,
            "show_raw_json":     self.show_raw_json,
            "step_through":      self.step_through,
        }

    def __repr__(self) -> str:
        d = self.as_dict()
        return (f"Config(scopes={d['scopes']!r}, code_max_age={d['code_max_age']}s, "
                f"simulate_id_token={d['simulate_id_token']}, show_raw_json={d['show_raw_json']}, "
                f"step_through={d['step_through']})")

    # ── Private helpers ───────────────────────────────────────────────────

    @staticmethod
    def _parse_max_age(raw: str) -> int:
        try:
            return max(1, min(600, int(raw)))
        except ValueError:
            return 600


# ─────────────────────────────────────────────────────────────────────────
# SessionStore
# ─────────────────────────────────────────────────────────────────────────
# Holds in-flight PKCE sessions keyed by the OAuth state parameter.
# Each entry lives only for the duration of a single authorization round-trip
# and is consumed (popped) at /callback.
# Extractable to session.py when the project grows.
# ─────────────────────────────────────────────────────────────────────────

class SessionStore:
    """PKCE session state for in-flight authorization requests."""

    def __init__(self) -> None:
        self._store: dict[str, dict] = {}

    def create(self, state: str, verifier: str, challenge: str) -> None:
        """Record a new session keyed by state token."""
        self._store[state] = {
            "verifier":  verifier,
            "challenge": challenge,
            "issued_at": time.monotonic(),
        }

    def peek(self, state: str) -> dict | None:
        """Return session data without removing it (used by step-through mode)."""
        return self._store.get(state)

    def consume(self, state: str) -> dict | None:
        """Return and remove the session for state, or None if not found."""
        return self._store.pop(state, None)

    def __len__(self) -> int:
        return len(self._store)


# ─────────────────────────────────────────────────────────────────────────
# TokenStore
# ─────────────────────────────────────────────────────────────────────────
# Holds the most recently issued access token in memory so the Revoke
# button always has something to act on.
# Single-user demo scope — one token at a time is sufficient.
# Extractable to token_store.py when the project grows.
# ─────────────────────────────────────────────────────────────────────────

class TokenStore:
    """In-memory store for the most recently issued access token."""

    def __init__(self) -> None:
        self._token: str = ""
        self._login: str = ""

    def save(self, access_token: str, login: str) -> None:
        self._token = access_token
        self._login = login

    def clear(self) -> None:
        self._token = ""
        self._login = ""

    @property
    def token(self) -> str:
        return self._token

    @property
    def login(self) -> str:
        return self._login

    @property
    def has_token(self) -> bool:
        return bool(self._token)


# ── Module-level singletons ───────────────────────────────────────────────
# One instance each — shared across all request handlers via module scope.

cfg           = Config()
session_store = SessionStore()
token_store   = TokenStore()


# ─────────────────────────────────────────────────────────────────────────
# FlowStore
# ─────────────────────────────────────────────────────────────────────────
# Holds intermediate state between step-through pause points.
# In normal (non-step-through) mode this is never written to.
# Extractable to flow_store.py when the project grows.
# ─────────────────────────────────────────────────────────────────────────

class FlowStore:
    """
    Carries in-progress OAuth flow data between step-through pause pages.

    Lifecycle:
      start()        called at /login when step_through is enabled
      save_callback() called when GitHub returns to /callback
      save_token()   called after token exchange succeeds
      clear()        called after the final results page is shown
    """

    def __init__(self) -> None:
        self._data: dict = {}

    def start(self, state: str, verifier: str, challenge: str, auth_url: str,
              auth_params: dict) -> None:
        self._data = {
            "state":       state,
            "verifier":    verifier,
            "challenge":   challenge,
            "auth_url":    auth_url,
            "auth_params": auth_params,
            "started_at":  time.monotonic(),
        }

    def save_callback(self, auth_code: str, code_age: float,
                      code_expired_locally: bool) -> None:
        self._data.update({
            "auth_code":            auth_code,
            "code_age":             code_age,
            "code_expired_locally": code_expired_locally,
        })

    def save_token(self, token_resp: dict) -> None:
        self._data["token_resp"] = token_resp

    def clear(self) -> None:
        self._data = {}

    @property
    def active(self) -> bool:
        return bool(self._data)

    @property
    def state(self) -> str:
        return self._data.get("state", "")

    @property
    def verifier(self) -> str:
        return self._data.get("verifier", "")

    @property
    def challenge(self) -> str:
        return self._data.get("challenge", "")

    @property
    def auth_url(self) -> str:
        return self._data.get("auth_url", "")

    @property
    def auth_params(self) -> dict:
        return self._data.get("auth_params", {})

    @property
    def auth_code(self) -> str:
        return self._data.get("auth_code", "")

    @property
    def code_age(self) -> float:
        return self._data.get("code_age", 0.0)

    @property
    def code_expired_locally(self) -> bool:
        return self._data.get("code_expired_locally", False)

    @property
    def token_resp(self) -> dict:
        return self._data.get("token_resp", {})


flow_store = FlowStore()


# ─────────────────────────────────────────────────────────────────────────
# StepRenderer
# ─────────────────────────────────────────────────────────────────────────
# Renders the four step-through pause pages.
# Each page shows a Request panel (what's about to be sent) and a
# Response panel (either "waiting…" or the actual response), then a
# Continue button that POSTs to fire the real network call.
# Extractable to step_renderer.py when the project grows.
# ─────────────────────────────────────────────────────────────────────────

class StepRenderer:
    """HTML renderers for each step-through pause point."""

    TOTAL_STEPS = 4

    # ── Shared step-through CSS injected into each pause page ─────────────
    _STEP_CSS = """
    .step-header{display:flex;align-items:center;gap:1.2rem;margin-bottom:1.8rem}
    .step-badge{font-family:monospace;font-size:0.72rem;color:#7a8298;
                background:#1e2a3a;border:1px solid #252d3d;border-radius:4px;
                padding:0.25rem 0.7rem;letter-spacing:0.08em;white-space:nowrap}
    .step-progress{flex:1;height:3px;background:#1e2a3a;border-radius:2px;overflow:hidden}
    .step-progress-fill{height:100%;border-radius:2px;
                        background:linear-gradient(90deg,#3b7dd8,#00d4aa);
                        transition:width 0.4s ease}
    .panel{border-radius:8px;border:1px solid #252d3d;overflow:hidden;margin:0.8rem 0}
    .panel-header{padding:0.5rem 1rem;font-family:monospace;font-size:0.72rem;
                  letter-spacing:0.08em;text-transform:uppercase;
                  display:flex;align-items:center;gap:0.5rem}
    .panel-req .panel-header{background:#1a2a1a;border-bottom:1px solid #2a3a2a;color:#00d4aa}
    .panel-res .panel-header{background:#1a1a2a;border-bottom:1px solid #252d3d;color:#3b7dd8}
    .panel-body{padding:1rem 1.2rem;background:#0a0c10}
    .panel-body pre{margin:0;font-size:0.78rem;line-height:1.7;
                    white-space:pre-wrap;word-break:break-all}
    .param-table{width:100%;border-collapse:collapse}
    .param-table td{padding:0.28rem 0.6rem;font-size:0.8rem;
                    border-bottom:1px solid #1a2035;vertical-align:top}
    .param-table td:first-child{font-family:monospace;color:#00d4aa;
                                white-space:nowrap;width:28%}
    .param-table td:last-child{color:#c8d0e0;word-break:break-all}
    .param-table .note{color:#4a5268;font-size:0.72rem;display:block;margin-top:0.15rem}
    .waiting{color:#4a5268;font-family:monospace;font-size:0.82rem;
             padding:1rem;font-style:italic}
    .step-actions{display:flex;gap:1rem;align-items:center;margin-top:1.5rem;flex-wrap:wrap}
    .skip-link{font-size:0.78rem;color:#4a5268;text-decoration:none;font-family:monospace}
    .skip-link:hover{color:#7a8298}
    .method-badge{display:inline-block;font-family:monospace;font-size:0.68rem;
                  padding:0.1rem 0.45rem;border-radius:3px;font-weight:600;
                  letter-spacing:0.05em;margin-right:0.4rem}
    .get-badge{background:rgba(0,212,170,0.15);color:#00d4aa;border:1px solid #00d4aa}
    .post-badge{background:rgba(59,125,216,0.15);color:#3b7dd8;border:1px solid #3b7dd8}
    """

    @staticmethod
    def _step_page(title: str, step: int, body: str) -> str:
        pct = int(step / StepRenderer.TOTAL_STEPS * 100)
        header = f"""
        <div class="step-header">
          <div class="step-badge">Step {step} of {StepRenderer.TOTAL_STEPS}</div>
          <div class="step-progress">
            <div class="step-progress-fill" style="width:{pct}%"></div>
          </div>
        </div>"""
        full_body = f"<style>{StepRenderer._STEP_CSS}</style>{header}{body}"
        return _page(title, full_body)

    @staticmethod
    def _param_rows(params: dict, notes: dict | None = None) -> str:
        notes = notes or {}
        rows = ""
        for k, v in params.items():
            note = notes.get(k, "")
            note_html = f'<span class="note">{html.escape(note)}</span>' if note else ""
            rows += (f'<tr><td>{html.escape(k)}</td>'
                     f'<td>{html.escape(str(v))}{note_html}</td></tr>')
        return rows

    # ── Step 1: Authorization request preview ─────────────────────────────

    @staticmethod
    def step1_authorize(state: str, auth_params: dict, auth_url: str) -> str:
        notes = {
            "client_id":             "Your app's identifier, registered with GitHub",
            "response_type":         "We want an authorization code back, not a token",
            "redirect_uri":          "Must match exactly what's registered in your OAuth App",
            "scope":                 "Permissions being requested from the user",
            "state":                 "Random CSRF token — verified when GitHub redirects back",
            "code_challenge":        "SHA-256 hash of the code_verifier (PKCE S256)",
            "code_challenge_method": "Tells GitHub which hash algorithm was used",
        }
        # Build the display params with response_type added
        display_params = {"response_type": "code"} | auth_params

        return StepRenderer._step_page("Step 1 — Authorization Request", 1, f"""
<h1>Step 1 — Authorization Request</h1>
<p class="label">About to redirect the browser to GitHub's Authorization Endpoint</p>

<div class="card">
  <h2>What's happening</h2>
  <p style="font-size:0.88rem;line-height:1.65">
    Your browser is about to be redirected to GitHub with the parameters below.
    GitHub will authenticate the user and show a consent screen listing the
    requested scopes. After approval, GitHub redirects back to
    <code>{html.escape(REDIRECT_URI)}</code> with a short-lived authorization code.
  </p>
  <p style="font-size:0.85rem;line-height:1.65">
    <strong>PKCE note:</strong> the <code>code_challenge</code> is sent now so
    GitHub can bind the code to this specific request. The verifier stays on
    the server — never sent to the browser.
  </p>
</div>

<div class="panel panel-req">
  <div class="panel-header">
    <span class="method-badge get-badge">GET</span>
    Request — Authorization Endpoint
  </div>
  <div class="panel-body">
    <pre style="color:#00d4aa;margin-bottom:0.8rem">{html.escape(auth_url)}</pre>
    <table class="param-table">
      {StepRenderer._param_rows(display_params, notes)}
    </table>
  </div>
</div>

<div class="panel panel-res">
  <div class="panel-header">Response — pending user action at GitHub</div>
  <div class="panel-body">
    <div class="waiting">
      ⏳ GitHub will redirect back to /callback with an authorization code
      and the original state token once the user approves…
    </div>
  </div>
</div>

<div class="step-actions">
  <form method="POST" action="/step/redirect">
    <input type="hidden" name="state" value="{html.escape(state)}">
    <button class="btn btn-accent" type="submit">Send to GitHub →</button>
  </form>
  <a class="skip-link" href="/step/skip?state={html.escape(urllib.parse.quote(state))}">
    Skip step-through and run full flow
  </a>
</div>
""")

    # ── Step 2: Callback received, preview token exchange ─────────────────

    @staticmethod
    def step2_exchange(state: str, auth_code: str, code_age: float,
                       code_expired_locally: bool, verifier: str,
                       challenge: str) -> str:
        age_cls   = "err" if code_expired_locally else "ok"
        age_label = f"{code_age:.1f} s"
        exchange_params = {
            "grant_type":    "authorization_code",
            "code":          auth_code,
            "redirect_uri":  REDIRECT_URI,
            "client_id":     CLIENT_ID,
            "code_verifier": verifier,
        }
        exchange_notes = {
            "grant_type":    "RFC 6749 §4.1.3 — identifies this as a code exchange",
            "code":          "The short-lived code just received from GitHub",
            "redirect_uri":  "Must be identical to the one in the authorization request",
            "client_id":     "Sent in body (GitHub's preference) or HTTP Basic Auth",
            "code_verifier": "The original random string — GitHub re-derives the challenge to verify",
        }
        callback_params = {
            "code":  auth_code,
            "state": state,
        }
        callback_notes = {
            "code":  "Single-use authorization code, expires in 600 s (GitHub hard limit)",
            "state": "Matches the value we sent — CSRF check passed ✓",
        }
        expired_warn = (
            f'<p class="err" style="font-size:0.85rem">⚠ Code age ({age_label}) exceeds '
            f'CODE_MAX_AGE_SECONDS ({cfg.code_max_age} s). '
            f'Continuing to demonstrate GitHub\'s own 600 s limit.</p>'
            if code_expired_locally else ""
        )

        return StepRenderer._step_page("Step 2 — Token Exchange", 2, f"""
<h1>Step 2 — Token Exchange</h1>
<p class="label">GitHub redirected back with an authorization code — ready to exchange it</p>

<div class="card">
  <h2>Callback received</h2>
  <p style="font-size:0.88rem;line-height:1.65">
    GitHub redirected to <code>/callback</code> with the parameters below.
    The state token has been verified (CSRF check passed). Now the server
    will POST directly to GitHub's Token Endpoint — the browser is
    not involved in this exchange.
  </p>
  <p style="font-size:0.88rem;line-height:1.65">
    Code age: <span class="{age_cls}"><strong>{age_label}</strong></span>
    (GitHub hard limit: 600 s · your guard: {cfg.code_max_age} s)
  </p>
  {expired_warn}
</div>

<div class="panel panel-res">
  <div class="panel-header">
    <span class="method-badge get-badge">GET</span>
    Received — /callback from GitHub
  </div>
  <div class="panel-body">
    <table class="param-table">
      {StepRenderer._param_rows(callback_params, callback_notes)}
    </table>
  </div>
</div>

<div class="panel panel-req">
  <div class="panel-header">
    <span class="method-badge post-badge">POST</span>
    About to send — Token Endpoint
    <span style="color:#4a5268;font-size:0.75rem;margin-left:0.3rem">
      {html.escape(TOKEN_URL)}
    </span>
  </div>
  <div class="panel-body">
    <p style="font-size:0.75rem;color:#4a5268;margin:0 0 0.7rem;font-family:monospace">
      Auth: HTTP Basic ({html.escape(CLIENT_ID[:8])}… : &lt;secret&gt;) ·
      Content-Type: application/x-www-form-urlencoded
    </p>
    <table class="param-table">
      {StepRenderer._param_rows(exchange_params, exchange_notes)}
    </table>
  </div>
</div>

<div class="panel panel-res">
  <div class="panel-header">Response — waiting for token</div>
  <div class="panel-body">
    <div class="waiting">⏳ GitHub will return an access_token, token_type, and scope…</div>
  </div>
</div>

<div class="step-actions">
  <form method="POST" action="/step/exchange">
    <input type="hidden" name="state" value="{html.escape(state)}">
    <button class="btn btn-accent" type="submit">Exchange Code for Token →</button>
  </form>
  <a class="skip-link" href="/step/skip?state={html.escape(urllib.parse.quote(state))}">
    Skip step-through and complete flow
  </a>
</div>
""")

    # ── Step 3: Token received, preview resource server calls ─────────────

    @staticmethod
    def step3_userinfo(state: str, token_resp: dict) -> str:
        access_token = token_resp.get("access_token", "")
        token_type   = token_resp.get("token_type", "")
        granted_scope = token_resp.get("scope", "")
        requested_scopes = set(cfg.scopes.split())
        granted_scopes   = set(granted_scope.split(",")) if granted_scope else set()
        scope_rows = ""
        for s in sorted(requested_scopes | granted_scopes):
            req = "✓" if s in requested_scopes else "—"
            grn = '<span class="ok">✓</span>' if s in granted_scopes else '<span class="err">✗</span>'
            scope_rows += f"<tr><td><code>{html.escape(s)}</code></td><td>{req}</td><td>{grn}</td></tr>"

        token_preview = access_token[:12] + "…" if access_token else "—"

        return StepRenderer._step_page("Step 3 — Resource Server Calls", 3, f"""
<h1>Step 3 — Resource Server Calls</h1>
<p class="label">Token received — ready to call the GitHub API</p>

<div class="card">
  <h2>Token response</h2>
  <p style="font-size:0.88rem;line-height:1.65">
    The token exchange succeeded. The access token is an
    <strong>opaque string</strong> — no expiry claim, no structure to decode,
    no <code>exp</code> field. Identity must be confirmed by calling the API.
    This is a key difference from OIDC, where a signed ID Token carries
    identity claims that can be verified locally.
  </p>
  <table style="margin-top:0.8rem">
    <tr><th>Field</th><th>Value</th><th>Note</th></tr>
    <tr><td><code>access_token</code></td>
        <td><code>{html.escape(token_preview)}</code></td>
        <td>Opaque — begins <code>gho_</code>, no exp</td></tr>
    <tr><td><code>token_type</code></td>
        <td><code>{html.escape(token_type)}</code></td>
        <td>Always <code>bearer</code> for GitHub</td></tr>
    <tr><td><code>scope</code></td>
        <td><code>{html.escape(granted_scope)}</code></td>
        <td>Comma-separated (GitHub) vs space-separated (RFC 6749)</td></tr>
  </table>

  <h2 style="margin-top:1.2rem">Scope comparison</h2>
  <table>
    <tr><th>Scope</th><th>Requested</th><th>Granted</th></tr>
    {scope_rows}
  </table>
</div>

<div class="panel panel-req">
  <div class="panel-header">
    <span class="method-badge get-badge">GET</span>
    About to send — Resource Server × 2
  </div>
  <div class="panel-body">
    <table class="param-table">
      <tr><td>GET {html.escape(USERINFO_URL)}</td>
          <td>Authorization: Bearer {html.escape(token_preview)}
            <span class="note">Returns public profile, login, avatar, bio…</span></td></tr>
      <tr><td>GET {html.escape(EMAILS_URL)}</td>
          <td>Authorization: Bearer {html.escape(token_preview)}
            <span class="note">Returns verified email list (requires user:email scope)</span></td></tr>
    </table>
  </div>
</div>

<div class="panel panel-res">
  <div class="panel-header">Response — waiting for /user and /user/emails</div>
  <div class="panel-body">
    <div class="waiting">⏳ GitHub API will return profile JSON and email list…</div>
  </div>
</div>

<div class="step-actions">
  <form method="POST" action="/step/userinfo">
    <input type="hidden" name="state" value="{html.escape(state)}">
    <button class="btn btn-accent" type="submit">Call Resource Server →</button>
  </form>
  <a class="skip-link" href="/step/skip?state={html.escape(urllib.parse.quote(state))}">
    Skip to results
  </a>
</div>
""")


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
  /* ── Nav bar ── */
  .nav{display:flex;gap:0.5rem;align-items:center;margin-bottom:2rem;
       padding-bottom:1rem;border-bottom:1px solid #252d3d;flex-wrap:wrap}
  .nav-link{display:inline-block;padding:0.35rem 0.9rem;border:1px solid #252d3d;
            border-radius:5px;color:#7a8298;text-decoration:none;font-size:0.82rem;
            font-family:monospace;transition:all 0.15s}
  .nav-link:hover{border-color:#00d4aa;color:#00d4aa}
  .nav-link.active{border-color:#00d4aa;color:#00d4aa;background:rgba(0,212,170,0.08)}
  .nav-sep{color:#252d3d;font-size:1.2rem;user-select:none}
  /* ── Config form ── */
  .cfg-form label{display:block;font-family:monospace;font-size:0.72rem;color:#7a8298;
                  letter-spacing:0.07em;text-transform:uppercase;margin-bottom:0.35rem}
  .cfg-form input[type=text],.cfg-form input[type=number]{
    width:100%;background:#0d0f14;border:1px solid #252d3d;color:#e8eaf0;
    padding:0.55rem 0.9rem;border-radius:6px;font-family:monospace;font-size:0.88rem;
    outline:none;box-sizing:border-box;transition:border-color 0.15s}
  .cfg-form input:focus{border-color:#00d4aa}
  .cfg-form .field{margin-bottom:1.2rem}
  .cfg-form .hint{font-size:0.75rem;color:#4a5268;margin-top:0.3rem;font-family:monospace}
  .cfg-form .toggle-row{display:flex;align-items:center;gap:0.8rem}
  .toggle{position:relative;width:44px;height:24px;flex-shrink:0}
  .toggle input{opacity:0;width:0;height:0}
  .toggle-slider{position:absolute;inset:0;background:#252d3d;border-radius:24px;
                 cursor:pointer;transition:0.2s}
  .toggle-slider:before{content:'';position:absolute;width:18px;height:18px;
                         left:3px;top:3px;background:#7a8298;border-radius:50%;transition:0.2s}
  .toggle input:checked + .toggle-slider{background:rgba(0,212,170,0.25);
                                          border:1px solid #00d4aa}
  .toggle input:checked + .toggle-slider:before{transform:translateX(20px);background:#00d4aa}
  .cfg-saved{background:rgba(0,212,170,0.1);border:1px solid #00d4aa;border-radius:6px;
             padding:0.7rem 1rem;color:#00d4aa;font-family:monospace;font-size:0.82rem;
             margin-bottom:1rem;display:none}
  .cfg-saved.show{display:block}
</style>
"""


def _nav(active: str = "") -> str:
    links = [("home", "/", "Home"), ("config", "/config", "⚙ Config")]
    items = ""
    for key, href, label in links:
        cls = ' class="nav-link active"' if key == active else ' class="nav-link"'
        items += f'<a{cls} href="{href}">{label}</a>'
    return f'<div class="nav">{items}</div>'


def _page(title: str, body: str, active_nav: str = "home") -> str:
    return (f'<!DOCTYPE html><html lang="en"><head>\n'
            f'<meta charset="UTF-8"><title>{title}</title>{_CSS}</head>\n'
            f'<body>{_nav(active_nav)}{body}</body></html>')

# ── Home page ─────────────────────────────────────────────────────────────

def _home_page() -> str:
    cred_status = (
        f'<p class="ok">✓ Client ID loaded: <code>{CLIENT_ID[:8]}…</code></p>'
        if CLIENT_ID else
        '<p class="err">⚠ GITHUB_CLIENT_ID not set — edit your .env file and restart.</p>'
    )
    scope_list    = " ".join(f"<code>{html.escape(s)}</code>" for s in cfg.scopes.split())
    code_age_note = (
        f'<span class="ok">{cfg.code_max_age} s</span> '
        f'{"(matches GitHub hard limit)" if cfg.code_max_age == 600 else "(stricter than GitHub — good for demos)"}'
    )
    id_token_note = (
        '<span class="ok">enabled</span> — simulated JWT shown after auth'
        if cfg.simulate_id_token else
        '<span class="warn">disabled</span> — set <code>cfg.simulate_id_token=true</code> to enable'
    )

    # Revoke button — only shown when a token is held in memory
    if token_store.has_token:
        login        = html.escape(token_store.login)
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
    <tr>
      <td>Show raw /user JSON</td>
      <td>{'<span class="ok">enabled</span>' if cfg.show_raw_json else '<span class="warn">disabled</span>'}</td>
      <td><code>SHOW_RAW_JSON</code></td>
    </tr>
    <tr>
      <td>Step-through mode</td>
      <td>{'<span class="ok">enabled</span> — flow will pause at each stage' if cfg.step_through else '<span class="muted">disabled</span>'}</td>
      <td><code>STEP_THROUGH</code></td>
    </tr>
  </table>
  <p style="margin-top:0.8rem;font-size:0.78rem">
    <a href="/config">⚙ Change configuration →</a>
  </p>
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
  {"<div class='step'>⑥ A <strong>simulated ID Token JWT</strong> is constructed from the /user response to illustrate OIDC structure. Clearly labelled — not cryptographically valid.</div>" if cfg.simulate_id_token else ""}
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
    requested  = set(cfg.scopes.split())
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
    age_colour = "ok" if code_age <= cfg.code_max_age else "err"
    age_label  = f'<span class="{age_colour}">{code_age:.1f} s</span>'
    if code_expired_locally:
        age_banner = (
            f'<p class="err">⚠ Code age ({code_age:.1f} s) exceeded CODE_MAX_AGE_SECONDS '
            f'({cfg.code_max_age} s). In production this request would be rejected before the '
            f'exchange attempt. The exchange was attempted here to demonstrate GitHub\'s '
            f'own 600 s hard limit separately.</p>'
        )
    else:
        age_banner = (
            f'<p class="ok">✓ Code age {age_label} is within the {cfg.code_max_age} s '
            f'local limit (GitHub hard limit: 600 s).</p>'
        )

    # Simulated ID Token section
    id_token_html = ""
    if cfg.simulate_id_token:
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

    step_offset   = 1 if cfg.simulate_id_token else 0
    user_step     = f"⑥" if not cfg.simulate_id_token else "⑦"
    compare_step  = f"⑦" if not cfg.simulate_id_token else "⑧"
    id_token_row  = (
        '<span class="warn">✗ Not issued — simulated above</span>'
        if cfg.simulate_id_token else
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
    <tr><td>scope</td><td><code>{html.escape(cfg.scopes)}</code></td>
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
      <td><span class="{'ok' if cfg.code_max_age <= 600 else 'warn'}">{cfg.code_max_age} s</span></td>
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
  {"<h2>Raw /user JSON</h2><pre>" + _j(user) + "</pre>" if cfg.show_raw_json else ""}
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
    <tr>
      <td><code>prompt=consent</code></td>
      <td class="err">✗ Not supported — GitHub suppresses the consent
          screen after first authorization, even after token revocation,
          if the same scopes are re-requested in the same browser session</td>
      <td class="ok">✓ Forces consent screen on every flow regardless
          of prior grants — required for step-up auth and re-authorization
          UX patterns</td>
    </tr>
  </table>

  <!-- ── prompt=consent callout ── -->
  <div style="margin-top:1.2rem;padding:1rem 1.2rem;border-radius:8px;
              background:#0f1a2b;border:1px solid #3b7dd8">
    <div style="font-family:monospace;font-size:0.72rem;color:#3b7dd8;
                letter-spacing:0.08em;text-transform:uppercase;margin-bottom:0.6rem">
      ⓘ Why Revoke didn't show a consent screen
    </div>
    <p style="font-size:0.85rem;line-height:1.65;margin:0 0 0.6rem">
      The revocation above succeeded — GitHub returned <code>204 No Content</code>
      and the grant was destroyed. However, because GitHub OAuth Apps don't support
      the <code>prompt=consent</code> parameter, GitHub silently re-authorized the
      app when the same scopes were re-requested in the same browser session.
    </p>
    <p style="font-size:0.85rem;line-height:1.65;margin:0 0 0.6rem">
      <strong style="color:#e8eaf0">To trigger the consent screen manually:</strong>
      go to
      <a href="https://github.com/settings/applications" target="_blank">
        GitHub → Settings → Authorized OAuth Apps
      </a>
      and revoke the app there, then run the flow again.
      Alternatively, request a <em>new scope</em> the app hasn't been granted before —
      GitHub must show the screen when new permissions are needed.
    </p>
    <p style="font-size:0.85rem;line-height:1.65;margin:0">
      <strong style="color:#e8eaf0">OIDC providers solve this properly.</strong>
      Platforms like PingOne, Okta, Auth0, and Google Identity support
      <code>prompt=consent</code> (and <code>prompt=login</code>,
      <code>prompt=select_account</code>), giving applications explicit control
      over the authentication UX on every request — no workarounds needed.
    </p>
  </div>
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
        'Click <strong>Start OAuth Flow</strong> to run a fresh authorization.<br>'
        '<span class="warn">⚠ Note:</span> GitHub OAuth Apps do not support '
        '<code>prompt=consent</code>, so GitHub may silently re-authorize if '
        'the same scopes are re-requested in the same browser session. '
        'To force the consent screen, request a new scope or revoke the app directly in '
        '<a href="https://github.com/settings/applications" target="_blank">'
        'GitHub → Settings → Authorized OAuth Apps</a>.</p>'
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


# ── Config page ───────────────────────────────────────────────────────────

# All known GitHub OAuth scopes for the multi-select helper
Config.KNOWN_SCOPES = [
    ("read:user",   "Read public profile data"),
    ("user",        "Read/write all profile data"),
    ("user:email",  "Access email addresses"),
    ("user:follow", "Follow/unfollow users"),
    ("repo",        "Full access to repositories"),
    ("public_repo", "Read/write public repositories"),
    ("read:org",    "Read org membership & teams"),
    ("admin:org",   "Full org admin access"),
    ("gist",        "Create/edit gists"),
    ("notifications", "Access notifications"),
]

def _config_page(saved: bool = False, reset: bool = False) -> str:
    active_scopes = set(cfg.scopes.split())

    scope_checkboxes = ""
    for scope, desc in Config.KNOWN_SCOPES:
        checked = "checked" if scope in active_scopes else ""
        scope_checkboxes += f"""
      <label style="display:flex;align-items:center;gap:0.6rem;padding:0.3rem 0;
                    cursor:pointer;font-size:0.85rem;font-family:monospace">
        <input type="checkbox" name="scope" value="{scope}" {checked}
               style="accent-color:#00d4aa;width:15px;height:15px">
        <span><code style="color:#00d4aa">{scope}</code>
          <span style="color:#4a5268;font-size:0.75rem"> — {desc}</span>
        </span>
      </label>"""

    if reset:
        saved_banner = '<div class="cfg-saved show">↺ Configuration reset to defaults.</div>'
    elif saved:
        saved_banner = '<div class="cfg-saved show">✓ Configuration saved — takes effect on the next OAuth flow.</div>'
    else:
        saved_banner = ''

    sim_checked   = "checked" if cfg.simulate_id_token else ""
    json_checked  = "checked" if cfg.show_raw_json     else ""
    step_checked  = "checked" if cfg.step_through      else ""

    return _page("Configuration", f"""
<h1>Configuration</h1>
<p class="label">Changes take effect immediately — no restart required. Reset to defaults by restarting the server.</p>

{saved_banner}

<form class="cfg-form" method="POST" action="/config">

  <!-- ── Scopes ── -->
  <div class="card">
    <h2>OAuth Scopes</h2>
    <p style="font-size:0.82rem;color:#7a8298;margin-bottom:1rem">
      Select the scopes to request from GitHub. The user will be asked to grant
      these on the consent screen. GitHub may grant fewer than requested.
      <a href="https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/scopes-for-oauth-apps"
         target="_blank" style="font-size:0.75rem">Full scope reference ↗</a>
    </p>
    {scope_checkboxes}
    <div class="field" style="margin-top:1rem">
      <label>Custom / additional scopes</label>
      <input type="text" name="custom_scopes"
             placeholder="e.g. workflow delete_repo  (space-separated)"
             value="">
      <div class="hint">Added on top of the checked scopes above.</div>
    </div>
  </div>

  <!-- ── Code expiry ── -->
  <div class="card">
    <h2>Authorization Code Max Age</h2>
    <div class="field">
      <label>Max age (seconds)</label>
      <input type="number" name="code_max_age" min="1" max="600"
             value="{cfg.code_max_age}">
      <div class="hint">
        GitHub hard-expires codes after <strong>600 s (10 min)</strong> — this cannot be changed.
        Set a lower value here to add a stricter local guard and observe the behaviour.
        Recommended: <code>30</code> for demos, <code>600</code> for normal use.
      </div>
    </div>
  </div>

  <!-- ── Display toggles ── -->
  <div class="card">
    <h2>Display Options</h2>

    <div class="field">
      <div class="toggle-row">
        <label class="toggle">
          <input type="checkbox" name="step_through" {step_checked}>
          <span class="toggle-slider"></span>
        </label>
        <div>
          <div style="font-size:0.88rem">Step-through Mode
            <span style="font-family:monospace;font-size:0.68rem;background:#1a2a44;
                         border:1px solid #3b7dd8;color:#3b7dd8;padding:0.1rem 0.45rem;
                         border-radius:3px;margin-left:0.4rem">DEMO</span>
          </div>
          <div class="hint">Pause the OAuth flow at each stage — authorization request,
          callback, token exchange, and resource server calls — showing the exact
          request and response at each step before proceeding.
          Ideal for walkthroughs and presentations.</div>
        </div>
      </div>
    </div>

    <div class="field" style="margin-top:1.2rem">
      <div class="toggle-row">
        <label class="toggle">
          <input type="checkbox" name="simulate_id_token" {sim_checked}>
          <span class="toggle-slider"></span>
        </label>
        <div>
          <div style="font-size:0.88rem">Simulate ID Token</div>
          <div class="hint">Construct a JWT-shaped simulated OIDC ID Token from the
          <code>/user</code> response after auth. Clearly labelled as not valid.
          Useful for explaining what a real ID Token looks like.
          <br><em>Note: GitHub OAuth Apps do not issue real ID Tokens.</em></div>
        </div>
      </div>
    </div>

    <div class="field" style="margin-top:1.2rem">
      <div class="toggle-row">
        <label class="toggle">
          <input type="checkbox" name="show_raw_json" {json_checked}>
          <span class="toggle-slider"></span>
        </label>
        <div>
          <div style="font-size:0.88rem">Show Raw /user JSON</div>
          <div class="hint">Display the full raw JSON response from the GitHub
          <code>/user</code> endpoint on the results page. Disable to keep the
          results page cleaner during a live demo.</div>
        </div>
      </div>
    </div>
  </div>

  <!-- ── Actions ── -->
  <div style="display:flex;gap:1rem;align-items:center;margin-top:0.5rem">
    <button class="btn" type="submit" name="action" value="save">Save Configuration</button>
    <button class="btn" type="submit" name="action" value="reset"
            style="background:none;border-color:#e0b55c;color:#e0b55c"
            onclick="return confirm('Reset all settings to defaults?')">Reset to Defaults</button>
    <a class="btn" href="/" style="background:none;border-color:#252d3d;color:#7a8298">Cancel</a>
  </div>

</form>
""", active_nav="config")


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
        elif path == "/config":
            self._send_html(_config_page())
        elif path == "/step/skip":
            self._handle_step_skip(params)
        else:
            self._send_html("<h1>404</h1>", 404)

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/revoke":
            self._handle_revoke()
        elif parsed.path == "/config":
            self._handle_config()
        elif parsed.path == "/step/redirect":
            self._handle_step_redirect()
        elif parsed.path == "/step/exchange":
            self._handle_step_exchange()
        elif parsed.path == "/step/userinfo":
            self._handle_step_userinfo()
        else:
            self._send_html("<h1>404</h1>", 404)

    def _handle_config(self):
        length  = int(self.headers.get("Content-Length", 0))
        raw     = self.rfile.read(length).decode()
        params  = urllib.parse.parse_qs(raw, keep_blank_values=True)

        # ── Reset to defaults shortcut ────────────────────────────────────
        if params.get("action", ["save"])[0] == "reset":
            cfg.reset()
            print(f"[⚙] Config reset to defaults: {cfg!r}")
            self._send_html(_config_page(saved=True, reset=True))
            return

        # ── Scopes — merge checkboxes + custom field ──────────────────────
        checked = params.get("scope", [])
        custom  = params.get("custom_scopes", [""])[0].strip()
        extra   = [s for s in custom.split() if s]
        merged  = " ".join(dict.fromkeys(checked + extra)) or Config.DEFAULTS["scopes"]

        # ── Apply all changes via cfg.update() ────────────────────────────
        cfg.update(
            scopes            = merged,
            code_max_age      = int(params.get("code_max_age", ["600"])[0]),
            simulate_id_token = "simulate_id_token" in params,
            show_raw_json     = "show_raw_json"     in params,
            step_through      = "step_through"      in params,
        )

        print(f"[⚙] {cfg!r}")

        self._send_html(_config_page(saved=True))

    def _handle_revoke(self):
        if not token_store.has_token:
            self._send_html(_revoke_result_page(
                success=False,
                message="No token held in memory. Complete an OAuth flow first.",
                login="",
            ))
            return

        token = token_store.token
        login = token_store.login
        url   = f"https://api.github.com/applications/{CLIENT_ID}/token"

        print(f"[✕] Revoking token for {login}…")
        status = _delete_json(url, CLIENT_ID, CLIENT_SECRET, {"access_token": token})

        if status == 204:
            # Success — clear the in-memory store
            token_store.clear()
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

        state               = secrets.token_urlsafe(24)
        verifier, challenge = generate_pkce_pair()
        session_store.create(state, verifier, challenge)

        auth_params = {
            "client_id":             CLIENT_ID,
            "redirect_uri":          REDIRECT_URI,
            "scope":                 cfg.scopes,
            "state":                 state,
            "code_challenge":        challenge,
            "code_challenge_method": "S256",
        }
        auth_url = AUTHORIZE_URL + "?" + urllib.parse.urlencode(auth_params)

        if cfg.step_through:
            # Pause at Step 1 — show the authorization request before firing it
            flow_store.start(state, verifier, challenge, auth_url, auth_params)
            print(f"\n[⏸] Step-through mode: pausing before authorization redirect")
            self._send_html(StepRenderer.step1_authorize(state, auth_params, auth_url))
        else:
            print(f"\n[→] Redirecting to GitHub:\n    {auth_url}\n")
            self._redirect(auth_url)

    # ── Step-through handlers ─────────────────────────────────────────────

    def _read_post_params(self) -> dict:
        """Read and parse a URL-encoded POST body."""
        length = int(self.headers.get("Content-Length", 0))
        raw    = self.rfile.read(length).decode()
        return urllib.parse.parse_qs(raw, keep_blank_values=True)

    def _handle_step_redirect(self):
        """Step 1 → fire the actual GitHub redirect."""
        params = self._read_post_params()
        state  = params.get("state", [""])[0]
        if not flow_store.active or flow_store.state != state:
            self._send_html('<p class="err">Step-through session expired. '
                            '<a href="/">Start over</a></p>', 400)
            return
        print(f"\n[→] Step-through: redirecting to GitHub\n    {flow_store.auth_url}\n")
        self._redirect(flow_store.auth_url)

    def _handle_step_exchange(self):
        """Step 2 → fire the token exchange POST."""
        params = self._read_post_params()
        state  = params.get("state", [""])[0]
        if not flow_store.active or flow_store.state != state:
            self._send_html('<p class="err">Step-through session expired. '
                            '<a href="/">Start over</a></p>', 400)
            return

        print("[↔] Step-through: exchanging code for token…")
        try:
            token_resp = _post_form(TOKEN_URL, {
                "client_id":     CLIENT_ID,
                "client_secret": CLIENT_SECRET,
                "code":          flow_store.auth_code,
                "redirect_uri":  REDIRECT_URI,
                "code_verifier": flow_store.verifier,
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

        flow_store.save_token(token_resp)
        self._send_html(StepRenderer.step3_userinfo(state, token_resp))

    def _handle_step_userinfo(self):
        """Step 3 → fire the /user and /user/emails calls then show results."""
        params = self._read_post_params()
        state  = params.get("state", [""])[0]
        if not flow_store.active or flow_store.state != state:
            self._send_html('<p class="err">Step-through session expired. '
                            '<a href="/">Start over</a></p>', 400)
            return

        access_token = flow_store.token_resp.get("access_token", "")
        print("[→] Step-through: fetching /user and /user/emails…")
        try:
            user   = _get(USERINFO_URL, access_token)
            emails = _get(EMAILS_URL,   access_token)
        except Exception as exc:
            self._send_html(
                f'<pre style="color:#e05c5c">Resource Server error: {html.escape(str(exc))}</pre>',
                500,
            )
            return

        print(f"[✓] Authenticated as: {user.get('login')}  "
              f"(code age: {flow_store.code_age:.1f} s)")
        token_store.save(access_token, user.get("login", ""))

        # Reconstruct the full results page arguments from flow_store
        result_html = _callback_page(
            flow_store.auth_code, flow_store.state, flow_store.token_resp,
            user, emails, flow_store.auth_url,
            flow_store.verifier, flow_store.challenge,
            flow_store.code_age, flow_store.code_expired_locally,
        )
        flow_store.clear()
        self._send_html(result_html)

    def _handle_step_skip(self, params: dict):
        """Abandon step-through and run the remaining flow immediately."""
        state = urllib.parse.unquote(params.get("state", ""))
        if not flow_store.active or flow_store.state != state:
            self._redirect("/")
            return

        # If we haven't yet got a token, we need to exchange and fetch
        if not flow_store.token_resp:
            if not flow_store.auth_code:
                # Haven't even got the callback yet — just redirect normally
                flow_store.clear()
                self._redirect(flow_store.auth_url if flow_store.auth_url else "/")
                return
            # Exchange code
            try:
                token_resp = _post_form(TOKEN_URL, {
                    "client_id":     CLIENT_ID,
                    "client_secret": CLIENT_SECRET,
                    "code":          flow_store.auth_code,
                    "redirect_uri":  REDIRECT_URI,
                    "code_verifier": flow_store.verifier,
                })
            except Exception as exc:
                self._send_html(
                    f'<pre style="color:#e05c5c">Token exchange failed: {html.escape(str(exc))}</pre>',
                    500,
                )
                return
            flow_store.save_token(token_resp)

        access_token = flow_store.token_resp.get("access_token", "")
        if not access_token:
            flow_store.clear()
            self._redirect("/")
            return

        try:
            user   = _get(USERINFO_URL, access_token)
            emails = _get(EMAILS_URL,   access_token)
        except Exception as exc:
            self._send_html(
                f'<pre style="color:#e05c5c">Resource Server error: {html.escape(str(exc))}</pre>',
                500,
            )
            return

        token_store.save(access_token, user.get("login", ""))
        result_html = _callback_page(
            flow_store.auth_code, flow_store.state, flow_store.token_resp,
            user, emails, flow_store.auth_url,
            flow_store.verifier, flow_store.challenge,
            flow_store.code_age, flow_store.code_expired_locally,
        )
        flow_store.clear()
        self._send_html(result_html)

    def _handle_callback(self, params: dict):
        # ── CSRF check ────────────────────────────────────────────────────
        state   = params.get("state", "")
        session = session_store.consume(state)
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
        code_expired_locally = code_age > cfg.code_max_age
        if code_expired_locally:
            print(
                f"[⚠] Code age {code_age:.1f} s exceeds CODE_MAX_AGE_SECONDS={cfg.code_max_age} — "
                f"proceeding to demonstrate GitHub's own 600 s limit"
            )

        # ── Reconstruct auth URL for display ──────────────────────────────
        auth_url = AUTHORIZE_URL + "?" + urllib.parse.urlencode({
            "client_id":             CLIENT_ID,
            "redirect_uri":          REDIRECT_URI,
            "scope":                 cfg.scopes,
            "state":                 state,
            "code_challenge":        challenge,
            "code_challenge_method": "S256",
        })

        # ── Step-through: pause before token exchange ─────────────────────
        if cfg.step_through and flow_store.active and flow_store.state == state:
            flow_store.save_callback(auth_code, code_age, code_expired_locally)
            print(f"[⏸] Step-through: pausing before token exchange "
                  f"(code age: {code_age:.1f} s)")
            self._send_html(StepRenderer.step2_exchange(
                state, auth_code, code_age, code_expired_locally, verifier, challenge,
            ))
            return

        # ── Normal (non-step-through) flow ────────────────────────────────
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
        token_store.save(access_token, user.get("login", ""))

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

    print(f"   Scopes:            {cfg.scopes}")
    print(f"   Code max age:      {cfg.code_max_age} s  (GitHub hard limit: 600 s)")
    print(f"   Simulate ID Token: {cfg.simulate_id_token}")
    print(f"\n🚀  http://127.0.0.1:{port}")
    print(f"    Callback: {REDIRECT_URI}")
    print("──────────────────────────────────────────────────────────\n")

    server = HTTPServer(("127.0.0.1", port), OAuthHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
