// auth-inspector — Run an authentication protocol as a client against an IdP
// (Keycloak, etc.) and see exactly what's exchanged at every step: params,
// headers, and bodies for both requests and responses.
//
// Only OIDC (Authorization Code + PKCE) is implemented so far. SAML has a
// placeholder tab in the UI, since it needs a fundamentally different
// implementation (XML signing, SP metadata, etc.).
//
// Design notes:
//   - The authorization request (browser -> IdP) is a plain top-level
//     navigation/redirect -> not subject to CORS.
//   - The token exchange (server -> IdP) is a server-to-server back-channel
//     call -> also not subject to CORS; this is the only place the client
//     secret is ever sent.
//   - Each run is tracked in memory by its OAuth `state`. After the callback
//     is processed, the browser is redirected to /report/:state instead of
//     rendering directly, so refreshing the report page never resubmits the
//     (single-use) authorization code.

import express from 'express';
import crypto from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { jwtVerify, createRemoteJWKSet } from 'jose';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const PORT = process.env.PORT || 5555;

app.use(express.json());
app.use('/static', express.static(path.join(__dirname, 'public')));

// ── In-memory run store (state -> run record) ──────────────────────────
const runs = new Map();
const RUN_TTL_MS = 30 * 60 * 1000; // clean up after 30 minutes

setInterval(() => {
  const now = Date.now();
  for (const [state, run] of runs) {
    if (now - run.createdAt > RUN_TTL_MS) runs.delete(state);
  }
}, 5 * 60 * 1000).unref();

// ── Helpers ──────────────────────────────────────────────────────────────
function b64url(buf) {
  return Buffer.from(buf).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function randomToken(bytes = 32) {
  return b64url(crypto.randomBytes(bytes));
}
function genPkce(method) {
  const verifier = randomToken(32); // 43 chars, within RFC 7636's 43-128 range
  const challenge = method === 'plain' ? verifier : b64url(crypto.createHash('sha256').update(verifier).digest());
  return { verifier, challenge, method: method === 'plain' ? 'plain' : 'S256' };
}
function b64urlToBuffer(s) {
  s = s.replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  return Buffer.from(s, 'base64');
}
function decodeJwtRaw(token) {
  const parts = token.split('.');
  if (parts.length < 2) throw new Error('not a JWT (opaque token)');
  return {
    header: JSON.parse(b64urlToBuffer(parts[0]).toString('utf8')),
    payload: JSON.parse(b64urlToBuffer(parts[1]).toString('utf8')),
  };
}
function escapeHtml(str) {
  return String(str ?? '').replace(/[&<>"']/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  }[c]));
}
function pre(obj) {
  return `<pre>${escapeHtml(JSON.stringify(obj, null, 2))}</pre>`;
}
function normIssuer(issuer) {
  return issuer.replace(/\/+$/, '');
}

// JWKS cache, keyed by issuer
const jwksCache = new Map();
function getJwks(issuer) {
  const key = normIssuer(issuer);
  if (!jwksCache.has(key)) {
    jwksCache.set(key, createRemoteJWKSet(new URL(`${key}/protocol/openid-connect/certs`)));
  }
  return jwksCache.get(key);
}
async function verifySignature(token, issuer) {
  try {
    const JWKS = getJwks(issuer);
    const { payload, protectedHeader } = await jwtVerify(token, JWKS, { issuer: normIssuer(issuer) });
    return { verified: true, header: protectedHeader, payload };
  } catch (e) {
    return { verified: false, error: e.message };
  }
}
function audienceMatches(payload, clientId) {
  if (!payload) return null;
  const aud = payload.aud;
  const inAud = Array.isArray(aud) ? aud.includes(clientId) : aud === clientId;
  return inAud || payload.azp === clientId;
}
async function buildTokenInfo(token, issuer, clientId, expectedNonce) {
  let raw = null;
  try {
    raw = decodeJwtRaw(token);
  } catch {
    return { opaque: true };
  }
  const verify = await verifySignature(token, issuer);
  return {
    opaque: false,
    header: raw.header,
    payload: raw.payload,
    verify,
    audOk: audienceMatches(raw.payload, clientId),
    nonceOk: expectedNonce != null ? raw.payload.nonce === expectedNonce : null,
  };
}

// ── HTML rendering ──────────────────────────────────────────────────────
function page(title, bodyHtml) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${escapeHtml(title)} · auth-inspector</title>
<link rel="stylesheet" href="/static/style.css">
</head>
<body>
<header class="topbar">
  <a href="/" class="brand">🔎 auth-inspector</a>
  <nav class="protocol-nav">
    <span class="protocol-tab active">OIDC</span>
    <span class="protocol-tab disabled" title="Planned for a future release">SAML (coming soon)</span>
  </nav>
</header>
${bodyHtml}
<script>
function revealSecret(el){ el.textContent = el.dataset.value; el.classList.remove('mask'); }
</script>
</body>
</html>`;
}

function renderError(title, msg) {
  return page(title, `<div class="wrap"><div class="card">
    <h2>${escapeHtml(title)}</h2>
    <p class="note">${escapeHtml(msg)}</p>
    <p><a href="/">← Back to start</a></p>
  </div></div>`);
}

function renderHome() {
  return page('OIDC test', `
<div class="wrap">
  <h1>OIDC client test
    <small>Run the OIDC Authorization Code flow against Keycloak (or any OIDC IdP) and inspect every request and response along the way.</small>
  </h1>

  <div class="card">
    <div class="section-title"><h2>Connection</h2></div>
    <div class="grid">
      <div class="field full">
        <label>Issuer <span class="hint">e.g. http://70.12.115.171:24080/realms/dev</span></label>
        <div class="row">
          <input type="text" id="issuer" placeholder="http://localhost:24080/realms/dev">
          <button class="btn secondary" id="discoverBtn" type="button">Discover →</button>
        </div>
        <div id="discoverResult" style="display:none;"></div>
      </div>
      <div class="field">
        <label>Client ID</label>
        <input type="text" id="clientId" placeholder="knowledge-agent">
      </div>
      <div class="field">
        <label>Scope <span class="hint">must include "openid"</span></label>
        <input type="text" id="scope" value="openid profile email">
      </div>
      <div class="field full">
        <label>Redirect URI <span class="hint">must be a registered Valid redirect URI on the client</span></label>
        <input type="text" id="redirectUri" placeholder="">
      </div>
    </div>
  </div>

  <div class="card">
    <div class="section-title"><h2>Security options</h2></div>
    <div class="split">
      <div class="split-col">
        <label class="col-label">Client authentication</label>
        <div class="toggle-group" id="authToggle">
          <button type="button" data-val="off" class="active">Off (Public)</button>
          <button type="button" data-val="on">On (Confidential)</button>
        </div>
        <div id="authOnFields" style="display:none; margin-top:12px;">
          <input type="password" id="clientSecret" placeholder="Client secret" style="margin-bottom:8px;">
          <div class="toggle-group" id="authMethodToggle">
            <button type="button" data-val="post" class="active">Body</button>
            <button type="button" data-val="basic">Header</button>
          </div>
        </div>
        <details class="hint-details">
          <summary>Why?</summary>
          <p>Off = token exchange with no secret (Public). On = the secret is sent along (Confidential) — but never
            in the authorization request, only in Step 3's back-channel call. Body vs. Header switches whether it
            travels as <code>client_secret</code> in the form body or as an <code>Authorization: Basic</code> header.</p>
        </details>
      </div>
      <div class="split-col">
        <label class="col-label">PKCE</label>
        <div class="toggle-group" id="pkceToggle">
          <button type="button" data-val="off" class="active">Off</button>
          <button type="button" data-val="on">On</button>
        </div>
        <div id="pkceOnFields" style="display:none; margin-top:12px;">
          <div class="toggle-group" id="pkceMethodToggle">
            <button type="button" data-val="S256" class="active">S256</button>
            <button type="button" data-val="plain">plain</button>
          </div>
        </div>
        <details class="hint-details">
          <summary>Why?</summary>
          <p>When On, a code_verifier is generated and held server-side. Only its hashed code_challenge goes in the
            authorization request; the verifier itself is presented later, in Step 3.</p>
        </details>
      </div>
    </div>
  </div>

  <button class="btn block" id="startBtn" style="font-size:16px; padding:14px;">Generate authentication request →</button>

  <div class="card" id="step1Card" style="display:none; margin-top:14px;">
    <div class="section-title"><h2>Step 1 · Authorization Request</h2></div>
    <div id="step1Body"></div>
    <button class="btn block" id="goBtn" style="margin-top:14px;">Send request →</button>
  </div>

  <div class="card" id="historyCard">
    <div class="section-title"><h2>Recent test runs</h2></div>
    <div id="historyBody" class="note">None yet</div>
  </div>
</div>
<script src="/static/home.js"></script>
`);
}

function stepCard(num, title, bodyHtml, badgeHtml = '') {
  return `<div class="card">
    <div class="step">
      <div class="num">${num}</div>
      <div class="step-body">
        <div class="section-title"><h2>${escapeHtml(title)}</h2>${badgeHtml}</div>
        ${bodyHtml}
      </div>
    </div>
  </div>`;
}
function badge(ok, textOk = 'OK', textBad = 'Failed') {
  if (ok === null || ok === undefined) return `<span class="badge muted">N/A</span>`;
  return `<span class="badge ${ok ? 'ok' : 'bad'}">${escapeHtml(ok ? textOk : textBad)}</span>`;
}
function maskedRow(label, value) {
  return `<tr><td>${escapeHtml(label)}</td><td><span class="secret mask" data-value="${escapeHtml(value)}" onclick="revealSecret(this)">••••••••••••</span></td></tr>`;
}
function kvTable(obj, maskKeys = []) {
  const rows = Object.entries(obj).map(([k, v]) => {
    if (maskKeys.includes(k)) return maskedRow(k, String(v));
    const display = typeof v === 'string' ? v : JSON.stringify(v);
    return `<tr><td>${escapeHtml(k)}</td><td><code>${escapeHtml(display)}</code></td></tr>`;
  }).join('');
  return `<table class="kv">${rows}</table>`;
}

function renderReport(run) {
  const cfg = run.config;
  let html = `<div class="wrap">
    <a href="/" style="font-size:13px; color:var(--muted);">← New test</a>
    <h1 style="margin-top:10px;">Test report
      <small>${escapeHtml(cfg.clientId)} · Client authentication: <b>${cfg.authOn ? `On (${cfg.authMethod})` : 'Off'}</b> · PKCE: <b>${cfg.pkceOn ? `On (${cfg.pkceMethod})` : 'Off'}</b></small>
    </h1>`;

  html += stepCard(1, 'Authorization Request — browser → IdP (navigation, no CORS involved)',
    kvTable(run.step1.params) +
    `<div class="note" style="margin-top:10px; word-break:break-all;">Full URL: <code>${escapeHtml(run.step1.url)}</code></div>`
  );

  if (run.step2) {
    const hasError = !!run.step2.query.error;
    html += stepCard(2, 'Authorization Response — IdP → callback',
      kvTable(run.step2.query),
      badge(!hasError, 'Code received', 'Error response')
    );
  }

  if (run.status === 'auth_error' || run.status === 'no_code') {
    html += `<div class="card"><p class="note">The IdP returned an error (or no code) during authorization, so the token exchange was skipped.</p></div>`;
    html += `</div>`;
    return page('Test report', html);
  }

  if (run.status === 'awaiting_exchange') {
    html += `<div class="card">
      <div class="section-title"><h2>Ready for Step 3</h2></div>
      <p class="note">A single-use authorization code has been received. Nothing else happens automatically — click below to
        exchange it for tokens over the server ↔ IdP back-channel, and see exactly what's sent.</p>
      <form method="POST" action="/report/${escapeHtml(run.id)}/exchange">
        <button class="btn block" type="submit" style="margin-top:12px;">Exchange code for tokens →</button>
      </form>
    </div>`;
  }

  if (run.step3) {
    const maskKeys = [];
    if (run.step3.body.client_secret) maskKeys.push('client_secret');
    if (run.step3.body.code_verifier) maskKeys.push('code_verifier');
    if (run.step3.body.code) maskKeys.push('code');
    const headerMask = run.step3.headers.Authorization ? ['Authorization'] : [];
    html += stepCard(3, 'Token Request — server → IdP (back-channel, no CORS involved)',
      `<div class="sub">${run.step3.method} <code>${escapeHtml(run.step3.url)}</code></div>
       <div class="kv-title">Headers</div>${kvTable(run.step3.headers, headerMask)}
       <div class="kv-title">Body (application/x-www-form-urlencoded)</div>${kvTable(run.step3.body, maskKeys)}`
    );
  }

  if (run.step4) {
    const ok = typeof run.step4.status === 'number' && run.step4.status >= 200 && run.step4.status < 300;
    html += stepCard(4, `Token Response — HTTP ${run.step4.status ?? 'ERR'} ${escapeHtml(run.step4.statusText ?? '')}`,
      pre(run.step4.body ?? run.step4.error),
      badge(ok, 'Token issued', 'Token request failed')
    );
  }

  if (run.step5?.idToken) {
    const t = run.step5.idToken;
    html += stepCard(5, 'ID Token — decode & verify',
      t.opaque ? `<div class="note">Not a JWT.</div>` :
      `<div class="kv-title">Header</div>${pre(t.header)}
       <div class="kv-title">Payload</div>${pre(t.payload)}
       <div class="badges">
         ${badge(t.verify.verified, 'Signature valid', 'Signature invalid')}
         ${badge(t.audOk, 'Audience matches', 'Audience mismatch')}
         ${badge(t.nonceOk, 'Nonce matches', 'Nonce mismatch')}
       </div>
       ${!t.verify.verified ? `<div class="note" style="margin-top:8px;">${escapeHtml(t.verify.error)}</div>` : ''}`
    );
  }
  if (run.step5?.accessToken) {
    const t = run.step5.accessToken;
    html += stepCard(6, 'Access Token — decode & verify',
      t.opaque ? `<div class="note">Not a JWT — likely an opaque token (this can be normal).</div>` :
      `<div class="kv-title">Header</div>${pre(t.header)}
       <div class="kv-title">Payload</div>${pre(t.payload)}
       <div class="badges">
         ${badge(t.verify.verified, 'Signature valid', 'Signature invalid')}
         ${badge(t.audOk, 'Audience/azp matches', 'Audience/azp mismatch')}
       </div>
       ${!t.verify.verified ? `<div class="note" style="margin-top:8px;">${escapeHtml(t.verify.error)}</div>` : ''}`
    );
  }

  html += `</div>`;
  return page('Test report', html);
}

// ── Routes ──────────────────────────────────────────────────────────────

app.get('/', (req, res) => res.send(renderHome()));

app.post('/start', (req, res) => {
  const { issuer, clientId, clientSecret, redirectUri, scope, authOn, authMethod, pkceOn, pkceMethod } = req.body || {};

  if (!issuer || !clientId || !redirectUri) {
    return res.status(400).json({ error: 'issuer, clientId, and redirectUri are required.' });
  }

  const state = crypto.randomUUID();
  const nonce = crypto.randomUUID();
  const pkce = pkceOn ? genPkce(pkceMethod) : null;

  const params = {
    client_id: clientId,
    response_type: 'code',
    redirect_uri: redirectUri,
    scope: scope || 'openid',
    state,
    nonce,
  };
  if (pkce) {
    params.code_challenge = pkce.challenge;
    params.code_challenge_method = pkce.method;
  }

  const authUrl = `${normIssuer(issuer)}/protocol/openid-connect/auth?` + new URLSearchParams(params).toString();

  runs.set(state, {
    id: state,
    createdAt: Date.now(),
    config: {
      issuer, clientId, clientSecret: clientSecret || '', redirectUri,
      scope: scope || 'openid',
      authOn: !!authOn, authMethod: authMethod === 'basic' ? 'basic' : 'post',
      pkceOn: !!pkceOn, pkceMethod: pkce?.method || null,
    },
    nonce,
    pkceVerifier: pkce?.verifier || null,
    step1: { url: authUrl, params },
    step2: null, step3: null, step4: null, step5: null,
    status: 'pending',
  });

  res.json({ state, authUrl, params });
});

// Performs Step 3 (token request) + Step 4 (token response) + Step 5/6
// (decode & verify), mutating `run` in place. Split out from the callback
// handler so it can be triggered explicitly by the "Exchange code for
// tokens" button instead of running automatically.
async function performTokenExchange(run) {
  const code = run.step2.query.code;
  const tokenUrl = `${normIssuer(run.config.issuer)}/protocol/openid-connect/token`;
  const bodyParams = {
    grant_type: 'authorization_code',
    code: String(code),
    redirect_uri: run.config.redirectUri,
  };
  if (run.config.pkceOn) bodyParams.code_verifier = run.pkceVerifier;

  const headers = { 'Content-Type': 'application/x-www-form-urlencoded' };

  if (run.config.authOn) {
    if (run.config.authMethod === 'basic') {
      headers['Authorization'] = 'Basic ' + Buffer.from(`${run.config.clientId}:${run.config.clientSecret}`).toString('base64');
      // When using Basic auth, client_id is not duplicated in the body (per spec).
    } else {
      bodyParams.client_id = run.config.clientId;
      bodyParams.client_secret = run.config.clientSecret;
    }
  } else {
    bodyParams.client_id = run.config.clientId; // public: client_id only, no secret
  }

  run.step3 = { url: tokenUrl, method: 'POST', headers: { ...headers }, body: { ...bodyParams } };

  let tokenRes, tokenText, tokenJson;
  try {
    tokenRes = await fetch(tokenUrl, { method: 'POST', headers, body: new URLSearchParams(bodyParams) });
    tokenText = await tokenRes.text();
    try { tokenJson = JSON.parse(tokenText); } catch { tokenJson = null; }
  } catch (e) {
    run.status = 'fetch_error';
    run.step4 = { error: e.message };
    return;
  }

  run.step4 = {
    status: tokenRes.status,
    statusText: tokenRes.statusText,
    body: tokenJson ?? tokenText,
  };

  if (!tokenRes.ok || !tokenJson) {
    run.status = 'token_error';
    return;
  }

  const step5 = {};
  if (tokenJson.id_token) {
    step5.idToken = await buildTokenInfo(tokenJson.id_token, run.config.issuer, run.config.clientId, run.nonce);
  }
  if (tokenJson.access_token) {
    step5.accessToken = await buildTokenInfo(tokenJson.access_token, run.config.issuer, run.config.clientId, null);
  }
  run.step5 = step5;
  run.status = 'success';
}

// Step 0 (optional, not tied to a run): fetch the IdP's discovery document
// so its advertised endpoints/capabilities can be inspected before doing
// anything else. Proxied through this server so it's never subject to the
// browser's CORS rules, regardless of what the target issuer allows.
app.post('/discover', async (req, res) => {
  const { issuer } = req.body || {};
  if (!issuer) return res.status(400).json({ error: 'issuer is required.' });

  const url = `${normIssuer(issuer)}/.well-known/openid-configuration`;
  try {
    const r = await fetch(url);
    const text = await r.text();
    let json = null;
    try { json = JSON.parse(text); } catch { json = null; }
    res.json({ url, status: r.status, statusText: r.statusText, body: json ?? text });
  } catch (e) {
    res.status(502).json({ url, error: e.message });
  }
});

app.get('/callback', (req, res) => {
  const { code, state, error } = req.query;
  const run = state && runs.get(String(state));

  if (!run) {
    return res.status(400).send(renderError(
      'Session not found',
      'The state value does not match any recorded session. It may have expired (30 min) or the server may have restarted. Please start over.'
    ));
  }

  // Only Step 2 (the authorization response) is recorded here. Step 3
  // (the token exchange) is a separate, explicit action on the report page.
  run.step2 = { receivedAt: Date.now(), query: { ...req.query } };
  run.status = error ? 'auth_error' : !code ? 'no_code' : 'awaiting_exchange';

  res.redirect(`/report/${state}`);
});

// Step 3, triggered explicitly from the report page. Uses POST + a redirect
// back (PRG pattern) so refreshing the report page never re-runs the exchange.
app.post('/report/:state/exchange', async (req, res) => {
  const run = runs.get(req.params.state);
  if (!run) {
    return res.status(404).send(renderError('Run not found', 'It may have expired or the server may have restarted.'));
  }
  if (run.step2 && !run.step2.query.error && run.step2.query.code) {
    await performTokenExchange(run);
  }
  res.redirect(`/report/${req.params.state}`);
});

app.get('/report/:state', (req, res) => {
  const run = runs.get(req.params.state);
  if (!run) {
    return res.status(404).send(renderError('Run not found', 'It may have expired or the server may have restarted.'));
  }
  res.send(renderReport(run));
});

app.get('/api/runs', (req, res) => {
  const list = [...runs.entries()]
    .sort((a, b) => b[1].createdAt - a[1].createdAt)
    .slice(0, 20)
    .map(([state, r]) => ({ state, createdAt: r.createdAt, clientId: r.config.clientId, status: r.status }));
  res.json(list);
});

app.listen(PORT, () => {
  console.log(`auth-inspector → http://localhost:${PORT}`);
});
