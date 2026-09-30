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
import zlib from 'node:zlib';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { jwtVerify, createRemoteJWKSet } from 'jose';
import { DOMParser } from '@xmldom/xmldom';
import xpath from 'xpath';
import { SignedXml } from 'xml-crypto';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const PORT = process.env.PORT || 5555;

app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use('/static', express.static(path.join(__dirname, 'public')));

// ── In-memory run store (state -> run record) ──────────────────────────
const runs = new Map();
const samlRuns = new Map(); // RelayState -> SAML run record
const RUN_TTL_MS = 30 * 60 * 1000; // clean up after 30 minutes

setInterval(() => {
  const now = Date.now();
  for (const [state, run] of runs) {
    if (now - run.createdAt > RUN_TTL_MS) runs.delete(state);
  }
  for (const [id, run] of samlRuns) {
    if (now - run.createdAt > RUN_TTL_MS) samlRuns.delete(id);
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

function withQuery(url, params) {
  return url + (url.includes('?') ? '&' : '?') + new URLSearchParams(params).toString();
}

// OIDC Discovery: {issuer}/.well-known/openid-configuration is the standard
// location, and every endpoint this app calls is read from that document.
async function fetchOidcDiscovery(issuer) {
  const url = `${normIssuer(issuer)}/.well-known/openid-configuration`;
  const r = await fetch(url);
  const text = await r.text();
  let json = null;
  try { json = JSON.parse(text); } catch { json = null; }
  return { url, status: r.status, statusText: r.statusText, ok: r.ok, json, text };
}

// JWKS cache, keyed by the jwks_uri the IdP advertises
const jwksCache = new Map();
function getJwks(jwksUri) {
  if (!jwksCache.has(jwksUri)) {
    jwksCache.set(jwksUri, createRemoteJWKSet(new URL(jwksUri)));
  }
  return jwksCache.get(jwksUri);
}
async function verifySignature(token, endpoints) {
  try {
    if (!endpoints.jwks_uri) throw new Error('The IdP\'s discovery document has no jwks_uri.');
    const JWKS = getJwks(endpoints.jwks_uri);
    const { payload, protectedHeader } = await jwtVerify(token, JWKS, { issuer: endpoints.issuer });
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
async function buildTokenInfo(token, endpoints, clientId, expectedNonce) {
  let raw = null;
  try {
    raw = decodeJwtRaw(token);
  } catch {
    return { opaque: true };
  }
  const verify = await verifySignature(token, endpoints);
  return {
    opaque: false,
    header: raw.header,
    payload: raw.payload,
    verify,
    audOk: audienceMatches(raw.payload, clientId),
    nonceOk: expectedNonce != null ? raw.payload.nonce === expectedNonce : null,
  };
}

// ── SAML Response validation ────────────────────────────────────────────
// Parses and validates a SAML 2.0 Response as a Relying Party would receive
// it (e.g. from the SAMLResponse form field of an HTTP-POST binding),
// without this app acting as an actual SP (no AuthnRequest, no ACS
// endpoint). It only inspects what's pasted in: XML-DSig signature
// verification, Conditions time window, AudienceRestriction, and
// SubjectConfirmationData — plus a full parse of the assertion for display.

function xall(ctxNode, localName) {
  return xpath.select(`.//*[local-name(.)='${localName}']`, ctxNode);
}
function xchild(ctxNode, localName) {
  return ctxNode ? xpath.select(`*[local-name(.)='${localName}']`, ctxNode)[0] || null : null;
}
function xtext(node) {
  return node ? node.textContent.trim() : null;
}
function xattr(node, name) {
  return node && node.getAttribute ? node.getAttribute(name) : null;
}

function decodeSamlInput(raw) {
  const trimmed = raw.trim();
  if (trimmed.startsWith('<')) return trimmed;
  try {
    const decoded = Buffer.from(trimmed, 'base64').toString('utf8');
    if (decoded.trim().startsWith('<')) return decoded;
  } catch { /* fall through */ }
  throw new Error('Not valid XML or base64-encoded XML.');
}

function verifySamlSignature(signatureNode, xmlString, cert) {
  try {
    const sig = new SignedXml({ publicCert: cert });
    sig.loadSignature(signatureNode);
    const verified = sig.checkSignature(xmlString);
    return verified
      ? { verified: true }
      : { verified: false, error: (sig.validationErrors || []).join('; ') || 'Signature does not match.' };
  } catch (e) {
    return { verified: false, error: e.message };
  }
}

function parseAndValidateSaml({ raw, cert, expectedAudience, expectedRecipient, expectedInResponseTo }) {
  const xmlString = decodeSamlInput(raw);

  const parseErrors = [];
  const doc = new DOMParser({
    onError: (level, msg) => { if (level !== 'warning') parseErrors.push(msg); },
  }).parseFromString(xmlString, 'text/xml');
  if (parseErrors.length) throw new Error('XML parse error: ' + parseErrors.join('; '));

  const root = doc.documentElement;
  if (!root) throw new Error('No root element found.');

  const isBareAssertion = root.localName === 'Assertion';
  const responseNode = isBareAssertion ? null : root;
  const assertionNode = isBareAssertion ? root : xall(root, 'Assertion')[0] || null;

  const status = responseNode ? {
    code: xattr(xchild(xchild(responseNode, 'Status'), 'StatusCode'), 'Value'),
  } : null;

  const responseIssuer = responseNode ? xtext(xchild(responseNode, 'Issuer')) : null;

  let assertion = null;
  const signatures = [];

  if (responseNode) {
    const responseSig = xchild(responseNode, 'Signature');
    if (responseSig) signatures.push({ scope: 'Response', node: responseSig });
  }

  if (assertionNode) {
    const issuer = xtext(xchild(assertionNode, 'Issuer'));

    const assertionSig = xchild(assertionNode, 'Signature');
    if (assertionSig) signatures.push({ scope: 'Assertion', node: assertionSig });

    const subjectNode = xchild(assertionNode, 'Subject');
    const nameIdNode = subjectNode && xall(subjectNode, 'NameID')[0];
    const confirmationDataNode = subjectNode && xall(subjectNode, 'SubjectConfirmationData')[0];
    const subject = {
      nameId: xtext(nameIdNode),
      nameIdFormat: xattr(nameIdNode, 'Format'),
      recipient: xattr(confirmationDataNode, 'Recipient'),
      notOnOrAfter: xattr(confirmationDataNode, 'NotOnOrAfter'),
      inResponseTo: xattr(confirmationDataNode, 'InResponseTo'),
    };

    const conditionsNode = xchild(assertionNode, 'Conditions');
    const conditions = {
      notBefore: xattr(conditionsNode, 'NotBefore'),
      notOnOrAfter: xattr(conditionsNode, 'NotOnOrAfter'),
      audiences: conditionsNode ? xall(conditionsNode, 'Audience').map(xtext) : [],
    };

    const authnStatementNode = xchild(assertionNode, 'AuthnStatement');
    const authn = authnStatementNode ? {
      authnInstant: xattr(authnStatementNode, 'AuthnInstant'),
      sessionIndex: xattr(authnStatementNode, 'SessionIndex'),
      contextClassRef: xtext(xall(authnStatementNode, 'AuthnContextClassRef')[0]),
    } : null;

    const attributeStatementNode = xchild(assertionNode, 'AttributeStatement');
    const attributes = attributeStatementNode ? xall(attributeStatementNode, 'Attribute').map((a) => ({
      name: xattr(a, 'Name'),
      friendlyName: xattr(a, 'FriendlyName'),
      values: xall(a, 'AttributeValue').map(xtext),
    })) : [];

    const now = new Date();
    const notBeforeOk = !conditions.notBefore || now >= new Date(conditions.notBefore);
    const notOnOrAfterOk = !conditions.notOnOrAfter || now < new Date(conditions.notOnOrAfter);
    const confirmationOk = !subject.notOnOrAfter || now < new Date(subject.notOnOrAfter);
    const audienceOk = expectedAudience ? conditions.audiences.includes(expectedAudience) : null;
    const recipientOk = expectedRecipient ? subject.recipient === expectedRecipient : null;
    const inResponseToOk = expectedInResponseTo ? subject.inResponseTo === expectedInResponseTo : null;

    assertion = {
      issuer, subject, conditions, authn, attributes,
      timeValid: notBeforeOk && notOnOrAfterOk,
      confirmationValid: confirmationOk,
      audienceOk, recipientOk, inResponseToOk,
    };
  }

  const signatureResults = signatures.map(({ scope, node }) => ({
    scope,
    ...verifySamlSignature(node, xmlString, cert),
  }));

  return {
    xml: xmlString,
    isBareAssertion,
    status,
    responseIssuer,
    assertion,
    signatures: signatureResults,
    anySignedAndValid: signatureResults.length > 0 && signatureResults.every((s) => s.verified),
  };
}

// ── SAML AuthnRequest (SP-initiated, HTTP-Redirect binding) ───────────────
function xmlEscape(s) {
  return String(s ?? '').replace(/[&<>"']/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&apos;',
  }[c]));
}

function buildAuthnRequestXml({ id, issueInstant, destination, acsUrl, spEntityId, nameIdFormat, forceAuthn }) {
  return `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"` +
    ` ID="${xmlEscape(id)}" Version="2.0" IssueInstant="${issueInstant}"` +
    ` Destination="${xmlEscape(destination)}"` +
    ` ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"` +
    ` AssertionConsumerServiceURL="${xmlEscape(acsUrl)}"` +
    (forceAuthn ? ` ForceAuthn="true"` : '') + `>` +
    `<saml:Issuer>${xmlEscape(spEntityId)}</saml:Issuer>` +
    (nameIdFormat ? `<samlp:NameIDPolicy Format="${xmlEscape(nameIdFormat)}" AllowCreate="true"/>` : '') +
    `</samlp:AuthnRequest>`;
}

function buildLogoutRequestXml({ id, issueInstant, destination, spEntityId, nameId, nameIdFormat, sessionIndex }) {
  return `<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"` +
    ` ID="${xmlEscape(id)}" Version="2.0" IssueInstant="${issueInstant}" Destination="${xmlEscape(destination)}">` +
    `<saml:Issuer>${xmlEscape(spEntityId)}</saml:Issuer>` +
    `<saml:NameID${nameIdFormat ? ` Format="${xmlEscape(nameIdFormat)}"` : ''}>${xmlEscape(nameId)}</saml:NameID>` +
    (sessionIndex ? `<samlp:SessionIndex>${xmlEscape(sessionIndex)}</samlp:SessionIndex>` : '') +
    `</samlp:LogoutRequest>`;
}

// Redirect binding messages are DEFLATEd; POST binding ones are plain base64.
function decodeSamlMessage(b64) {
  const buf = Buffer.from(String(b64), 'base64');
  try { return zlib.inflateRawSync(buf).toString('utf8'); } catch { return buf.toString('utf8'); }
}

function parseLogoutResponse(xml) {
  const parseErrors = [];
  const doc = new DOMParser({ onError: (level, msg) => { if (level !== 'warning') parseErrors.push(msg); } })
    .parseFromString(xml, 'text/xml');
  if (parseErrors.length || !doc.documentElement) throw new Error('XML parse error: ' + (parseErrors.join('; ') || 'no root element'));
  const root = doc.documentElement;
  return {
    xml,
    rootName: root.localName,
    statusCode: xattr(xall(root, 'StatusCode')[0], 'Value'),
    inResponseTo: xattr(root, 'InResponseTo'),
    issuer: xtext(xchild(root, 'Issuer')),
  };
}

// Same client-authentication choices for every back-channel call (token, revoke).
function applyClientAuth(cfg, headers, body) {
  if (cfg.authOn) {
    if (cfg.authMethod === 'basic') {
      headers['Authorization'] = 'Basic ' + Buffer.from(`${cfg.clientId}:${cfg.clientSecret}`).toString('base64');
      // When using Basic auth, client_id is not duplicated in the body (per spec).
    } else {
      body.client_id = cfg.clientId;
      body.client_secret = cfg.clientSecret;
    }
  } else {
    body.client_id = cfg.clientId; // public: client_id only, no secret
  }
}

// Keycloak hands out keys/certs as bare base64 (no -----BEGIN----- lines), so
// accept both PEM and bare base64 and normalize.
function normalizePrivateKey(input) {
  const t = String(input).trim();
  if (t.includes('-----BEGIN')) return crypto.createPrivateKey(t);
  const der = Buffer.from(t.replace(/\s+/g, ''), 'base64');
  for (const type of ['pkcs8', 'pkcs1']) {
    try { return crypto.createPrivateKey({ key: der, format: 'der', type }); } catch { /* try next */ }
  }
  throw new Error('Unrecognized private key format (expected PEM, or bare base64 PKCS#8 / PKCS#1).');
}
function normalizeCert(input) {
  const t = String(input || '').trim();
  if (!t || t.includes('-----BEGIN')) return t;
  const b64 = t.replace(/\s+/g, '');
  return `-----BEGIN CERTIFICATE-----\n${b64.match(/.{1,64}/g).join('\n')}\n-----END CERTIFICATE-----`;
}

// Redirect binding: raw DEFLATE -> base64 -> URL-encode. When signing, the
// signature covers the exact query string "SAMLRequest=..&RelayState=..&SigAlg=..".
function buildRedirectUrl({ ssoUrl, requestXml, relayState, privateKey }) {
  const samlRequest = zlib.deflateRawSync(Buffer.from(requestXml, 'utf8')).toString('base64');
  const params = { SAMLRequest: samlRequest, RelayState: relayState };
  let signed = false;
  if (privateKey) {
    const sigAlg = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256';
    const signedQuery = new URLSearchParams({ ...params, SigAlg: sigAlg }).toString();
    const signature = crypto.createSign('RSA-SHA256').update(signedQuery).sign(privateKey, 'base64');
    params.SigAlg = sigAlg;
    params.Signature = signature;
    signed = true;
  }
  const query = new URLSearchParams(params).toString();
  const url = ssoUrl + (ssoUrl.includes('?') ? '&' : '?') + query;
  return { url, params, samlRequestB64: samlRequest, signed };
}

// Pulls the Redirect-binding SSO URL and signing cert out of IdP metadata.
function parseIdpMetadata(xml) {
  const doc = new DOMParser().parseFromString(xml, 'text/xml');
  const root = doc.documentElement;
  if (!root) throw new Error('No root element found in metadata.');
  const ssoNodes = xall(root, 'SingleSignOnService');
  const redirect = ssoNodes.find((n) => (xattr(n, 'Binding') || '').endsWith('HTTP-Redirect')) || ssoNodes[0];
  const certNode = xall(root, 'KeyDescriptor').find((k) => xattr(k, 'use') !== 'encryption');
  const certB64 = certNode ? xtext(xall(certNode, 'X509Certificate')[0]) : null;
  return {
    entityId: xattr(root, 'entityID'),
    ssoUrl: xattr(redirect, 'Location'),
    ssoBinding: xattr(redirect, 'Binding'),
    cert: certB64
      ? `-----BEGIN CERTIFICATE-----\n${certB64.replace(/\s+/g, '').match(/.{1,64}/g).join('\n')}\n-----END CERTIFICATE-----`
      : null,
  };
}

// ── HTML rendering ──────────────────────────────────────────────────────
function page(title, bodyHtml, activeProtocol = 'oidc') {
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
  <div class="topbar-right">
    <nav class="protocol-nav">
      <a href="/" class="protocol-tab${activeProtocol === 'oidc' ? ' active' : ''}">OIDC</a>
      <a href="/saml" class="protocol-tab${activeProtocol === 'saml' ? ' active' : ''}">SAML</a>
    </nav>
    <a href="/runs" class="topbar-link">Recent runs</a>
  </div>
</header>
${bodyHtml}
<script>
function revealSecret(el){
  if (el.classList.contains('mask')) {
    el.textContent = el.dataset.value;
    el.classList.remove('mask');
    el.title = 'Click to hide';
  } else {
    el.textContent = '••••••••••••';
    el.classList.add('mask');
    el.title = 'Click to reveal';
  }
}

// Generic tab switching for any ".tab-group" (a ".tabs" bar of ".tab-btn"
// alongside sibling ".tab-panel" elements, matched by data-tab).
document.querySelectorAll('.tab-group').forEach((group) => {
  group.querySelectorAll('.tab-btn').forEach((btn) => {
    btn.addEventListener('click', () => {
      group.querySelectorAll('.tab-btn').forEach((b) => b.classList.remove('active'));
      btn.classList.add('active');
      group.querySelectorAll('.tab-panel').forEach((p) => {
        p.classList.toggle('active', p.dataset.tab === btn.dataset.tab);
      });
    });
  });
});

// Draggable divider between .layout-left and .layout-right. Width is
// remembered in localStorage; double-click resets to an even 50/50 split.
document.querySelectorAll('.layout').forEach((layout) => {
  const left = layout.querySelector('.layout-left');
  const resizer = layout.querySelector('.layout-resizer');
  if (!left || !resizer) return;

  const saved = Number(localStorage.getItem('auth-inspector:leftWidth'));
  if (saved) left.style.flexBasis = saved + 'px';

  function clamp(px) {
    const max = layout.clientWidth - 320 - resizer.offsetWidth;
    return Math.min(Math.max(px, 280), Math.max(280, max));
  }

  let dragging = false, startX = 0, startWidth = 0;
  resizer.addEventListener('mousedown', (e) => {
    dragging = true;
    startX = e.clientX;
    startWidth = left.getBoundingClientRect().width;
    resizer.classList.add('dragging');
    document.body.style.userSelect = 'none';
    document.body.style.cursor = 'col-resize';
    e.preventDefault();
  });
  window.addEventListener('mousemove', (e) => {
    if (!dragging) return;
    left.style.flexBasis = clamp(startWidth + (e.clientX - startX)) + 'px';
  });
  window.addEventListener('mouseup', () => {
    if (!dragging) return;
    dragging = false;
    resizer.classList.remove('dragging');
    document.body.style.userSelect = '';
    document.body.style.cursor = '';
    localStorage.setItem('auth-inspector:leftWidth', Math.round(left.getBoundingClientRect().width));
  });
  resizer.addEventListener('dblclick', () => {
    const half = clamp(Math.round(layout.clientWidth / 2));
    left.style.flexBasis = half + 'px';
    localStorage.setItem('auth-inspector:leftWidth', half);
  });
});

// Pinned left column: fit it to the space left in the viewport so the action
// buttons stay visible; the inputs scroll inside it.
document.querySelectorAll('.layout-left.pinned').forEach((left) => {
  function fit() {
    if (matchMedia('(max-width:900px)').matches) { left.style.maxHeight = ''; return; }
    const top = Math.max(left.getBoundingClientRect().top, 20);
    left.style.maxHeight = Math.max(360, window.innerHeight - top - 16) + 'px';
  }
  fit();
  addEventListener('resize', fit);
  addEventListener('scroll', fit, { passive: true });
});
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
    <small>Run the OIDC Authorization Code flow against Keycloak (or any OIDC IdP). Configure and act on the left, watch each request/response appear on the right.</small>
  </h1>

  <div class="layout">
    <div class="layout-left pinned">
      <div class="left-scroll">
      <div class="card">
        <div class="section-title"><h2>Connection</h2></div>
        <div class="field">
          <label>Issuer <span class="hint">e.g. https://idp.example.com/realms/dev</span></label>
          <input type="text" id="issuer" placeholder="http://localhost:8080/realms/dev">
        </div>
        <button class="btn block" id="discoverBtn" type="button" style="margin-bottom:14px;">Discover →</button>
        <div class="field">
          <label>Client ID</label>
          <input type="text" id="clientId" placeholder="my-client">
        </div>
        <div class="field">
          <label>Scope <span class="hint">must include "openid"</span></label>
          <input type="text" id="scope" value="openid profile email">
        </div>
        <div class="field">
          <label>Redirect URI <span class="hint">must be a registered Valid redirect URI on the client</span></label>
          <input type="text" id="redirectUri" placeholder="">
        </div>
      </div>

      <div class="card">
        <div class="section-title"><h2>Security options</h2></div>
        <div class="field">
          <label>Client authentication</label>
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
        <div class="field">
          <label>PKCE</label>
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
      <div class="left-actions">
        <button class="btn block" id="startBtn" style="font-size:16px; padding:14px;">Generate authentication request →</button>
        <button class="btn block go" id="goBtn" style="display:none; margin-top:10px;">Send request →</button>
        <button class="link-btn" id="resetBtn" type="button">Reset all inputs</button>
      </div>
    </div>

    <div class="layout-resizer" title="Drag to resize · double-click to reset"></div>

    <div class="layout-right">
      <div class="card tab-group">
        <div class="tabs" id="resultTabs">
          <button class="tab-btn" data-tab="discovery" id="tabBtnDiscovery" style="display:none;">Discovery</button>
          <button class="tab-btn" data-tab="step1" id="tabBtnStep1" style="display:none;">Request preview</button>
        </div>
        <div class="placeholder" id="resultsPlaceholder">Run a step on the left to see its request/response here.</div>
        <div class="tab-panel" data-tab="discovery" id="tabPanelDiscovery"></div>
        <div class="tab-panel" data-tab="step1" id="tabPanelStep1"></div>
      </div>
    </div>
  </div>
</div>
<script src="/static/home.js"></script>
`);
}

function renderSamlHome() {
  return page('SAML test', `
<div class="wrap">
  <h1>SAML SP-initiated login test
    <small>Act as a SAML Service Provider: fill in the values on the left, generate the SAMLRequest (AuthnRequest), send it to the IdP, and watch the response come back to the ACS URL and get validated.</small>
  </h1>

  <div class="layout">
    <div class="layout-left pinned">
      <div class="left-scroll">
      <div class="card">
        <div class="section-title"><h2>Identity Provider</h2></div>
        <div class="field">
          <label>IdP metadata URL <span class="hint">optional — e.g. https://idp.example.com/realms/dev/protocol/saml/descriptor</span></label>
          <input type="text" id="metadataUrl" placeholder="http://localhost:8080/realms/dev/protocol/saml/descriptor">
        </div>
        <button class="btn block" id="discoverBtn" type="button" style="margin-bottom:14px;">Fetch metadata →</button>
        <div class="field">
          <label>IdP SSO URL <span class="hint">where the SAMLRequest is sent (HTTP-Redirect binding)</span></label>
          <input type="text" id="ssoUrl" placeholder="http://localhost:8080/realms/dev/protocol/saml">
        </div>
        <div class="field">
          <label>IdP signing certificate (PEM) <span class="hint">used to verify the Response/Assertion signature</span></label>
          <textarea id="cert" rows="5" placeholder="-----BEGIN CERTIFICATE-----&#10;...&#10;-----END CERTIFICATE-----"></textarea>
          <div class="file-row"><label class="file-pick">Choose file…<input type="file" id="certFile" hidden></label><span>or drag a .pem/.crt file onto the box</span></div>
        </div>
      </div>

      <div class="card">
        <div class="section-title"><h2>Service Provider (this app)</h2></div>
        <div class="field">
          <label>SP Entity ID <span class="hint">sent as the AuthnRequest Issuer; must match the IdP client's Client ID</span></label>
          <input type="text" id="spEntityId" placeholder="auth-inspector-saml">
        </div>
        <div class="field">
          <label>ACS URL <span class="hint">must be a registered Valid redirect URI on the IdP client</span></label>
          <input type="text" id="acsUrl" placeholder="">
        </div>
        <div class="field">
          <label>NameID Format</label>
          <select id="nameIdFormat">
            <option value="">(unspecified — let the IdP decide)</option>
            <option value="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">emailAddress</option>
            <option value="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">persistent</option>
            <option value="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">transient</option>
            <option value="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">unspecified</option>
          </select>
        </div>
        <div class="field">
          <label>ForceAuthn <span class="hint">make the IdP re-authenticate even if a session exists</span></label>
          <div class="toggle-group" id="forceAuthnToggle">
            <button type="button" data-val="off" class="active">Off</button>
            <button type="button" data-val="on">On</button>
          </div>
        </div>
      </div>

      <div class="card">
        <div class="section-title"><h2>Security options</h2></div>
        <div class="field">
          <label>Sign AuthnRequest</label>
          <div class="toggle-group" id="signToggle">
            <button type="button" data-val="off" class="active">Off</button>
            <button type="button" data-val="on">On</button>
          </div>
          <div id="signOnFields" style="display:none; margin-top:12px;">
            <textarea id="spPrivateKey" rows="5" placeholder="SP private key (PEM, RSA)&#10;-----BEGIN PRIVATE KEY-----"></textarea>
            <div class="file-row"><label class="file-pick">Choose file…<input type="file" id="spPrivateKeyFile" hidden></label><span>or drag a .pem/.key file onto the box</span></div>
          </div>
          <details class="hint-details">
            <summary>Why?</summary>
            <p>When On, the redirect URL carries <code>SigAlg</code> and <code>Signature</code> (RSA-SHA256 over the
              query string), as the HTTP-Redirect binding requires. The private key stays on the server and never
              appears in the request. The IdP needs the matching SP certificate to verify it.</p>
          </details>
        </div>
      </div>

      </div>
      <div class="left-actions">
        <button class="btn block" id="startBtn" style="font-size:16px; padding:14px;">Generate SAMLRequest →</button>
        <button class="btn block go" id="goBtn" style="display:none; margin-top:10px;">Send request →</button>
        <button class="link-btn" id="resetBtn" type="button">Reset all inputs</button>
      </div>
    </div>

    <div class="layout-resizer" title="Drag to resize · double-click to reset"></div>

    <div class="layout-right">
      <div class="card tab-group">
        <div class="tabs" id="resultTabs">
          <button class="tab-btn" data-tab="metadata" id="tabBtnMetadata" style="display:none;">Metadata</button>
          <button class="tab-btn" data-tab="step1" id="tabBtnStep1" style="display:none;">Request preview</button>
        </div>
        <div class="placeholder" id="resultsPlaceholder">Run a step on the left to see its request/response here.</div>
        <div class="tab-panel" data-tab="metadata" id="tabPanelMetadata"></div>
        <div class="tab-panel" data-tab="step1" id="tabPanelStep1"></div>
      </div>
    </div>
  </div>
</div>
<script src="/static/saml.js"></script>
`, 'saml');
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

// Builds the { label, title, badge, body } entries for whichever steps this
// run has data for, in order. Used to drive the right-hand tab strip.
function buildStepEntries(run) {
  const entries = [];

  entries.push({
    key: '1', label: 'Step 1',
    title: 'Authorization Request — browser → IdP (navigation, no CORS involved)',
    badge: '',
    body: kvTable(run.step1.params) +
      `<div class="note" style="margin-top:10px; word-break:break-all;">Full URL: <code>${escapeHtml(run.step1.url)}</code></div>`,
  });

  if (run.step2) {
    const hasError = !!run.step2.query.error;
    entries.push({
      key: '2', label: 'Step 2',
      title: 'Authorization Response — IdP → callback',
      badge: badge(!hasError, 'Code received', 'Error response'),
      body: kvTable(run.step2.query),
    });
  }

  if (run.step3) {
    const maskKeys = [];
    if (run.step3.body.client_secret) maskKeys.push('client_secret');
    if (run.step3.body.code_verifier) maskKeys.push('code_verifier');
    if (run.step3.body.code) maskKeys.push('code');
    const headerMask = run.step3.headers.Authorization ? ['Authorization'] : [];
    entries.push({
      key: '3', label: 'Step 3',
      title: 'Token Request — server → IdP (back-channel, no CORS involved)',
      badge: '',
      body: `<div class="sub">${run.step3.method} <code>${escapeHtml(run.step3.url)}</code></div>
        <div class="kv-title">Headers</div>${kvTable(run.step3.headers, headerMask)}
        <div class="kv-title">Body (application/x-www-form-urlencoded)</div>${kvTable(run.step3.body, maskKeys)}`,
    });
  }

  if (run.step4) {
    const ok = typeof run.step4.status === 'number' && run.step4.status >= 200 && run.step4.status < 300;
    entries.push({
      key: '4', label: 'Step 4',
      title: `Token Response — HTTP ${run.step4.status ?? 'ERR'} ${escapeHtml(run.step4.statusText ?? '')}`,
      badge: badge(ok, 'Token issued', 'Token request failed'),
      body: pre(run.step4.body ?? run.step4.error),
    });
  }

  if (run.step5?.idToken) {
    const t = run.step5.idToken;
    entries.push({
      key: '5', label: 'Step 5',
      title: 'ID Token — decode & verify',
      badge: t.opaque ? '' : badge(t.verify.verified, 'Verified', 'Invalid'),
      body: t.opaque ? `<div class="note">Not a JWT.</div>` :
        `<div class="kv-title">Header</div>${pre(t.header)}
         <div class="kv-title">Payload</div>${pre(t.payload)}
         <div class="badges">
           ${badge(t.verify.verified, 'Signature valid', 'Signature invalid')}
           ${badge(t.audOk, 'Audience matches', 'Audience mismatch')}
           ${badge(t.nonceOk, 'Nonce matches', 'Nonce mismatch')}
         </div>
         ${!t.verify.verified ? `<div class="note" style="margin-top:8px;">${escapeHtml(t.verify.error)}</div>` : ''}`,
    });
  }
  if (run.step5?.accessToken) {
    const t = run.step5.accessToken;
    entries.push({
      key: '6', label: 'Step 6',
      title: 'Access Token — decode & verify',
      badge: t.opaque ? '' : badge(t.verify.verified, 'Verified', 'Invalid'),
      body: t.opaque ? `<div class="note">Not a JWT — likely an opaque token (this can be normal).</div>` :
        `<div class="kv-title">Header</div>${pre(t.header)}
         <div class="kv-title">Payload</div>${pre(t.payload)}
         <div class="badges">
           ${badge(t.verify.verified, 'Signature valid', 'Signature invalid')}
           ${badge(t.audOk, 'Audience/azp matches', 'Audience/azp mismatch')}
         </div>
         ${!t.verify.verified ? `<div class="note" style="margin-top:8px;">${escapeHtml(t.verify.error)}</div>` : ''}`,
    });
  }

  return entries;
}

const STATUS_BADGE = {
  success: () => badge(true, 'Success'),
  pending: () => `<span class="badge muted">Pending</span>`,
  awaiting_exchange: () => `<span class="badge muted">Awaiting exchange</span>`,
  auth_error: () => badge(false, '', 'Auth error'),
  no_code: () => badge(false, '', 'No code'),
  token_error: () => badge(false, '', 'Token error'),
  fetch_error: () => badge(false, '', 'Network error'),
  validation_failed: () => badge(false, '', 'Validation failed'),
  parse_error: () => badge(false, '', 'Parse error'),
  no_response: () => badge(false, '', 'No SAMLResponse'),
};

function oidcEndSession(run) {
  const base = run.endpoints.end_session_endpoint;
  if (!base) return null;
  const idToken = run.step4?.body?.id_token;
  const params = { client_id: run.config.clientId };
  if (idToken) params.id_token_hint = idToken;
  return { base, params, url: withQuery(base, params) };
}

function buildOidcLogoutEntry(run) {
  const end = oidcEndSession(run);
  const rv = run.logout?.revoke;

  let revokeHtml = `<div class="note">Not run yet — use “Single logout” on the left.</div>`;
  if (rv?.error && !rv.url) {
    revokeHtml = `<div class="note">${escapeHtml(rv.error)}</div>`;
  } else if (rv) {
    const ok = typeof rv.status === 'number' && rv.status >= 200 && rv.status < 300;
    revokeHtml = `<div class="sub">POST <code>${escapeHtml(rv.url)}</code></div>
      <div class="kv-title">Headers</div>${kvTable(rv.headers, rv.headers.Authorization ? ['Authorization'] : [])}
      <div class="kv-title">Body (application/x-www-form-urlencoded)</div>${kvTable(rv.body, ['token', 'client_secret'])}
      <div class="kv-title">Response</div>
      ${rv.error
        ? `<div class="note">${escapeHtml(rv.error)}</div>`
        : `<div class="badges" style="margin-top:0;">${badge(ok, `HTTP ${rv.status} — token revoked`, `HTTP ${rv.status} — revoke failed`)}</div>
           ${rv.resBody ? `<pre style="flex:none; min-height:0;">${escapeHtml(rv.resBody)}</pre>` : ''}`}`;
  }

  return {
    key: 'logout', label: 'Logout',
    title: 'Logout — single vs. SSO',
    badge: rv ? badge(!rv.error && rv.status >= 200 && rv.status < 300, 'Tokens revoked', 'Revoke failed') : '',
    body: `<div class="kv-title">Single logout — revoke tokens (this app only)</div>
      <div class="note" style="margin-bottom:8px;">Back-channel call (RFC 7009) that invalidates this client's refresh token. What happens to the IdP's
        browser session depends on the IdP: many keep it (a new login signs straight back in), but Keycloak removes this client's session
        and, if it was the only client in the SSO session, the SSO session too — so the next login asks for credentials again.</div>
      ${revokeHtml}
      <div class="kv-title" style="margin-top:22px;">SSO logout — end the IdP session (RP-initiated)</div>
      ${end ? `<div class="note" style="margin-bottom:8px;">A browser redirect to the IdP's end-session endpoint (<code>end_session_endpoint</code> from discovery). It ends the IdP's SSO session, which signs
        out <b>every</b> app that shares it. ${end.params.id_token_hint ? '' : 'No id_token was issued, so <code>id_token_hint</code> is omitted and the IdP may ask for confirmation.'}</div>
      <div class="sub">GET <code>${escapeHtml(end.base)}</code></div>
      ${kvTable(end.params, ['id_token_hint'])}
      <p><a href="${escapeHtml(end.url)}" target="_blank" rel="noopener">Open SSO logout in new tab ↗</a></p>` :
        `<div class="note">The IdP's discovery document does not advertise an <code>end_session_endpoint</code>, so SSO logout is not available.</div>`}`,
  };
}

function oidcLogoutCard(run) {
  const end = oidcEndSession(run);
  return `<div class="card">
    <div class="section-title"><h2>Logout</h2></div>
    <form method="POST" action="/report/${escapeHtml(run.id)}/revoke">
      <button class="btn block secondary" type="submit">Single logout — revoke tokens</button>
    </form>
    ${end
      ? `<a class="btn block secondary" style="margin-top:10px;" href="${escapeHtml(end.url)}" target="_blank" rel="noopener">SSO logout — end IdP session ↗</a>`
      : `<p class="note" style="margin-top:10px;">SSO logout unavailable: no <code>end_session_endpoint</code> in the discovery document.</p>`}
    <details class="hint-details">
      <summary>What's the difference?</summary>
      <p><b>Single</b> revokes only this client's tokens; whether the IdP session survives depends on the IdP (Keycloak drops it when this was the only client in it). <b>SSO</b> ends the IdP session itself,
        so every app sharing it is signed out. See the Logout tab for the exact requests.</p>
    </details>
  </div>`;
}

function renderReport(run) {
  const cfg = run.config;
  const entries = buildStepEntries(run);
  if (run.status === 'success') entries.push(buildOidcLogoutEntry(run));
  const activeKey = run.logout ? 'logout' : entries.filter((e) => e.key !== 'logout').at(-1)?.key;

  const tabsHtml = entries.map((e) =>
    `<button class="tab-btn${e.key === activeKey ? ' active' : ''}" data-tab="${e.key}">${escapeHtml(e.label)}</button>`
  ).join('');
  const panelsHtml = entries.map((e) =>
    `<div class="tab-panel${e.key === activeKey ? ' active' : ''}" data-tab="${e.key}">
      <div class="section-title"><h2>${escapeHtml(e.title)}</h2>${e.badge}</div>
      ${e.body}
    </div>`
  ).join('');

  let leftExtra;
  if (run.status === 'awaiting_exchange') {
    leftExtra = `
      <p class="note">A single-use authorization code has been received. Nothing else happens automatically —
        this sends it over the server ↔ IdP back-channel and shows exactly what's exchanged.</p>
      <form method="POST" action="/report/${escapeHtml(run.id)}/exchange">
        <button class="btn block" type="submit">Exchange code for tokens →</button>
      </form>`;
  } else if (run.status === 'auth_error' || run.status === 'no_code') {
    leftExtra = `
      <p class="note">The IdP returned an error (or no code) during authorization, so the token exchange was skipped.</p>
      <a class="btn block secondary" href="/">Start a new test →</a>`;
  } else {
    leftExtra = (run.status === 'success' ? oidcLogoutCard(run) : '') + `<a class="btn block secondary" href="/">Start a new test →</a>`;
  }

  const html = `<div class="wrap">
    <a href="/" style="font-size:13px; color:var(--muted);">← New test</a>
    <h1 style="margin-top:10px;">Test report
      <small>${escapeHtml(cfg.clientId)} · Client authentication: <b>${cfg.authOn ? `On (${cfg.authMethod})` : 'Off'}</b> · PKCE: <b>${cfg.pkceOn ? `On (${cfg.pkceMethod})` : 'Off'}</b></small>
    </h1>

    <div class="layout">
      <div class="layout-left">
        <div class="card">
          <div class="section-title"><h2>Run summary</h2></div>
          <table class="kv">
            <tr><td>Client ID</td><td><code>${escapeHtml(cfg.clientId)}</code></td></tr>
            <tr><td>Issuer</td><td><code style="word-break:break-all;">${escapeHtml(cfg.issuer)}</code></td></tr>
            <tr><td>Redirect URI</td><td><code style="word-break:break-all;">${escapeHtml(cfg.redirectUri)}</code></td></tr>
            <tr><td>Status</td><td>${(STATUS_BADGE[run.status] || (() => escapeHtml(run.status)))()}</td></tr>
          </table>
        </div>
        ${leftExtra}
      </div>

      <div class="layout-resizer" title="Drag to resize · double-click to reset"></div>

      <div class="layout-right">
        <div class="card tab-group">
          <div class="tabs" id="resultTabs">${tabsHtml}</div>
          ${panelsHtml}
        </div>
      </div>
    </div>
  </div>`;

  return page('Test report', html);
}

function buildSamlStepEntries(run) {
  const entries = [];
  const rawPre = (s) => `<pre>${escapeHtml(s)}</pre>`;

  entries.push({
    key: '1', label: 'Step 1',
    title: 'SAMLRequest — browser → IdP (HTTP-Redirect binding, no CORS involved)',
    badge: run.step1.signed ? badge(true, 'Signed') : `<span class="badge muted">Unsigned</span>`,
    body: `<div class="kv-title">AuthnRequest XML (before deflate + base64)</div>${rawPre(run.step1.xml)}
      <div class="kv-title">Query parameters</div>${kvTable(run.step1.params)}
      <div class="note" style="margin-top:10px; word-break:break-all;">Full URL: <code>${escapeHtml(run.step1.url)}</code></div>`,
  });

  if (run.step2) {
    const b = run.step2.body;
    entries.push({
      key: '2', label: 'Step 2',
      title: 'SAMLResponse — IdP → ACS (HTTP-POST binding)',
      badge: b.SAMLResponse ? badge(true, 'Response received') : badge(false, '', 'No SAMLResponse'),
      body: `<div class="kv-title">Form fields</div>${kvTable(
        Object.fromEntries(Object.entries(b).map(([k, v]) => [k, k === 'SAMLResponse' ? `${String(v).length} chars (base64)` : v]))
      )}
      ${run.step3?.xml ? `<div class="kv-title">Decoded Response XML</div>${rawPre(run.step3.xml)}` : ''}`,
    });
  }

  if (run.step3?.error) {
    entries.push({
      key: '3', label: 'Step 3', title: 'Validation', badge: badge(false, '', 'Could not parse'),
      body: `<div class="note">${escapeHtml(run.step3.error)}</div>`,
    });
  } else if (run.step3) {
    const d = run.step3;
    const a = d.assertion;
    const sigRows = d.signatures.length
      ? d.signatures.map((s) => `<div class="kv-title">${escapeHtml(s.scope)} signature</div>
          <div class="badges">${badge(s.verified, 'Verified', 'Invalid')}</div>
          ${!s.verified && s.error ? `<div class="note" style="margin-top:8px;">${escapeHtml(s.error)}</div>` : ''}`).join('')
      : `<div class="note">No &lt;Signature&gt; on the Response or Assertion — the response is unsigned.</div>`;

    entries.push({
      key: '3', label: 'Step 3',
      title: 'Validation — signature & conditions',
      badge: badge(run.status === 'success', 'All checks passed', 'Checks failed'),
      body: `<div class="badges" style="margin-top:0;">
          ${badge(d.anySignedAndValid, 'Signature valid', d.signatures.length ? 'Signature invalid' : 'Not signed')}
          ${d.status ? badge(d.status.code === 'urn:oasis:names:tc:SAML:2.0:status:Success', 'Status: Success', 'Status: ' + (d.status.code || 'unknown')) : ''}
          ${a ? badge(a.timeValid, 'Within Conditions window', 'Expired / not yet valid') : ''}
          ${a ? badge(a.confirmationValid, 'Confirmation not expired', 'Confirmation expired') : ''}
          ${a ? badge(a.audienceOk, 'Audience matches SP Entity ID', 'Audience mismatch') : ''}
          ${a ? badge(a.recipientOk, 'Recipient matches ACS URL', 'Recipient mismatch') : ''}
          ${a ? badge(a.inResponseToOk, 'InResponseTo matches request', 'InResponseTo mismatch') : ''}
        </div>
        ${sigRows}`,
    });

    if (a) {
      const attrRows = a.attributes.length
        ? `<table class="kv">${a.attributes.map((at) =>
            `<tr><td>${escapeHtml(at.friendlyName ? `${at.name} (${at.friendlyName})` : at.name)}</td><td>${
              at.values.map((v) => `<code>${escapeHtml(v)}</code>`).join('<br>')}</td></tr>`).join('')}</table>`
        : `<div class="note">No attributes in AttributeStatement.</div>`;
      const clean = (o) => Object.fromEntries(Object.entries(o).filter(([, v]) => v != null && v !== ''));
      entries.push({
        key: '4', label: 'Step 4',
        title: 'Assertion — subject, conditions, attributes',
        badge: '',
        body: `<div class="kv-title">Issuer</div>${kvTable({ Issuer: a.issuer })}
          <div class="kv-title">Subject</div>${kvTable(clean({
            NameID: a.subject.nameId, Format: a.subject.nameIdFormat, Recipient: a.subject.recipient,
            NotOnOrAfter: a.subject.notOnOrAfter, InResponseTo: a.subject.inResponseTo }))}
          <div class="kv-title">Conditions</div>${kvTable(clean({
            NotBefore: a.conditions.notBefore, NotOnOrAfter: a.conditions.notOnOrAfter,
            Audience: a.conditions.audiences.join(', ') }))}
          ${a.authn ? `<div class="kv-title">AuthnStatement</div>${kvTable(clean({
            AuthnInstant: a.authn.authnInstant, SessionIndex: a.authn.sessionIndex,
            AuthnContextClassRef: a.authn.contextClassRef }))}` : ''}
          <div class="kv-title">Attributes</div>${attrRows}`,
      });
    }
  }

  return entries;
}

function buildSamlLogoutEntry(run) {
  const lg = run.logout;
  if (!lg) return null;

  if (lg.mode === 'local') {
    return {
      key: 'logout', label: 'Logout',
      title: 'Local logout — this app only',
      badge: `<span class="badge muted">No IdP contact</span>`,
      body: `<div class="note">Nothing was sent to the IdP. A local logout only forgets the session on the SP side, so the IdP's
        SSO session is still alive: starting a new login will usually sign straight back in without asking for a password.</div>`,
    };
  }

  const r = lg.response;
  const slsUrl = new URL('/saml/slo', run.config.acsUrl).href;
  let respHtml = `<div class="note">No LogoutResponse received yet. Click “Send to IdP”, then come back here (the IdP posts/redirects
    its LogoutResponse to <code>${escapeHtml(slsUrl)}</code>, which needs to be set as the client's Logout Service URL).</div>`;
  let respBadge = `<span class="badge muted">Awaiting response</span>`;
  if (r?.error) {
    respHtml = `<div class="note">${escapeHtml(r.error)}</div>`;
    respBadge = badge(false, '', 'Bad response');
  } else if (r) {
    const success = r.statusCode === 'urn:oasis:names:tc:SAML:2.0:status:Success';
    respBadge = badge(success, 'Logged out', 'Logout failed');
    respHtml = `<div class="badges" style="margin-top:0;">
        ${badge(success, 'Status: Success', 'Status: ' + (r.statusCode || 'unknown'))}
        ${badge(r.inResponseTo === lg.requestId, 'InResponseTo matches request', 'InResponseTo mismatch')}
      </div>
      ${kvTable({ Binding: r.binding, Issuer: r.issuer, InResponseTo: r.inResponseTo })}
      <div class="kv-title">LogoutResponse XML</div><pre style="flex:none; min-height:0;">${escapeHtml(r.xml)}</pre>
      <div class="note" style="margin-top:8px;">The LogoutResponse signature is not verified here — only its status and InResponseTo are checked.</div>`;
  }

  return {
    key: 'logout', label: 'Logout',
    title: 'SP-initiated Single Logout (SLO)',
    badge: respBadge,
    body: `<div class="note" style="margin-bottom:8px;">A LogoutRequest naming this user's NameID and SessionIndex. The IdP ends its SSO session and, if other SPs
      registered a logout URL, asks them to log out too — that's what makes SAML logout “single”.</div>
      <div class="kv-title">LogoutRequest XML (before deflate + base64)</div>
      <pre style="flex:none; min-height:0;">${escapeHtml(lg.xml)}</pre>
      <div class="kv-title">Query parameters</div>${kvTable(lg.params)}
      <p>${lg.signed ? badge(true, 'Signed') : '<span class="badge muted">Unsigned</span>'}
        <a href="${escapeHtml(lg.url)}" target="_blank" rel="noopener" style="margin-left:10px;">Send to IdP ↗</a></p>
      <div class="kv-title">LogoutResponse</div>${respHtml}`,
  };
}

function samlLogoutCard(run) {
  if (!run.step3?.assertion) return '';
  return `<div class="card">
    <div class="section-title"><h2>Logout</h2></div>
    <form method="POST" action="/saml/report/${escapeHtml(run.id)}/logout">
      <input type="hidden" name="mode" value="slo">
      <button class="btn block secondary" type="submit">Single Logout (SLO) — LogoutRequest to IdP</button>
    </form>
    <form method="POST" action="/saml/report/${escapeHtml(run.id)}/logout" style="margin-top:10px;">
      <input type="hidden" name="mode" value="local">
      <button class="btn block secondary" type="submit">Local logout only (this app)</button>
    </form>
    <details class="hint-details">
      <summary>What's the difference?</summary>
      <p><b>SLO</b> builds a LogoutRequest and lets you send it to the IdP, which ends the SSO session for every participating app.
        <b>Local</b> contacts nobody — the IdP session survives.</p>
    </details>
  </div>`;
}

function renderSamlReport(run) {
  const cfg = run.config;
  const entries = buildSamlStepEntries(run);
  const logoutEntry = buildSamlLogoutEntry(run);
  if (logoutEntry) entries.push(logoutEntry);
  const activeKey = run.logout ? 'logout' : entries.filter((e) => e.key !== 'logout').at(-1)?.key;

  const tabsHtml = entries.map((e) =>
    `<button class="tab-btn${e.key === activeKey ? ' active' : ''}" data-tab="${e.key}">${escapeHtml(e.label)}</button>`
  ).join('');
  const panelsHtml = entries.map((e) =>
    `<div class="tab-panel${e.key === activeKey ? ' active' : ''}" data-tab="${e.key}">
      <div class="section-title"><h2>${escapeHtml(e.title)}</h2>${e.badge}</div>
      ${e.body}
    </div>`
  ).join('');

  const html = `<div class="wrap">
    <a href="/saml" style="font-size:13px; color:var(--muted);">← New SAML test</a>
    <h1 style="margin-top:10px;">SAML test report
      <small>${escapeHtml(cfg.spEntityId)} · Signed request: <b>${cfg.signOn ? 'On' : 'Off'}</b> · ForceAuthn: <b>${cfg.forceAuthn ? 'On' : 'Off'}</b></small>
    </h1>

    <div class="layout">
      <div class="layout-left">
        <div class="card">
          <div class="section-title"><h2>Run summary</h2></div>
          <table class="kv">
            <tr><td>SP Entity ID</td><td><code>${escapeHtml(cfg.spEntityId)}</code></td></tr>
            <tr><td>IdP SSO URL</td><td><code style="word-break:break-all;">${escapeHtml(cfg.ssoUrl)}</code></td></tr>
            <tr><td>ACS URL</td><td><code style="word-break:break-all;">${escapeHtml(cfg.acsUrl)}</code></td></tr>
            <tr><td>Request ID</td><td><code>${escapeHtml(run.requestId)}</code></td></tr>
            <tr><td>Status</td><td>${(STATUS_BADGE[run.status] || (() => escapeHtml(run.status)))()}</td></tr>
            <tr><td>Logout</td><td>${run.logout ? (run.logout.mode === 'local' ? '<span class="badge muted">Local only</span>' : run.logout.response ? badge(run.logout.response.statusCode === 'urn:oasis:names:tc:SAML:2.0:status:Success', 'SLO complete', 'SLO failed') : '<span class="badge muted">SLO requested</span>') : '—'}</td></tr>
          </table>
        </div>
        ${samlLogoutCard(run)}
        <a class="btn block secondary" href="/saml">Start a new SAML test →</a>
      </div>

      <div class="layout-resizer" title="Drag to resize · double-click to reset"></div>

      <div class="layout-right">
        <div class="card tab-group">
          <div class="tabs" id="resultTabs">${tabsHtml}</div>
          ${panelsHtml}
        </div>
      </div>
    </div>
  </div>`;

  return page('SAML report', html, 'saml');
}

function renderRuns() {
  const list = [...runs.entries()]
    .sort((a, b) => b[1].createdAt - a[1].createdAt)
    .slice(0, 50);

  const rows = list.length
    ? list.map(([state, r]) => `
        <tr>
          <td>${escapeHtml(new Date(r.createdAt).toLocaleString())}</td>
          <td><code>${escapeHtml(r.config.clientId)}</code></td>
          <td>${(STATUS_BADGE[r.status] || (() => escapeHtml(r.status)))()}</td>
          <td><a href="/report/${state}">View →</a></td>
        </tr>`).join('')
    : `<tr><td colspan="4" class="note">No runs yet — start one from the home page.</td></tr>`;

  return page('Recent runs', `
    <div class="wrap" style="max-width:760px;">
      <a href="/" style="font-size:13px; color:var(--muted);">← New test</a>
      <h1 style="margin-top:10px;">Recent test runs</h1>
      <div class="card">
        <table class="runs">
          <thead><tr><th>Time</th><th>Client ID</th><th>Status</th><th></th></tr></thead>
          <tbody>${rows}</tbody>
        </table>
      </div>
    </div>
  `);
}

// ── Routes ──────────────────────────────────────────────────────────────

app.get('/', (req, res) => res.send(renderHome()));

app.get('/runs', (req, res) => res.send(renderRuns()));

app.post('/start', async (req, res) => {
  const { issuer, clientId, clientSecret, redirectUri, scope, authOn, authMethod, pkceOn, pkceMethod } = req.body || {};

  if (!issuer || !clientId || !redirectUri) {
    return res.status(400).json({ error: 'issuer, clientId, and redirectUri are required.' });
  }

  let disc;
  try {
    disc = await fetchOidcDiscovery(issuer);
  } catch (e) {
    return res.status(502).json({ error: `Could not reach the discovery endpoint (${normIssuer(issuer)}/.well-known/openid-configuration): ${e.message}` });
  }
  if (!disc.ok || !disc.json) {
    return res.status(502).json({ error: `Discovery failed: GET ${disc.url} returned HTTP ${disc.status}${disc.json ? '' : ' (not JSON)'}. Check the Issuer.` });
  }
  const d = disc.json;
  if (!d.authorization_endpoint || !d.token_endpoint) {
    return res.status(502).json({ error: 'The discovery document has no authorization_endpoint / token_endpoint.' });
  }
  const endpoints = {
    discoveryUrl: disc.url,
    issuer: d.issuer || normIssuer(issuer),
    issuerMismatch: !!d.issuer && d.issuer !== normIssuer(issuer),
    authorization_endpoint: d.authorization_endpoint,
    token_endpoint: d.token_endpoint,
    jwks_uri: d.jwks_uri || null,
    end_session_endpoint: d.end_session_endpoint || null,
    revocation_endpoint: d.revocation_endpoint || null,
  };

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

  const authUrl = withQuery(endpoints.authorization_endpoint, params);

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
    endpoints,
    pkceVerifier: pkce?.verifier || null,
    step1: { url: authUrl, params },
    step2: null, step3: null, step4: null, step5: null,
    status: 'pending',
  });

  res.json({ state, authUrl, params, endpoints: { discoveryUrl: endpoints.discoveryUrl, authorization_endpoint: endpoints.authorization_endpoint, issuer: endpoints.issuer, issuerMismatch: endpoints.issuerMismatch } });
});

// Performs Step 3 (token request) + Step 4 (token response) + Step 5/6
// (decode & verify), mutating `run` in place. Split out from the callback
// handler so it can be triggered explicitly by the "Exchange code for
// tokens" button instead of running automatically.
async function performTokenExchange(run) {
  const code = run.step2.query.code;
  const tokenUrl = run.endpoints.token_endpoint;
  const bodyParams = {
    grant_type: 'authorization_code',
    code: String(code),
    redirect_uri: run.config.redirectUri,
  };
  if (run.config.pkceOn) bodyParams.code_verifier = run.pkceVerifier;

  const headers = { 'Content-Type': 'application/x-www-form-urlencoded' };

  applyClientAuth(run.config, headers, bodyParams);

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
    step5.idToken = await buildTokenInfo(tokenJson.id_token, run.endpoints, run.config.clientId, run.nonce);
  }
  if (tokenJson.access_token) {
    step5.accessToken = await buildTokenInfo(tokenJson.access_token, run.endpoints, run.config.clientId, null);
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

  try {
    const d = await fetchOidcDiscovery(issuer);
    res.json({ url: d.url, status: d.status, statusText: d.statusText, body: d.json ?? d.text });
  } catch (e) {
    res.status(502).json({ url: `${normIssuer(issuer)}/.well-known/openid-configuration`, error: e.message });
  }
});

app.get('/saml', (req, res) => res.send(renderSamlHome()));

// Optional convenience: fetch IdP metadata (server-side, so no CORS) and
// return the SSO URL / signing cert found in it.
app.post('/saml/discover', async (req, res) => {
  const { metadataUrl } = req.body || {};
  if (!metadataUrl) return res.status(400).json({ error: 'metadataUrl is required.' });
  try {
    const r = await fetch(metadataUrl);
    const text = await r.text();
    let parsed = null, parseError = null;
    try { parsed = parseIdpMetadata(text); } catch (e) { parseError = e.message; }
    res.json({ url: metadataUrl, status: r.status, statusText: r.statusText, xml: text, parsed, parseError });
  } catch (e) {
    res.status(502).json({ url: metadataUrl, error: e.message });
  }
});

// Step 1: build the AuthnRequest and the redirect URL. Nothing is sent yet.
app.post('/saml/start', (req, res) => {
  const { ssoUrl, cert, spEntityId, acsUrl, nameIdFormat, forceAuthn, signOn, spPrivateKey } = req.body || {};
  if (!ssoUrl || !spEntityId || !acsUrl) {
    return res.status(400).json({ error: 'IdP SSO URL, SP Entity ID, and ACS URL are required.' });
  }
  if (signOn && !spPrivateKey) {
    return res.status(400).json({ error: 'A private key is required to sign the request.' });
  }

  const relayState = crypto.randomUUID();
  const requestId = '_' + crypto.randomBytes(16).toString('hex');
  const xml = buildAuthnRequestXml({
    id: requestId,
    issueInstant: new Date().toISOString(),
    destination: ssoUrl,
    acsUrl, spEntityId,
    nameIdFormat: nameIdFormat || '',
    forceAuthn: !!forceAuthn,
  });

  let built, keyObj = null;
  try {
    keyObj = signOn ? normalizePrivateKey(spPrivateKey) : null;
    built = buildRedirectUrl({ ssoUrl, requestXml: xml, relayState, privateKey: keyObj });
  } catch (e) {
    return res.status(400).json({ error: 'Could not build the request: ' + e.message });
  }

  samlRuns.set(relayState, {
    id: relayState,
    createdAt: Date.now(),
    config: {
      ssoUrl, cert: normalizeCert(cert), spEntityId, acsUrl,
      nameIdFormat: nameIdFormat || '', forceAuthn: !!forceAuthn, signOn: !!signOn,
    },
    requestId,
    privateKey: keyObj,
    step1: { xml, url: built.url, params: built.params, samlRequestB64: built.samlRequestB64, signed: built.signed },
    step2: null, step3: null,
    status: 'pending',
  });

  res.json({ id: relayState, requestId, xml, url: built.url, params: built.params, signed: built.signed });
});

// Step 2: the IdP POSTs the SAMLResponse here (HTTP-POST binding). It's
// validated immediately, then we redirect to the report (PRG) so a browser
// refresh never re-submits the form.
app.post('/saml/acs', (req, res) => {
  const { SAMLResponse, RelayState } = req.body || {};
  const run = RelayState && samlRuns.get(String(RelayState));
  if (!run) {
    return res.status(400).send(renderError(
      'Session not found',
      'The RelayState does not match any recorded SAML test. It may have expired (30 min), the server may have restarted, or the IdP did not echo RelayState back.'
    ));
  }

  run.step2 = { receivedAt: Date.now(), body: { ...req.body } };
  if (!SAMLResponse) {
    run.status = 'no_response';
  } else {
    try {
      run.step3 = parseAndValidateSaml({
        raw: String(SAMLResponse),
        cert: run.config.cert,
        expectedAudience: run.config.spEntityId,
        expectedRecipient: run.config.acsUrl,
        expectedInResponseTo: run.requestId,
      });
      const a = run.step3.assertion;
      const ok = run.step3.anySignedAndValid && a && a.timeValid && a.confirmationValid &&
        a.audienceOk !== false && a.recipientOk !== false && a.inResponseToOk !== false &&
        run.step3.status?.code === 'urn:oasis:names:tc:SAML:2.0:status:Success';
      run.status = ok ? 'success' : 'validation_failed';
    } catch (e) {
      run.step3 = { error: e.message };
      run.status = 'parse_error';
    }
  }
  res.redirect(`/saml/report/${run.id}`);
});

app.get('/saml/report/:id', (req, res) => {
  const run = samlRuns.get(req.params.id);
  if (!run) {
    return res.status(404).send(renderError('Run not found', 'It may have expired or the server may have restarted.'));
  }
  res.send(renderSamlReport(run));
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

// OIDC single logout: revoke this client's tokens at the IdP (back-channel).
// The SSO logout is a plain browser link built at render time.
app.post('/report/:state/revoke', async (req, res) => {
  const run = runs.get(req.params.state);
  if (!run) {
    return res.status(404).send(renderError('Run not found', 'It may have expired or the server may have restarted.'));
  }
  const tokens = run.step4?.body;
  const token = tokens?.refresh_token || tokens?.access_token;
  if (!token) {
    run.logout = { ...(run.logout || {}), revoke: { error: 'There is no token to revoke.' } };
    return res.redirect(`/report/${run.id}`);
  }

  const url = run.endpoints.revocation_endpoint;
  if (!url) {
    run.logout = { ...(run.logout || {}), revoke: { error: 'The IdP\'s discovery document does not advertise a revocation_endpoint.' } };
    return res.redirect(`/report/${run.id}`);
  }
  const headers = { 'Content-Type': 'application/x-www-form-urlencoded' };
  const body = { token, token_type_hint: tokens.refresh_token ? 'refresh_token' : 'access_token' };
  applyClientAuth(run.config, headers, body);

  const rec = { url, headers: { ...headers }, body: { ...body } };
  try {
    const r = await fetch(url, { method: 'POST', headers, body: new URLSearchParams(body) });
    rec.status = r.status;
    rec.statusText = r.statusText;
    rec.resBody = await r.text();
  } catch (e) {
    rec.error = e.message;
  }
  run.logout = { ...(run.logout || {}), revoke: rec };
  res.redirect(`/report/${run.id}`);
});

// SAML logout: either build an SP-initiated LogoutRequest (shown first, sent
// by the user), or just forget the session locally without contacting the IdP.
app.post('/saml/report/:id/logout', (req, res) => {
  const run = samlRuns.get(req.params.id);
  if (!run) {
    return res.status(404).send(renderError('Run not found', 'It may have expired or the server may have restarted.'));
  }
  const a = run.step3?.assertion;
  if (!a) {
    return res.status(400).send(renderError('Nothing to log out', 'This run has no assertion, so there is no session to end.'));
  }

  if (req.body?.mode === 'local') {
    run.logout = { mode: 'local', at: Date.now() };
    return res.redirect(`/saml/report/${run.id}`);
  }

  const requestId = '_' + crypto.randomBytes(16).toString('hex');
  const xml = buildLogoutRequestXml({
    id: requestId,
    issueInstant: new Date().toISOString(),
    destination: run.config.ssoUrl,
    spEntityId: run.config.spEntityId,
    nameId: a.subject.nameId,
    nameIdFormat: a.subject.nameIdFormat,
    sessionIndex: a.authn?.sessionIndex,
  });
  let built;
  try {
    built = buildRedirectUrl({ ssoUrl: run.config.ssoUrl, requestXml: xml, relayState: run.id, privateKey: run.privateKey });
  } catch (e) {
    return res.status(400).send(renderError('Could not build the request', e.message));
  }
  run.logout = { mode: 'slo', requestId, xml, url: built.url, params: built.params, signed: built.signed, response: null };
  res.redirect(`/saml/report/${run.id}`);
});

// Single Logout Service: where the IdP returns its LogoutResponse.
function handleSlo(req, res) {
  const src = (req.method === 'GET' ? req.query : req.body) || {};
  const run = src.RelayState && samlRuns.get(String(src.RelayState));
  if (!run || run.logout?.mode !== 'slo') {
    return res.status(400).send(renderError(
      'No matching logout',
      'The RelayState does not match a logout started from this app (it may have expired, or the IdP did not echo RelayState).'
    ));
  }
  if (src.SAMLRequest && !src.SAMLResponse) {
    return res.status(501).send(renderError('IdP-initiated logout', 'A LogoutRequest from the IdP was received, but IdP-initiated logout is not implemented.'));
  }
  try {
    run.logout.response = {
      receivedAt: Date.now(),
      binding: req.method === 'GET' ? 'HTTP-Redirect' : 'HTTP-POST',
      ...parseLogoutResponse(decodeSamlMessage(src.SAMLResponse || '')),
    };
  } catch (e) {
    run.logout.response = { error: e.message };
  }
  res.redirect(`/saml/report/${run.id}`);
}
app.get('/saml/slo', handleSlo);
app.post('/saml/slo', handleSlo);

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
