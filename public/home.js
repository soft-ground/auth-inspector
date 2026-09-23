function $(id) { return document.getElementById(id); }

function escapeHtml(str) {
  return String(str).replace(/[&<>"']/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  }[c]));
}

function setupToggle(groupId, onChange) {
  const group = $(groupId);
  if (!group) return { get: () => null };
  let val = group.querySelector('button.active')?.dataset.val;
  group.querySelectorAll('button').forEach((btn) => {
    btn.addEventListener('click', () => {
      group.querySelectorAll('button').forEach((b) => b.classList.remove('active'));
      btn.classList.add('active');
      val = btn.dataset.val;
      onChange?.(val);
    });
  });
  return { get: () => val };
}

// Reveals a result tab (if hidden), fills its panel, and switches to it.
// Mirrors the click-driven tab switching wired up in the shared page() script.
function showResult(tabKey, html) {
  $('resultsPlaceholder').style.display = 'none';

  const btn = $('tabBtn' + tabKey[0].toUpperCase() + tabKey.slice(1));
  if (btn) btn.style.display = '';

  const panel = $('tabPanel' + tabKey[0].toUpperCase() + tabKey.slice(1));
  if (panel) panel.innerHTML = html;

  document.querySelectorAll('#resultTabs .tab-btn').forEach((b) => b.classList.toggle('active', b.dataset.tab === tabKey));
  document.querySelectorAll('.tab-group .tab-panel').forEach((p) => p.classList.toggle('active', p.dataset.tab === tabKey));
}

// ── Remember field values locally for convenience ─────────────────────────
const FIELDS = ['issuer', 'clientId', 'scope', 'redirectUri', 'clientSecret'];
FIELDS.forEach((id) => {
  const saved = localStorage.getItem('auth-inspector:' + id);
  if (saved) $(id).value = saved;
});
if (!$('redirectUri').value) {
  $('redirectUri').value = location.origin + '/callback';
}
FIELDS.forEach((id) => {
  $(id).addEventListener('input', () => localStorage.setItem('auth-inspector:' + id, $(id).value));
});

// ── Toggles ─────────────────────────────────────────────────────────────
const authToggle = setupToggle('authToggle', (v) => {
  $('authOnFields').style.display = v === 'on' ? 'block' : 'none';
});
const authMethodToggle = setupToggle('authMethodToggle');
const pkceToggle = setupToggle('pkceToggle', (v) => {
  $('pkceOnFields').style.display = v === 'on' ? 'block' : 'none';
});
const pkceMethodToggle = setupToggle('pkceMethodToggle');

function renderKv(obj) {
  const rows = Object.entries(obj)
    .map(([k, v]) => `<tr><td>${escapeHtml(k)}</td><td><code>${escapeHtml(String(v))}</code></td></tr>`)
    .join('');
  return `<table class="kv">${rows}</table>`;
}

// ── Step 0: discover the provider ─────────────────────────────────────────
$('discoverBtn').addEventListener('click', async () => {
  const issuer = $('issuer').value.trim();
  if (!issuer) {
    alert('Issuer is required.');
    return;
  }

  showResult('discovery', '<div class="note">Fetching…</div>');

  const res = await fetch('/discover', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ issuer }),
  });
  const data = await res.json();

  if (data.error) {
    showResult('discovery', `<div class="note">Request to <code>${escapeHtml(data.url)}</code> failed: ${escapeHtml(data.error)}</div>`);
    return;
  }

  const ok = data.status >= 200 && data.status < 300;
  showResult('discovery', `
    <div class="sub">GET <code>${escapeHtml(data.url)}</code> — HTTP ${data.status} ${escapeHtml(data.statusText || '')}
      <span class="badge ${ok ? 'ok' : 'bad'}" style="margin-left:6px;">${ok ? 'Reachable' : 'Failed'}</span>
    </div>
    <pre>${escapeHtml(JSON.stringify(data.body, null, 2))}</pre>
  `);
});

// ── Step 1: build the authorization request ────────────────────────────────
let lastAuthUrl = null;

$('startBtn').addEventListener('click', async () => {
  const payload = {
    issuer: $('issuer').value.trim(),
    clientId: $('clientId').value.trim(),
    clientSecret: $('clientSecret').value,
    redirectUri: $('redirectUri').value.trim(),
    scope: $('scope').value.trim() || 'openid',
    authOn: authToggle.get() === 'on',
    authMethod: authMethodToggle.get(),
    pkceOn: pkceToggle.get() === 'on',
    pkceMethod: pkceMethodToggle.get(),
  };
  if (!payload.issuer || !payload.clientId || !payload.redirectUri) {
    alert('Issuer, Client ID, and Redirect URI are required.');
    return;
  }

  const res = await fetch('/start', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  if (!res.ok) {
    alert('Failed to create request: ' + (await res.text()));
    return;
  }
  const data = await res.json();
  lastAuthUrl = data.authUrl;

  const notes = [];
  if (payload.authOn) {
    notes.push('Client authentication is On, but the secret is <b>never included in this authorization request (front-channel)</b>. It is only sent in Step 3 (token exchange).');
  }
  notes.push(payload.pkceOn
    ? `PKCE is On → <code>code_challenge</code> (${payload.pkceMethod}) is included. The code_verifier stays on the server and is presented in Step 3.`
    : 'PKCE is Off → no code_challenge is included.');

  showResult('step1', `
    <div class="note">${notes.join('<br>')}</div>
    ${renderKv(data.params)}
    <div class="sub" style="margin-top:8px; word-break:break-all;">
      Full URL: <code>${escapeHtml(data.authUrl)}</code>
      <a href="${data.authUrl}" target="_blank" rel="noopener">Open in new tab ↗</a>
    </div>
  `);

  $('goBtn').style.display = '';
});

// Opens in a new tab rather than navigating this one away: the IdP's login
// page can't be embedded in an iframe here (Keycloak sends
// frame-ancestors 'self'), so a new tab is the only way to keep this page
// (and everything filled in on the left) visible while you log in. The new
// tab lands on our own /callback → /report/:state once you're done.
$('goBtn').addEventListener('click', () => {
  if (lastAuthUrl) window.open(lastAuthUrl, '_blank', 'noopener');
});
