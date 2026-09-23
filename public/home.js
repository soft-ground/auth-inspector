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

  const box = $('discoverResult');
  box.style.display = 'block';
  box.innerHTML = '<div class="note">Fetching…</div>';

  const res = await fetch('/discover', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ issuer }),
  });
  const data = await res.json();

  if (data.error) {
    box.innerHTML = `<div class="note">Request to <code>${escapeHtml(data.url)}</code> failed: ${escapeHtml(data.error)}</div>`;
    return;
  }

  const ok = data.status >= 200 && data.status < 300;
  box.innerHTML = `
    <div class="sub">GET <code>${escapeHtml(data.url)}</code> — HTTP ${data.status} ${escapeHtml(data.statusText || '')}
      <span class="badge ${ok ? 'ok' : 'bad'}" style="margin-left:6px;">${ok ? 'Reachable' : 'Failed'}</span>
    </div>
    <pre>${escapeHtml(JSON.stringify(data.body, null, 2))}</pre>
  `;
});

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

  $('step1Card').style.display = 'block';
  $('step1Body').innerHTML = `
    <div class="note">${notes.join('<br>')}</div>
    ${renderKv(data.params)}
    <div class="sub" style="margin-top:8px; word-break:break-all;">
      Full URL: <code>${escapeHtml(data.authUrl)}</code>
      <a href="${data.authUrl}" target="_blank" rel="noopener">Open in new tab ↗</a>
    </div>
  `;
  $('step1Card').scrollIntoView({ behavior: 'smooth', block: 'start' });
});

$('goBtn').addEventListener('click', () => {
  if (lastAuthUrl) location.href = lastAuthUrl;
});

async function loadHistory() {
  const res = await fetch('/api/runs');
  const list = await res.json();
  if (!list.length) {
    $('historyBody').innerHTML = 'None yet';
    return;
  }
  const badgeClass = (status) =>
    status === 'success' ? 'ok' : status === 'pending' || status === 'awaiting_exchange' ? 'muted' : 'bad';
  $('historyBody').innerHTML = '<table class="kv">' + list.map((r) => `
    <tr>
      <td>${new Date(r.createdAt).toLocaleTimeString()}</td>
      <td>${escapeHtml(r.clientId)} · <span class="badge ${badgeClass(r.status)}">${escapeHtml(r.status)}</span>
        · <a href="/report/${r.state}">view →</a></td>
    </tr>`).join('') + '</table>';
}
loadHistory();
