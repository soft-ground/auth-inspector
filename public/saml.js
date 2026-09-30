function $(id) { return document.getElementById(id); }

function escapeHtml(str) {
  return String(str ?? '').replace(/[&<>"']/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  }[c]));
}

function setupToggle(groupId, onChange) {
  const group = $(groupId);
  const storeKey = 'auth-inspector:saml:toggle:' + groupId;
  let val = group.querySelector('button.active')?.dataset.val;
  group.querySelectorAll('button').forEach((btn) => {
    btn.addEventListener('click', () => {
      group.querySelectorAll('button').forEach((b) => b.classList.remove('active'));
      btn.classList.add('active');
      val = btn.dataset.val;
      onChange?.(val);
      try { localStorage.setItem(storeKey, val); } catch { /* storage unavailable */ }
    });
  });
  let saved = null;
  try { saved = localStorage.getItem(storeKey); } catch { /* storage unavailable */ }
  const savedBtn = saved && group.querySelector(`button[data-val="${saved}"]`);
  if (savedBtn) savedBtn.click();
  return { get: () => val };
}

function showResult(tabKey, html) {
  $('resultsPlaceholder').style.display = 'none';
  const cap = tabKey[0].toUpperCase() + tabKey.slice(1);
  const btn = $('tabBtn' + cap);
  if (btn) btn.style.display = '';
  const panel = $('tabPanel' + cap);
  if (panel) panel.innerHTML = html;
  document.querySelectorAll('#resultTabs .tab-btn').forEach((b) => b.classList.toggle('active', b.dataset.tab === tabKey));
  document.querySelectorAll('.tab-group .tab-panel').forEach((p) => p.classList.toggle('active', p.dataset.tab === tabKey));
}

function renderKv(obj) {
  const rows = Object.entries(obj)
    .map(([k, v]) => `<tr><td>${escapeHtml(k)}</td><td><code>${escapeHtml(String(v))}</code></td></tr>`)
    .join('');
  return `<table class="kv">${rows}</table>`;
}

// ── Remember field values locally for convenience (private key is never stored) ──
const FIELDS = ['metadataUrl', 'ssoUrl', 'cert', 'spEntityId', 'acsUrl', 'nameIdFormat'];
FIELDS.forEach((id) => {
  const saved = localStorage.getItem('auth-inspector:saml:' + id);
  if (saved) $(id).value = saved;
  $(id).addEventListener('input', () => localStorage.setItem('auth-inspector:saml:' + id, $(id).value));
});
if (!$('acsUrl').value) $('acsUrl').value = location.origin + '/saml/acs';

// Fill a PEM textarea from a picked or dropped file. The file is read in the
// browser only; nothing is uploaded until "Generate SAMLRequest".
function bindPemFile(textareaId, fileInputId) {
  const ta = $(textareaId);
  async function load(file) {
    if (!file) return;
    if (file.size > 64 * 1024) { alert('That file is too large to be a PEM key/certificate.'); return; }
    const text = await file.text();
    const looksPem = text.includes('-----BEGIN');
    const looksBareBase64 = /^[A-Za-z0-9+/=\s]+$/.test(text.trim());
    if (!looksPem && !looksBareBase64) {
      alert('Expected a PEM text file (-----BEGIN ...) or bare base64 text. Binary keystores (.p12/.jks/.der) must be converted first.');
      return;
    }
    ta.value = text.trim();
    ta.dispatchEvent(new Event('input'));
  }
  $(fileInputId).addEventListener('change', (e) => { load(e.target.files[0]); e.target.value = ''; });
  ta.addEventListener('dragover', (e) => { e.preventDefault(); ta.classList.add('drag-over'); });
  ta.addEventListener('dragleave', () => ta.classList.remove('drag-over'));
  ta.addEventListener('drop', (e) => {
    e.preventDefault();
    ta.classList.remove('drag-over');
    load(e.dataTransfer.files[0]);
  });
}
bindPemFile('cert', 'certFile');
bindPemFile('spPrivateKey', 'spPrivateKeyFile');

const forceAuthnToggle = setupToggle('forceAuthnToggle');
const signToggle = setupToggle('signToggle', (v) => {
  $('signOnFields').style.display = v === 'on' ? 'block' : 'none';
});

// ── Optional: fetch IdP metadata and prefill SSO URL / cert ──────────────────
$('discoverBtn').addEventListener('click', async () => {
  const metadataUrl = $('metadataUrl').value.trim();
  if (!metadataUrl) {
    alert('IdP metadata URL is required.');
    return;
  }
  showResult('metadata', '<div class="note">Fetching…</div>');

  const res = await fetch('/saml/discover', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ metadataUrl }),
  });
  const data = await res.json();

  if (data.error) {
    showResult('metadata', `<div class="note">Request to <code>${escapeHtml(data.url || metadataUrl)}</code> failed: ${escapeHtml(data.error)}</div>`);
    return;
  }

  const ok = data.status >= 200 && data.status < 300;
  let filled = '';
  if (data.parsed) {
    if (data.parsed.ssoUrl) { $('ssoUrl').value = data.parsed.ssoUrl; $('ssoUrl').dispatchEvent(new Event('input')); }
    if (data.parsed.cert) { $('cert').value = data.parsed.cert; $('cert').dispatchEvent(new Event('input')); }
    filled = `<div class="note" style="margin-bottom:10px;">Filled in from metadata: IdP SSO URL${data.parsed.cert ? ' and signing certificate' : ''}.
      IdP entityID: <code>${escapeHtml(data.parsed.entityId || '—')}</code></div>`;
  } else if (data.parseError) {
    filled = `<div class="note" style="margin-bottom:10px;">Could not parse metadata: ${escapeHtml(data.parseError)}</div>`;
  }

  showResult('metadata', `
    <div class="sub">GET <code>${escapeHtml(data.url)}</code> — HTTP ${data.status} ${escapeHtml(data.statusText || '')}
      <span class="badge ${ok ? 'ok' : 'bad'}" style="margin-left:6px;">${ok ? 'Reachable' : 'Failed'}</span>
    </div>
    ${filled}
    <pre>${escapeHtml(data.xml)}</pre>
  `);
});

// ── Step 1: build the SAMLRequest ────────────────────────────────────────────
let lastUrl = null;

$('startBtn').addEventListener('click', async () => {
  const payload = {
    ssoUrl: $('ssoUrl').value.trim(),
    cert: $('cert').value.trim(),
    spEntityId: $('spEntityId').value.trim(),
    acsUrl: $('acsUrl').value.trim(),
    nameIdFormat: $('nameIdFormat').value,
    forceAuthn: forceAuthnToggle.get() === 'on',
    signOn: signToggle.get() === 'on',
    spPrivateKey: $('spPrivateKey').value.trim(),
  };
  if (!payload.ssoUrl || !payload.spEntityId || !payload.acsUrl) {
    alert('IdP SSO URL, SP Entity ID, and ACS URL are required.');
    return;
  }
  if (!payload.cert) {
    if (!confirm('No IdP certificate entered — the response signature cannot be verified. Continue anyway?')) return;
  }

  const res = await fetch('/saml/start', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  const data = await res.json();
  if (!res.ok) {
    alert('Failed to create request: ' + (data.error || res.statusText));
    return;
  }
  lastUrl = data.url;

  const notes = [
    'The AuthnRequest XML below is <b>raw DEFLATE-compressed, base64-encoded, then URL-encoded</b> into the <code>SAMLRequest</code> query parameter (HTTP-Redirect binding).',
    `<code>RelayState</code> carries this test's id, so the IdP's POST to the ACS URL can be matched back to it. The request <code>ID</code> is <code>${escapeHtml(data.requestId)}</code> — the response's <code>InResponseTo</code> should echo it.`,
  ];
  notes.push(data.signed
    ? 'Signing is On → <code>SigAlg</code> and <code>Signature</code> are appended. The private key stays on the server.'
    : 'Signing is Off → no <code>Signature</code> is sent.');

  showResult('step1', `
    <div class="note">${notes.join('<br>')}</div>
    <div class="kv-title">AuthnRequest XML</div>
    <pre style="flex:none; min-height:0;">${escapeHtml(data.xml)}</pre>
    <div class="kv-title">Query parameters</div>
    ${renderKv(data.params)}
    <div class="sub" style="margin-top:8px; word-break:break-all;">
      Full URL: <code>${escapeHtml(data.url)}</code>
    </div>
  `);
  $('goBtn').disabled = false;
});

// New tab: the IdP login page can't be framed here, and the IdP's POST lands
// on our own /saml/acs -> /saml/report/:id in that tab.
$('goBtn').addEventListener('click', () => {
  if (lastUrl) window.open(lastUrl, '_blank', 'noopener');
});

// ── Reset every input (and the saved copies) back to a fresh state ───────────
$('resetBtn').addEventListener('click', () => {
  if (!confirm('Clear all inputs and the values saved in this browser?')) return;
  FIELDS.forEach((id) => localStorage.removeItem('auth-inspector:saml:' + id));
  ['metadataUrl', 'ssoUrl', 'cert', 'spEntityId', 'spPrivateKey'].forEach((id) => { $(id).value = ''; });
  $('acsUrl').value = location.origin + '/saml/acs';
  $('nameIdFormat').value = '';
  ['forceAuthnToggle', 'signToggle'].forEach((id) => $(id).querySelector('button').click());
  ['forceAuthnToggle', 'signToggle'].forEach((id) => localStorage.removeItem('auth-inspector:saml:toggle:' + id));

  document.querySelectorAll('#resultTabs .tab-btn').forEach((b) => { b.style.display = 'none'; b.classList.remove('active'); });
  document.querySelectorAll('.tab-group .tab-panel').forEach((p) => { p.innerHTML = ''; p.classList.remove('active'); });
  $('resultsPlaceholder').style.display = '';
  $('goBtn').disabled = true;
  lastUrl = null;
});
