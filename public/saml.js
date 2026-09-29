function $(id) { return document.getElementById(id); }

function escapeHtml(str) {
  return String(str ?? '').replace(/[&<>"']/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  }[c]));
}

function badge(ok, textOk = 'OK', textBad = 'Failed') {
  if (ok === null || ok === undefined) return `<span class="badge muted">N/A</span>`;
  return `<span class="badge ${ok ? 'ok' : 'bad'}">${escapeHtml(ok ? textOk : textBad)}</span>`;
}

function kvTable(rows) {
  const trs = rows
    .filter(([, v]) => v !== null && v !== undefined && v !== '')
    .map(([k, v]) => `<tr><td>${escapeHtml(k)}</td><td><code>${escapeHtml(String(v))}</code></td></tr>`)
    .join('');
  return `<table class="kv">${trs}</table>`;
}

// Shows a result tab (revealing its button if hidden) and fills its panel —
// mirrors showResult() in home.js / the tab-switching wired up in page().
function showTab(tabKey, html) {
  $('resultsPlaceholder').style.display = 'none';
  const cap = tabKey[0].toUpperCase() + tabKey.slice(1);
  const btn = $('tabBtn' + cap);
  if (btn) btn.style.display = '';
  const panel = $('tabPanel' + cap);
  if (panel) panel.innerHTML = html;
}

function activateTab(tabKey) {
  document.querySelectorAll('#resultTabs .tab-btn').forEach((b) => b.classList.toggle('active', b.dataset.tab === tabKey));
  document.querySelectorAll('.tab-group .tab-panel').forEach((p) => p.classList.toggle('active', p.dataset.tab === tabKey));
}

// ── Remember cert/audience/recipient locally for convenience ──────────────
const FIELDS = ['cert', 'audience', 'recipient'];
FIELDS.forEach((id) => {
  const saved = localStorage.getItem('auth-inspector:saml:' + id);
  if (saved) $(id).value = saved;
  $(id).addEventListener('input', () => localStorage.setItem('auth-inspector:saml:' + id, $(id).value));
});

function renderOverview(data) {
  const parts = [];

  parts.push(`<div class="badges" style="margin-bottom:14px;">
    ${badge(data.anySignedAndValid, 'Signature valid', data.signatures.length ? 'Signature invalid' : 'Not signed')}
    ${data.status ? badge(data.status.code === 'urn:oasis:names:tc:SAML:2.0:status:Success', 'Status: Success', 'Status: ' + (data.status.code || 'unknown')) : ''}
    ${data.assertion ? badge(data.assertion.timeValid, 'Within Conditions window', 'Expired / not yet valid') : ''}
    ${data.assertion ? badge(data.assertion.confirmationValid, 'Confirmation not expired', 'Confirmation expired') : ''}
    ${data.assertion?.audienceOk !== null && data.assertion ? badge(data.assertion.audienceOk, 'Audience matches', 'Audience mismatch') : ''}
    ${data.assertion?.recipientOk !== null && data.assertion ? badge(data.assertion.recipientOk, 'Recipient matches', 'Recipient mismatch') : ''}
  </div>`);

  parts.push(kvTable([
    ['Root element', data.isBareAssertion ? 'Assertion (no envelope)' : 'Response'],
    ['Response status', data.status?.code],
    ['Response Issuer', data.responseIssuer],
    ['Assertion Issuer', data.assertion?.issuer],
    ['NameID', data.assertion?.subject?.nameId],
    ['NameID Format', data.assertion?.subject?.nameIdFormat],
    ['Conditions NotBefore', data.assertion?.conditions?.notBefore],
    ['Conditions NotOnOrAfter', data.assertion?.conditions?.notOnOrAfter],
    ['Audience(s)', data.assertion?.conditions?.audiences?.join(', ')],
  ]));

  if (!data.signatures.length) {
    parts.push(`<div class="note" style="margin-top:10px;">No &lt;Signature&gt; element found on the Response or Assertion — this response is unsigned (or was signed some other way, e.g. TLS-only transport, which this tool doesn't check).</div>`);
  }

  return parts.join('');
}

function renderSignature(data) {
  if (!data.signatures.length) {
    return `<div class="note">No &lt;Signature&gt; element found on the Response or Assertion.</div>`;
  }
  return data.signatures.map((s) => `
    <div class="kv-title">${escapeHtml(s.scope)} signature</div>
    <div class="badges">${badge(s.verified, 'Verified', 'Invalid')}</div>
    ${!s.verified && s.error ? `<div class="note" style="margin-top:8px;">${escapeHtml(s.error)}</div>` : ''}
  `).join('<hr style="border:none; border-top:1px solid var(--border); margin:16px 0;">');
}

function renderAttributesTable(attrs) {
  if (!attrs || !attrs.length) return '<div class="note">No attributes in AttributeStatement.</div>';
  const rows = attrs.map((a) => `
    <tr>
      <td>${escapeHtml(a.friendlyName ? `${a.name} (${a.friendlyName})` : a.name)}</td>
      <td>${a.values.map((v) => `<code>${escapeHtml(v)}</code>`).join('<br>') || '<span class="note">—</span>'}</td>
    </tr>`).join('');
  return `<table class="kv">${rows}</table>`;
}

function renderAssertion(data) {
  const a = data.assertion;
  if (!a) return `<div class="note">No &lt;Assertion&gt; found in this response.</div>`;

  return `
    <div class="kv-title">Subject</div>
    ${kvTable([
      ['NameID', a.subject.nameId],
      ['NameID Format', a.subject.nameIdFormat],
      ['SubjectConfirmationData Recipient', a.subject.recipient],
      ['SubjectConfirmationData NotOnOrAfter', a.subject.notOnOrAfter],
      ['InResponseTo', a.subject.inResponseTo],
    ])}

    <div class="kv-title">Conditions</div>
    ${kvTable([
      ['NotBefore', a.conditions.notBefore],
      ['NotOnOrAfter', a.conditions.notOnOrAfter],
      ['Audience(s)', a.conditions.audiences.join(', ')],
    ])}

    ${a.authn ? `<div class="kv-title">AuthnStatement</div>
    ${kvTable([
      ['AuthnInstant', a.authn.authnInstant],
      ['SessionIndex', a.authn.sessionIndex],
      ['AuthnContextClassRef', a.authn.contextClassRef],
    ])}` : ''}

    <div class="kv-title">Attributes</div>
    ${renderAttributesTable(a.attributes)}
  `;
}

$('validateBtn').addEventListener('click', async () => {
  const samlResponse = $('samlInput').value.trim();
  const cert = $('cert').value.trim();
  if (!samlResponse) {
    alert('Paste a SAML Response first.');
    return;
  }
  if (!cert) {
    alert('Paste the IdP signing certificate (PEM) first.');
    return;
  }

  showTab('overview', '<div class="note">Validating…</div>');
  activateTab('overview');

  const res = await fetch('/saml/verify', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      samlResponse,
      cert,
      audience: $('audience').value.trim(),
      recipient: $('recipient').value.trim(),
    }),
  });
  const data = await res.json();

  if (!res.ok) {
    showTab('overview', `<div class="note">${escapeHtml(data.error || 'Validation failed.')}</div>`);
    activateTab('overview');
    return;
  }

  showTab('overview', renderOverview(data));
  showTab('signature', renderSignature(data));
  showTab('assertion', renderAssertion(data));
  showTab('raw', `<pre>${escapeHtml(data.xml)}</pre>`);
  activateTab('overview');
});
