# auth-inspector

A lightweight tool for running authentication protocols **as a client** against an
IdP (Keycloak, etc.) and seeing exactly what's exchanged at every step —
request/response params, headers, and bodies.

Both **OIDC (Authorization Code + PKCE)** and **SAML 2.0 (SP-initiated, Redirect
request / POST response)** run as a full client/SP flow, with every step visible.

## Features

- **OIDC** (works with any standards-compliant IdP: every endpoint — authorization,
  token, JWKS, revocation, end-session — is read from the discovery document at
  `{issuer}/.well-known/openid-configuration`, not assumed from a vendor path)
  - **Client authentication (Authorization) On/Off**, with a **Body vs.
    Header** delivery-method switch for the client secret.
  - **PKCE On/Off** (S256/plain).
  - Full visibility into Step 1 (authorization request) → Step 2 (callback
    response) → Step 3 (token exchange request) → Step 4 (token response) →
    Step 5/6 (**ID/Access Token decode + JWKS signature verification +
    audience/nonce checks**), all on one report page.
  - **Logout**, both ways: *single logout* revokes this client's tokens
    (RFC 7009 back-channel call; whether the IdP session survives depends on the IdP — Keycloak also ends it when this was the only client in the session), and *SSO logout*
    sends the browser to the IdP's end-session endpoint (RP-initiated, with
    `id_token_hint`), which signs out every app sharing the IdP session.
- **SAML** (this app acts as the Service Provider)
  - Enter the IdP SSO URL + signing certificate (or fetch both from the IdP
    metadata URL), plus SP Entity ID, ACS URL, NameID format, and
    ForceAuthn.
  - **Sign AuthnRequest On/Off** — when On, the redirect URL carries
    `SigAlg`/`Signature` (RSA-SHA256); the private key stays server-side.
  - Step 1 shows the `AuthnRequest` XML and how it becomes the
    `SAMLRequest` parameter (raw DEFLATE → base64 → URL-encode). Nothing is
    sent until you click **Send request**.
  - Step 2 is the IdP's HTTP-POST to `/saml/acs`; Step 3 validates it
    (**XML-DSig signature**, Status, **Conditions** window,
    **SubjectConfirmationData** expiry, **Audience** = SP Entity ID,
    **Recipient** = ACS URL, **InResponseTo** = the request ID); Step 4 shows
    the parsed assertion (Subject, AuthnStatement, Attributes).
  - Time checks are explained, not just pass/fail: Step 3 shows when validation
    ran, the estimated clock offset against the assertion's `IssueInstant`, and how
    far `NotBefore`/`NotOnOrAfter` are from now. A fixed **±60 s clock-skew allowance** absorbs a machine clock that drifts
    from the IdP's, and the result is flagged when it passed only thanks to it.
  - **Logout**: *SP-initiated Single Logout* builds a `LogoutRequest`
    (NameID + SessionIndex, signed if signing is On), shows it, and — once
    sent — validates the `LogoutResponse` that returns to `/saml/slo`
    (set that URL as the client's Logout Service URL in the IdP).
    *Local logout* contacts nobody, to show that the IdP session survives.
- **Convenience**: field values and option switches are remembered in your browser and
  pre-filled on the next visit (client secrets and private keys are never saved); **Reset
  all inputs** on either page clears the fields and the saved copies. The
  action buttons stay pinned in view while the input column scrolls.
- A single Node/Express process with a handful of small dependencies
  (`express`, `jose`, `xml-crypto`, `@xmldom/xmldom`, `xpath`). No build
  step — `npm start` and you're running.

## How it works

- **Step 1 (authorization request) is a plain browser redirect** — a
  top-level navigation, not a fetch/XHR — so it's **not subject to CORS**.
  Even with Client authentication On, **the secret never appears in this
  URL**.
- **Step 3 (token exchange) happens server-to-server** (this app ↔ the IdP).
  The secret is only ever sent here — never to the browser. Switch between
  Body (`client_secret_post`) and Header (`Basic`) to compare the actual
  wire format.
- An authorization code is single-use. Refreshing the callback URL would
  resubmit it and fail, so after processing the callback the app redirects
  to `/report/:state` — refreshing that page is safe.

## Run it

```bash
npm install
npm start            # http://localhost:5555
# or
PORT=6000 npm start
```

The server binds to `0.0.0.0`, so it's also reachable at
`http://<your-dev-host>:5555` from other machines on the same network.

## Set up your IdP client

Register this app's callback URL in the client's **Valid redirect URIs**:

```
http://localhost:5555/callback
```

- To test with **Client authentication On**, copy the client secret from
  the **Credentials** tab and paste it into the app.
- **PKCE On/Off** here is independent of the IdP's own "Require PKCE"
  setting — it controls whether *this app* actually sends PKCE parameters.
  If the IdP requires PKCE and you leave it Off, you'll see the IdP's
  rejection right there in Step 2 — which is itself a useful thing to see.

## Usage

1. Fill in Issuer, Client ID, Scope, and Redirect URI (remembered in
   localStorage for next time).
2. Set the Client authentication and PKCE toggles to the combination you
   want to test.
3. Click **"Build authorization request"** — Step 1 shows exactly what will
   be sent (confirm for yourself that the secret is nowhere in it), then
   click **"Continue to IdP login"**.
4. After logging in, the IdP redirects back to this app's `/callback`,
   which performs the token exchange and lands you on the report page with
   Steps 1–6 filled in.
5. Sensitive values (secret, code_verifier, code) are masked by default —
   click to reveal.
6. Past OIDC and SAML runs are listed together under "Recent runs" (top bar),
   newest first, with a protocol column. They are kept in memory for 30 minutes
   or until the server restarts.

## Combinations worth trying

| Client auth | PKCE | What to look for |
|---|---|---|
| Off | On | Step 1 has `code_challenge`; Step 3's body has only `code_verifier` — no secret anywhere (Public + PKCE, the same pattern Keycloak's own admin console uses) |
| On (Body) | On | Step 3's body carries both `client_secret` and `code_verifier` (Confidential + PKCE, the recommended combination) |
| On (Header) | On | Same intent, but Step 3's body has no `client_secret` — it's sent as an `Authorization: Basic ...` header instead |
| Off | Off | If the IdP client has "Require PKCE" on, Step 2 shows its rejection directly |

## Notes and limitations

- Built for local/internal development networks. Secrets are shown on
  screen (when unmasked) for learning purposes — **never use a production
  client secret here.**
- Runs are kept **in memory only**, with no database. Restarting the server
  clears history — a deliberate trade-off for staying lightweight.
- SAML uses the **HTTP-Redirect** binding for the request and **HTTP-POST**
  for the response. SP metadata generation and IdP-initiated logout are not
  implemented; the `LogoutResponse` signature is not verified.
- SAML validation doesn't handle **encrypted assertions**
  (`<EncryptedAssertion>`) — only plain, signed (or unsigned) assertions.

## License

MIT — see [LICENSE](LICENSE).
