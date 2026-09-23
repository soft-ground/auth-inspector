# auth-inspector

A lightweight tool for running authentication protocols **as a client** against an
IdP (Keycloak, etc.) and seeing exactly what's exchanged at every step —
request/response params, headers, and bodies.

Only **OIDC (Authorization Code + PKCE)** is implemented so far. **SAML** has a
placeholder tab in the UI ("SAML (coming soon)") — it needs a fundamentally
different implementation (XML signing, SP metadata, etc.) and will be added
once there's a SAML client to test against.

## Features

- **Client authentication (Authorization) On/Off**, with a **Body vs. Header**
  delivery-method switch for the client secret.
- **PKCE On/Off** (S256/plain).
- Full visibility into Step 1 (authorization request) → Step 2 (callback
  response) → Step 3 (token exchange request) → Step 4 (token response) →
  Step 5/6 (**ID/Access Token decode + JWKS signature verification +
  audience/nonce checks**), all on one report page.
- A single Node/Express process with two dependencies (`express`, `jose`).
  No build step — `npm start` and you're running.

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
6. Past runs are listed under "Recent test runs" on the home page (kept in
   memory until the server restarts).

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
- **OIDC only, for now.** SAML is a placeholder tab and not implemented.

## License

MIT — see [LICENSE](LICENSE).
