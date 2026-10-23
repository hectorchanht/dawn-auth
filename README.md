# @dawn-studio/auth

The Dawn Studio **app-auth standard**, extracted from OpenMusic (the reference implementation, live since 2026-10-20):

- **Magic link** — click to sign in (15-min, single-use; mail-scanner-safe: the link lands on a page that POSTs the token, so prefetch can't burn it)
- **6-digit code** — in the same email, typed into the app (the native path: no browser, no deep link)
- **Google sign-in** — no Firebase, no new infra: Google only proves identity via ID token (RS256 vs Google JWKS); the app's own session infra takes over

Link and code are **two credentials for one login intent**: either consumes it; both single-use, 15-min; the code dies after 5 wrong attempts. Same-email Google + magic-link + code resolve to **one user row** (upsert by email). Sessions are 30-day, stored as `SHA-256('session:'+token)` in D1, carried in an httpOnly cookie on web and as `Authorization: Bearer` on native.

Edge-safe (Web Crypto only), **zero runtime dependencies**, framework-agnostic.

## Install

```bash
npm i @dawn-studio/auth
```

## Setup

```ts
import { defineAuth, createD1Store } from '@dawn-studio/auth';

// One call per app. `from` is REQUIRED (own-domain rule: every app sends from its
// own domain — never a borrowed one). Missing `from` throws at boot, not at the
// first sign-in attempt.
export const auth = defineAuth({
  appName: 'Clipbin',
  domain: 'clipbin.lol',
  from: 'Clipbin <login@clipbin.lol>',
  resendApiKey: process.env.RESEND_API_KEY,
  googleClientId: 'YOUR-WEB-CLIENT-ID.apps.googleusercontent.com', // public, not a secret
  nativeSchemes: ['clipbin://'], // omit for web-only apps
});

export const store = createD1Store(env.ACCOUNTS_DB);
```

Apply `schema.sql` to a **dedicated** D1 database (PII isolation: emails live here, never in the analytics DB):

```bash
wrangler d1 execute accounts --file=node_modules/@dawn-studio/auth/schema.sql
```

## Server routes

The service layer owns the semantics; your routes own the HTTP shape (guards, CORS, body parsing). SvelteKit example:

```ts
// POST /api/auth/magic-link
import { requestMagicLink, requestIp } from '@dawn-studio/auth';
export const POST = async ({ request }) => {
  const { email, scheme } = await request.json();
  const result = await requestMagicLink(store, auth, {
    email, scheme,
    origin: new URL(request.url).origin,
    ip: requestIp(request),
  });
  return Response.json(result === 'ok' ? { ok: true } : { ok: false, err: result },
    { status: result === 'ok' ? 200 : result === 'rate-limited' ? 429 : 400 });
};

// POST /api/auth/verify  (the /auth/magic landing page POSTs the token here)
import { verifyMagicToken, sessionCookie } from '@dawn-studio/auth';
export const POST = async ({ request }) => {
  const { token } = await request.json();
  const r = await verifyMagicToken(store, auth, token);
  if (!r.ok) return Response.json({ ok: false, err: 'invalid-token' }, { status: 400 });
  return new Response(JSON.stringify({ user: r.user, token: r.sessionToken, scheme: r.scheme }), {
    headers: { 'content-type': 'application/json', 'Set-Cookie': sessionCookie(r.sessionToken, auth) },
  });
};

// POST /api/auth/verify-code, POST /api/auth/google — same shape, via
// verifyCode(store, auth, { email, code, ip }) and
// signInWithGoogle(store, auth, { idToken, ip }).

// GET /api/auth/session
import { getSessionUser } from '@dawn-studio/auth';
export const GET = async ({ request }) => {
  const user = await getSessionUser(store, auth, request); // cookie OR bearer
  return Response.json({ user }); // always 200; null = signed out
};

// POST /api/auth/logout
import { destroySession } from '@dawn-studio/auth';
export const POST = async ({ request }) => {
  const { clearCookie } = await destroySession(store, auth, request);
  return new Response(JSON.stringify({ ok: true }), {
    headers: { 'content-type': 'application/json', 'Set-Cookie': clearCookie },
  });
};
```

Result unions (map each to your status / i18n key — the lib never localizes):

| function | results |
|---|---|
| `requestMagicLink` | `ok` · `invalid-email` · `invalid-scheme` · `rate-limited` · `not-configured` · `send-failed` |
| `verifyMagicToken` | `{ok:true,…}` · `{ok:false, reason:'invalid-token'}` (one refusal for unknown/used/expired — no oracle) |
| `verifyCode` | `ok` · `invalid` · `invalid-code` · `too-many-attempts` · `rate-limited` |
| `signInWithGoogle` | `{ok:true,…}` · `{ok:false, reason:'invalid-token'|'rate-limited'|'not-configured'}` |

`requestLinkMessages` / `verifyCodeMessages` / `googleSignInMessages` provide default English copy.

## Browser client

Framework-agnostic (React/Vue/Svelte/vanilla). Web uses the httpOnly cookie; native (Capacitor etc.) persists the bearer and sends it as `Authorization: Bearer`.

```ts
import { DawnAuthClient } from '@dawn-studio/auth';

export const authClient = new DawnAuthClient({
  isNative: () => Capacitor.isNativePlatform(), // default false (web)
  tokenStorageKey: 'clipbin:auth-token:v1',
  onNativeGoogleSignOut: async () => { /* release Play-Services identity */ },
});

authClient.subscribe(({ user, ready }) => { /* render */ });
await authClient.load(); // boot probe: GET /api/auth/session

await authClient.requestLink(email, { scheme: 'clipbin://' }); // 'ok' | 'rate-limited' | … (one retry on network failure, then a differential probe; diag in client.lastLinkDiag)
await authClient.verify(tokenFromUrl);        // magic-link landing page
await authClient.verifyCode(email, code);     // native path
await authClient.signInWithGoogle(idToken);   // GIS button / Play Services
await authClient.adoptNativeToken(token);     // deep-link callback handler
await authClient.logout();
```

## What each module does

| module | contents |
|---|---|
| `config` | `defineAuth()` — validated app config (branding, cookie, schemes, TTLs, rate limits, mailer override) |
| `core` | pure primitives: token/code minting, SHA-256 helpers, cookie + bearer extraction, deep-link build/parse, `diagLine` (the real error), constant-time compare |
| `google` | `verifyGoogleIdToken` — RS256 vs Google JWKS (kid-matched), aud/iss/exp/email_verified; never throws |
| `email` | `buildSignInEmail` — the house design: teal CTA button, big copyable code box (Gmail "Copy code" mirror), formal footer |
| `store` | `AuthStore` interface + `createD1Store()` (the house backend); `rateLimit` fixed-window helper |
| `service` | the three flows + `getSessionUser` / `destroySession` — never-throw, typed results |
| `client` | `DawnAuthClient` — browser session client, web + native bearer seam |
| `messages` | default English UI copy for the result unions |

## Security notes

- Raw tokens **never touch the database** — only `SHA-256('magic:'|… 'code:'|'session:'+token)` are stored. A DB leak hands out no usable credential.
- One refusal shape for unknown/used/expired/wrong (`invalid-token` / `invalid-code`) — no oracle for guessing.
- Code hashes compared in constant time; the 6-digit space is never indexed (lookup is by email).
- Google certs are cached 1h per isolate; `email_verified` must be boolean `true`.
- The Resend send carries a browser User-Agent — Resend's front door 403s bare UAs (error 1010).

## Migrating an app (from OpenMusic's inline copy)

OpenMusic's `src/lib/auth/auth-core.ts` + the five `/api/auth/*` routes + `src/lib/stores/auth.svelte.ts` map 1:1 onto this lib. Deltas:

- constants → `defineAuth()` fields (`SESSION_COOKIE_NAME` → `cookieName`, `GOOGLE_WEB_CLIENT_ID` → `googleClientId`, `NATIVE_APP_SCHEME` → `nativeSchemes`, `DEFAULT_MAGIC_LINK_FROM` → `from`)
- `verifyGoogleIdToken(token)` → `verifyGoogleIdToken(token, { clientId })`
- `buildSignInEmail(link, code, to)` → `buildSignInEmail({ appName, domain, brandColor, link, code, toEmail })`
- routes → thin wrappers over `requestMagicLink` / `verifyMagicToken` / `verifyCode` / `signInWithGoogle` / `getSessionUser` / `destroySession` with a `createD1Store(env.ACCOUNTS_DB)`
- the Svelte store → `DawnAuthClient` (or keep the store and call the service from routes only)

`user_sync` / the sync envelope stays per-app — it is data, not auth.

## License

Apache-2.0 — Dawn Studio.
