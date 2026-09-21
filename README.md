# newton-auth-cloudflare

Newton School authentication SDK for Cloudflare Workers.

It is the Worker-runtime port of [`newton-auth-nodejs`](https://github.com/Newton-School/newton-auth-nodejs): the same login flow, the same cookies and the same wire format as the Node, [Python](https://github.com/Newton-School/newton-auth-python) and [Go](https://github.com/Newton-School/newton-auth-golang) SDKs, built on WebCrypto instead of `node:crypto` so it runs at the edge with zero dependencies. It owns:

- `/newton/login` to start the Newton login redirect flow
- `/newton/callback` to complete the callback flow

Protected routes stay explicit. They return `401` (unauthenticated) or `403` (unauthorized) by default, and you can swap in a redirect to login for browser navigations.

The SDK holds the app's `client_secret` and `callback_secret` and sets `HttpOnly` cookies, so it belongs in a Worker, never in browser code.

## Installation

Install from a Git tag so consumers get an immutable version instead of a moving branch head.

```bash
npm install github:Newton-School/newton-auth-cloudflare#v0.1.0
```

The package builds itself on install via the `prepare` script. ESM only. Requires Node `>=20` to build and test; at runtime any current Workers `compatibility_date` works.

## Usage

```js
import { NewtonAuth, createWorkerHandlers, redirectToLogin } from "newton-auth-cloudflare"

let handlers

export default {
  async fetch(request, env) {
    handlers ??= createWorkerHandlers(
      new NewtonAuth({
        clientId: env.NEWTON_AUTH_CLIENT_ID,
        clientSecret: env.NEWTON_AUTH_CLIENT_SECRET,
        callbackSecret: env.NEWTON_AUTH_CALLBACK_SECRET,
        newtonApiBase: env.NEWTON_AUTH_BASE_URL ?? "https://my.newtonschool.co/api/v1",
      }),
    )

    // GET /newton/login and GET /newton/callback
    const authResponse = await handlers.handleAuthRoutes(request)
    if (authResponse) return authResponse

    // Everything else requires an authorized Newton user.
    const protectedFetch = handlers.withAuth(
      (request, user) => Response.json({ uid: user.uid, email: user.email }),
      { onUnauthenticated: (request, result) => redirectToLogin(handlers.auth, request, result) },
    )
    return protectedFetch(request)
  },
}
```

Put the three secrets in the Worker with `wrangler secret put`, never in `wrangler.toml` vars.

To start login, the browser navigates to:

```text
/newton/login?next=/protected
```

After a successful callback the SDK sets a `newton_session` cookie and redirects to the original `next` path.

### Handlers

`createWorkerHandlers(auth, options)` returns:

- `handleAuthRoutes(request)`: answers the login and callback paths (GET only, `405` otherwise); returns `null` for every other request so your router keeps going.
- `loginGET(request)` and `callbackGET(request)`: the two routes individually, for routers that dispatch by path themselves.
- `withAuth(handler, options)`: wraps `(request, user) => Response`. Rejects with `401` or `403`, or calls `onUnauthenticated` / `onUnauthorized` when given.
- `authenticate(request)`: the raw `AuthResult` when you want to decide yourself.

`redirectToLogin(auth, request, result)` builds the `302` to `/newton/login?next=<current path>` and clears a stale session cookie when the result says so. Use it as `onUnauthenticated` for HTML navigations; keep the `401` default for JSON and assets.

### Options

`createWorkerHandlers(auth, { trustForwardedHeaders: true })` derives host and scheme from `X-Forwarded-Host` / `X-Forwarded-Proto` like the Node SDK does. It is **off by default** here: a Worker already sees the real inbound URL, and a client can send those headers itself. Turn it on only when a proxy you control sits in front of the Worker.

`NewtonAuth` accepts the same config as the Node SDK: `loginPath`, `callbackPath`, `sessionCookieName`, `stateCookieName`, `sessionSigningSecret`, `cacheMaxMb`, `authTimeoutMs`, `fetch`.

## User fields

The authenticated user carries:

- `uid`: opaque user identifier
- `authorized`: whether the user is authorized for this app
- `firstName`, `lastName`, `email`: strings (empty `""` if unset on the Newton profile, never `null`/`undefined`)

Profile fields refresh every `clientCacheTtlSeconds` (default 60s) via the auth-check call to newton-api. The cache lives in isolate memory, so it is shared by the requests one isolate serves and dropped when the isolate is recycled. It only saves round-trips; nothing depends on a hit.

## Unauthenticated callbacks (no Newton account)

If a user completes Google login but has no Newton account, newton-api returns a signed `authenticated=false` assertion. The SDK establishes no session for it; `callbackGET` responds `401 account_not_found` and clears the state cookie. `handleCallback` surfaces this as `result.authenticated === false` with `user` and `sessionCookie` both `null`.

## Authentication-only mode

The guard rejects an authenticated-but-unauthorized user with `403`. If your app manages its own authorization and only needs Newton to identify the user, pass `authenticatedOnly: true` to `withAuth` so unauthorized users are let through (unauthenticated users are still rejected with `401`). This pairs with binding the Newton OAuth application without a `required_permission`, in which case `authorized` is already `true` for every authenticated user.

## Callback URL contract

The callback path is configurable, but it must exactly match the redirect URI registered for the Newton OAuth application in newton-api. The backend validates `redirect_uri` strictly. The SDK derives it from the inbound request URL: `https://<host>/newton/callback`.

## Differences from newton-auth-nodejs

- Every method that touches a cookie or an assertion is `async` (WebCrypto is promise-based): `buildLoginRedirect`, `handleCallback`, `authenticate`, and the cookie builders and parsers.
- `X-Forwarded-*` headers are ignored unless `trustForwardedHeaders` is set.
- One adapter, for the Worker `fetch` handler. No Express, Fastify or `node:http` adapters.
- ESM only.

The wire format is identical, which is what the checks below prove.

## Wire compatibility

- `tests/vectors.test.ts` decrypts **frozen wire vectors generated by the real Python SDK**, the same fixture file the Node SDK tests against, on every test run.
- `scripts/wire-compat-check.mjs` generates fresh assertions and cookies with a local `newton-auth-python` checkout, parses them here, and round-trips a Worker-built session cookie back through Python.
- `scripts/node-sdk-compat-check.mjs` exchanges state and session cookies with a built local `newton-auth-nodejs` checkout in both directions.

```bash
npm run build
node scripts/wire-compat-check.mjs ../newton-auth-python python3
node scripts/node-sdk-compat-check.mjs ../newton-auth-nodejs
```

## Development

```bash
npm install
npm test          # vitest
npm run typecheck # tsc --noEmit
npm run build     # tsup -> dist/ (esm + d.ts)
```

## Release process

This repository uses semantic versioning and Git tags. See [RELEASING.md](./RELEASING.md).
