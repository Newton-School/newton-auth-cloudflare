import { describe, expect, it } from "vitest"
import { createWorkerHandlers, redirectToLogin } from "../src/adapters/worker.js"
import { buildStateCookieValue } from "../src/cookies.js"
import { NewtonAuth } from "../src/core.js"
import {
  BASE,
  CALLBACK_SECRET,
  CLIENT_ID,
  CLIENT_SECRET,
  okCheckResponse,
  sealServerSide,
  setCookieMap,
  validAssertion,
} from "./helpers.js"

function makeAuth(fetchImpl?: typeof fetch) {
  return new NewtonAuth({
    clientId: CLIENT_ID,
    clientSecret: CLIENT_SECRET,
    callbackSecret: CALLBACK_SECRET,
    newtonApiBase: BASE,
    fetch: fetchImpl ?? ((async () => okCheckResponse()) as typeof fetch),
  })
}

function makeHandlers(fetchImpl?: typeof fetch) {
  return createWorkerHandlers(makeAuth(fetchImpl))
}

async function establishSession(
  handlers: ReturnType<typeof makeHandlers>,
  overrides: Record<string, unknown> = {},
): Promise<string> {
  const stateCookie = await buildStateCookieValue("st1", "/protected", CLIENT_SECRET)
  const identity = sealServerSide(validAssertion(overrides), CALLBACK_SECRET, CLIENT_ID)
  const res = await handlers.callbackGET(
    new Request(`https://app.example.com/newton/callback?state=st1&identity=${encodeURIComponent(identity)}`, {
      headers: { cookie: `newton_state=${stateCookie}` },
    }),
  )
  expect(res.status).toBe(302)
  return setCookieMap(res.headers.getSetCookie())["newton_session"]!.value
}

describe("worker adapter", () => {
  it("loginGET redirects with state cookie, deriving host from the request URL", async () => {
    const handlers = makeHandlers()
    const res = await handlers.loginGET(new Request("https://app.example.com/newton/login?next=/protected"))
    expect(res.status).toBe(302)
    const location = new URL(res.headers.get("location")!)
    expect(location.origin + location.pathname).toBe(`${BASE}/platform-auth/login`)
    expect(location.searchParams.get("redirect_uri")).toBe("https://app.example.com/newton/callback")
    expect(setCookieMap(res.headers.getSetCookie())["newton_state"]!.raw).toContain("Max-Age=300")
  })

  it("ignores x-forwarded headers unless told to trust them", async () => {
    const forwarded = new Request("https://app.example.com/newton/login?next=/p", {
      headers: { "x-forwarded-proto": "http", "x-forwarded-host": "evil.example.com" },
    })
    const ignored = await makeHandlers().loginGET(forwarded)
    expect(new URL(ignored.headers.get("location")!).searchParams.get("redirect_uri")).toBe(
      "https://app.example.com/newton/callback",
    )

    const trusting = createWorkerHandlers(makeAuth(), { trustForwardedHeaders: true })
    const honoured = await trusting.loginGET(forwarded)
    expect(new URL(honoured.headers.get("location")!).searchParams.get("redirect_uri")).toBe(
      "http://evil.example.com/newton/callback",
    )
  })

  it("loginGET rejects a next equal to the login path", async () => {
    const bad = await makeHandlers().loginGET(new Request("https://app.example.com/newton/login?next=/newton/login"))
    expect(bad.status).toBe(400)
  })

  it("callbackGET establishes the session and clears state cookie", async () => {
    const session = await establishSession(makeHandlers())
    expect(session.startsWith("v2.")).toBe(true)
  })

  it("callbackGET failure clears cookies and 400s", async () => {
    const res = await makeHandlers().callbackGET(
      new Request("https://app.example.com/newton/callback?state=st1&identity=garbage", {
        headers: { cookie: `newton_state=${await buildStateCookieValue("st1", "/p", CLIENT_SECRET)}` },
      }),
    )
    expect(res.status).toBe(400)
    expect(setCookieMap(res.headers.getSetCookie())["newton_session"]!.raw).toContain("Max-Age=0")
  })

  it("callbackGET answers 401 account_not_found for an authenticated=false assertion", async () => {
    const stateCookie = await buildStateCookieValue("st1", "/protected", CLIENT_SECRET)
    const identity = sealServerSide(
      validAssertion({ sub: "", platform_token: "", authenticated: false, authorized: false }),
      CALLBACK_SECRET,
      CLIENT_ID,
    )
    const res = await makeHandlers().callbackGET(
      new Request(`https://app.example.com/newton/callback?state=st1&identity=${encodeURIComponent(identity)}`, {
        headers: { cookie: `newton_state=${stateCookie}` },
      }),
    )
    expect(res.status).toBe(401)
    expect(await res.text()).toBe("account_not_found")
  })

  it("handleAuthRoutes dispatches only the login and callback paths", async () => {
    const handlers = makeHandlers()
    expect(await handlers.handleAuthRoutes(new Request("https://app.example.com/index.html"))).toBeNull()
    const login = await handlers.handleAuthRoutes(new Request("https://app.example.com/newton/login"))
    expect(login?.status).toBe(302)
    const post = await handlers.handleAuthRoutes(new Request("https://app.example.com/newton/login", { method: "POST" }))
    expect(post?.status).toBe(405)
    const callback = await handlers.handleAuthRoutes(new Request("https://app.example.com/newton/callback"))
    expect(callback?.status).toBe(400)
  })

  it("withAuth: 401 without session, 403 unauthorized, 200 with user", async () => {
    const handlers = makeHandlers()
    const protectedRoute = handlers.withAuth(async (_req, user) => Response.json(user))

    expect((await protectedRoute(new Request("https://app.example.com/protected"))).status).toBe(401)

    const session = await establishSession(handlers)
    const ok = await protectedRoute(
      new Request("https://app.example.com/protected", { headers: { cookie: `newton_session=${session}` } }),
    )
    expect(ok.status).toBe(200)
    expect(await ok.json()).toEqual({
      uid: "usr_1",
      authorized: true,
      firstName: "Ada",
      lastName: "Lovelace",
      email: "ada@example.com",
    })

    const handlers403 = makeHandlers((async () => okCheckResponse({ authorized: false })) as typeof fetch)
    const session403 = await establishSession(handlers403, { authorized: false, client_cache_ttl_seconds: 0 })
    const route403 = handlers403.withAuth(async (_req, user) => Response.json(user))
    const res403 = await route403(
      new Request("https://app.example.com/protected", { headers: { cookie: `newton_session=${session403}` } }),
    )
    expect(res403.status).toBe(403)
  })

  it("authenticatedOnly lets an unauthorized user through but still blocks unauthenticated", async () => {
    const handlers = makeHandlers((async () => okCheckResponse({ authorized: false })) as typeof fetch)
    const route = handlers.withAuth(async (_req, user) => Response.json(user), { authenticatedOnly: true })

    expect((await route(new Request("https://app.example.com/protected"))).status).toBe(401)

    const session = await establishSession(handlers, { authorized: false, client_cache_ttl_seconds: 0 })
    const res = await route(
      new Request("https://app.example.com/protected", { headers: { cookie: `newton_session=${session}` } }),
    )
    expect(res.status).toBe(200)
    expect(((await res.json()) as { authorized: boolean }).authorized).toBe(false)
  })

  it("withAuth clears a stale session cookie on 401 and honours onUnauthenticated", async () => {
    const handlers = makeHandlers()
    const stale = new Request("https://app.example.com/protected", { headers: { cookie: "newton_session=garbage" } })
    const res = await handlers.withAuth(async () => new Response("ok"))(stale)
    expect(res.status).toBe(401)
    expect(setCookieMap(res.headers.getSetCookie())["newton_session"]!.raw).toContain("Max-Age=0")

    const auth = makeAuth()
    const redirecting = createWorkerHandlers(auth).withAuth(async () => new Response("ok"), {
      onUnauthenticated: (request, result) => redirectToLogin(auth, request, result),
    })
    const redirected = await redirecting(new Request("https://app.example.com/reports/2026-09-20?x=1"))
    expect(redirected.status).toBe(302)
    expect(redirected.headers.get("location")).toBe("/newton/login?next=%2Freports%2F2026-09-20%3Fx%3D1")
  })
})
