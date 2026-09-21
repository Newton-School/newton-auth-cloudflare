import { describe, expect, it, vi } from "vitest"
import { buildSessionCookieValue, buildStateCookieValue } from "../src/cookies.js"
import { NewtonAuth } from "../src/core.js"
import { InvalidStateError } from "../src/errors.js"
import type { AuthRequestData } from "../src/models.js"
import {
  BASE,
  CALLBACK_SECRET,
  CLIENT_ID,
  CLIENT_SECRET,
  ISSUER,
  okCheckResponse,
  sealServerSide,
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

function req(overrides: Partial<AuthRequestData> = {}): AuthRequestData {
  return { path: "/protected", query: {}, cookies: {}, host: "app.example.com", proto: "https", ...overrides }
}

function sessionCookie(uid = "usr_1", ttl = 86400): Promise<string> {
  return buildSessionCookieValue(uid, "tok", true, ttl, CLIENT_SECRET, CLIENT_ID)
}

describe("authenticate", () => {
  it("returns unauthenticated without clearing when no cookie", async () => {
    const result = await makeAuth().authenticate(req())
    expect(result).toEqual({
      authenticated: false,
      authorized: false,
      shouldClearSession: false,
      user: null,
      clientCacheTtlSeconds: 0,
      sessionTtlSeconds: 0,
    })
  })

  it("flags shouldClearSession on unparseable cookie", async () => {
    const result = await makeAuth().authenticate(req({ cookies: { newton_session: "garbage" } }))
    expect(result.authenticated).toBe(false)
    expect(result.shouldClearSession).toBe(true)
  })

  it("checks with newton-api on cache miss and builds the user", async () => {
    const fetchMock = vi.fn(async () => okCheckResponse()) as unknown as typeof fetch
    const auth = makeAuth(fetchMock)
    const result = await auth.authenticate(req({ cookies: { newton_session: await sessionCookie() } }))
    expect(result.authenticated).toBe(true)
    expect(result.authorized).toBe(true)
    expect(result.user).toEqual({
      uid: "usr_1",
      authorized: true,
      firstName: "Ada",
      lastName: "Lovelace",
      email: "ada@example.com",
    })
    expect(fetchMock).toHaveBeenCalledTimes(1)
  })

  it("serves from cache on second call", async () => {
    const fetchMock = vi.fn(async () => okCheckResponse()) as unknown as typeof fetch
    const auth = makeAuth(fetchMock)
    const cookies = { newton_session: await sessionCookie() }
    await auth.authenticate(req({ cookies }))
    await auth.authenticate(req({ cookies }))
    expect(fetchMock).toHaveBeenCalledTimes(1)
  })

  it("maps auth-check 401 to unauthenticated + clear", async () => {
    const fetchMock = (async () => new Response("no", { status: 401 })) as typeof fetch
    const result = await makeAuth(fetchMock).authenticate(req({ cookies: { newton_session: await sessionCookie() } }))
    expect(result.authenticated).toBe(false)
    expect(result.shouldClearSession).toBe(true)
    expect(result.user).toBeNull()
  })

  it("keeps user but not authorized when authorized=false", async () => {
    const fetchMock = (async () => okCheckResponse({ authorized: false })) as typeof fetch
    const result = await makeAuth(fetchMock).authenticate(req({ cookies: { newton_session: await sessionCookie() } }))
    expect(result.authenticated).toBe(true)
    expect(result.authorized).toBe(false)
    expect(result.user?.authorized).toBe(false)
  })

  it("falls back to session ttl when server omits it", async () => {
    const fetchMock = (async () => okCheckResponse({ session_ttl_seconds: 0 })) as typeof fetch
    const result = await makeAuth(fetchMock).authenticate(
      req({ cookies: { newton_session: await sessionCookie("usr_1", 5555) } }),
    )
    expect(result.sessionTtlSeconds).toBe(5555)
  })
})

describe("buildLoginRedirect", () => {
  it("builds login URL with state cookie", async () => {
    const auth = makeAuth()
    const { location, stateCookie } = await auth.buildLoginRedirect(req(), "/protected?x=1")
    const url = new URL(location)
    expect(url.origin + url.pathname).toBe(`${BASE}/platform-auth/login`)
    expect(url.searchParams.get("client_id")).toBe(CLIENT_ID)
    expect(url.searchParams.get("redirect_uri")).toBe("https://app.example.com/newton/callback")
    const state = url.searchParams.get("state")!
    expect(state.length).toBeGreaterThanOrEqual(32)
    expect(stateCookie.name).toBe("newton_state")
    expect(stateCookie.maxAge).toBe(300)
    expect(stateCookie.value).toContain(".")
  })

  it("defaults redirect target to current path+query", async () => {
    const auth = makeAuth()
    const { location, stateCookie } = await auth.buildLoginRedirect(req({ path: "/p", query: { a: "1" } }))
    const state = new URL(location).searchParams.get("state")!
    const identity = sealServerSide(validAssertion(), CALLBACK_SECRET, CLIENT_ID)
    const result = await auth.handleCallback(
      req({ path: "/newton/callback", query: { state, identity }, cookies: { newton_state: stateCookie.value } }),
    )
    expect(result.redirectUri).toBe("/p?a=1")
  })
})

describe("handleCallback", () => {
  function callbackReq(state: string, identity: string, stateCookieValue: string): AuthRequestData {
    return req({
      path: "/newton/callback",
      query: { state, identity },
      cookies: { newton_state: stateCookieValue },
    })
  }

  it("completes the flow: session cookie, state cleared, redirect, cache seeded", async () => {
    const fetchMock = vi.fn(async () => okCheckResponse()) as unknown as typeof fetch
    const auth = makeAuth(fetchMock)
    const stateCookieValue = await buildStateCookieValue("st1", "/protected?x=1", CLIENT_SECRET)
    const identity = sealServerSide(validAssertion(), CALLBACK_SECRET, CLIENT_ID)

    const result = await auth.handleCallback(callbackReq("st1", identity, stateCookieValue))
    expect(result.authenticated).toBe(true)
    expect(result.redirectUri).toBe("/protected?x=1")
    expect(result.user!.uid).toBe("usr_1")
    expect(result.user!.firstName).toBe("Ada")
    expect(result.sessionCookie!.name).toBe("newton_session")
    expect(result.sessionCookie!.maxAge).toBe(86400)
    expect(result.clearStateCookie.maxAge).toBe(0)

    const authResult = await auth.authenticate(req({ cookies: { newton_session: result.sessionCookie!.value } }))
    expect(authResult.authenticated).toBe(true)
    expect(fetchMock).not.toHaveBeenCalled()
  })

  it("handles an authenticated=false assertion: no session, no user, state cleared", async () => {
    const fetchMock = vi.fn(async () => okCheckResponse()) as unknown as typeof fetch
    const auth = makeAuth(fetchMock)
    const stateCookieValue = await buildStateCookieValue("st1", "/protected", CLIENT_SECRET)
    const now = Math.floor(Date.now() / 1000)
    const unauth = {
      sub: "",
      aud: CLIENT_ID,
      iss: ISSUER,
      authenticated: false,
      authorized: false,
      client_cache_ttl_seconds: 60,
      session_ttl_seconds: 86400,
      platform_token: "",
      iat: now - 5,
      exp: now + 55,
    }
    const identity = sealServerSide(unauth, CALLBACK_SECRET, CLIENT_ID)

    const result = await auth.handleCallback(callbackReq("st1", identity, stateCookieValue))
    expect(result.authenticated).toBe(false)
    expect(result.user).toBeNull()
    expect(result.sessionCookie).toBeNull()
    expect(result.clearStateCookie.maxAge).toBe(0)
    expect(fetchMock).not.toHaveBeenCalled()
  })

  it("rejects state mismatch and missing state cookie", async () => {
    const auth = makeAuth()
    const stateCookieValue = await buildStateCookieValue("st1", "/p", CLIENT_SECRET)
    const identity = sealServerSide(validAssertion(), CALLBACK_SECRET, CLIENT_ID)
    await expect(auth.handleCallback(callbackReq("WRONG", identity, stateCookieValue))).rejects.toThrow(
      InvalidStateError,
    )
    await expect(
      auth.handleCallback(req({ path: "/newton/callback", query: { state: "st1", identity } })),
    ).rejects.toThrow(InvalidStateError)
  })
})

describe("clearSessionCookies / validateLoginRedirectTarget", () => {
  it("returns delete instructions for both cookies", () => {
    const cookies = makeAuth().clearSessionCookies()
    expect(cookies.map((c) => [c.name, c.maxAge])).toEqual([
      ["newton_session", 0],
      ["newton_state", 0],
    ])
  })

  it("rejects redirect target equal to login path", () => {
    const auth = makeAuth()
    expect(() => auth.validateLoginRedirectTarget("/newton/login")).toThrow("invalid login redirect target")
    expect(() => auth.validateLoginRedirectTarget("/anything-else")).not.toThrow()
  })

  it("rejects off-site redirect targets (open redirect)", async () => {
    const auth = makeAuth()
    for (const bad of ["https://evil.example.com/x", "//evil.example.com", "/\\evil.example.com", "evil"]) {
      expect(() => auth.validateLoginRedirectTarget(bad)).toThrow("invalid login redirect target")
      await expect(auth.buildLoginRedirect(req(), bad)).rejects.toThrow("invalid login redirect target")
    }
    expect(() => auth.validateLoginRedirectTarget("")).toThrow("invalid login redirect target")
    // An empty explicit target means "current path", which is always local.
    expect((await auth.buildLoginRedirect(req(), "")).stateCookie.value).toBeTruthy()
    expect(() => auth.validateLoginRedirectTarget("/reports/2026-09-20?x=1")).not.toThrow()
  })

  it("rejects an off-site target even from a validly signed state cookie", async () => {
    const auth = makeAuth()
    const stateCookieValue = await buildStateCookieValue("st1", "https://evil.example.com/", CLIENT_SECRET)
    const identity = sealServerSide(validAssertion(), CALLBACK_SECRET, CLIENT_ID)
    await expect(
      auth.handleCallback(
        req({ path: "/newton/callback", query: { state: "st1", identity }, cookies: { newton_state: stateCookieValue } }),
      ),
    ).rejects.toThrow(InvalidStateError)
  })
})
