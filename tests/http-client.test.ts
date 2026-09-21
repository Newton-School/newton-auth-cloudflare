import { describe, expect, it, vi } from "vitest"
import { resolveConfig } from "../src/config.js"
import { NewtonAuthError } from "../src/errors.js"
import { AuthHttpClient } from "../src/http-client.js"
import { BASE, CALLBACK_SECRET, CLIENT_ID, CLIENT_SECRET, okCheckResponse } from "./helpers.js"

function client(fetchImpl: typeof fetch) {
  return new AuthHttpClient(
    resolveConfig({
      clientId: CLIENT_ID,
      clientSecret: CLIENT_SECRET,
      callbackSecret: CALLBACK_SECRET,
      newtonApiBase: BASE,
      fetch: fetchImpl,
    }),
  )
}

describe("AuthHttpClient.authCheck", () => {
  it("posts uid + token with Basic auth to the auth-check endpoint", async () => {
    const fetchMock = vi.fn(async () => okCheckResponse())
    const result = await client(fetchMock as unknown as typeof fetch).authCheck("usr_1", "tok")
    expect(result.authenticated).toBe(true)
    expect(result.firstName).toBe("Ada")

    const [url, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit]
    expect(url).toBe(`${BASE}/platform-auth/auth/check/`)
    expect(init.method).toBe("POST")
    expect((init.headers as Record<string, string>)["Authorization"]).toBe(
      "Basic " + Buffer.from(`${CLIENT_ID}:${CLIENT_SECRET}`, "utf8").toString("base64"),
    )
    expect(JSON.parse(init.body as string)).toEqual({ uid: "usr_1", platform_token: "tok" })
  })

  it("maps 401 to unauthenticated + shouldClearSession", async () => {
    const result = await client((async () => new Response("", { status: 401 })) as typeof fetch).authCheck("u", "t")
    expect(result).toMatchObject({ authenticated: false, authorized: false, uid: "u", shouldClearSession: true })
  })

  it("throws on other non-2xx statuses", async () => {
    await expect(
      client((async () => new Response("", { status: 503 })) as typeof fetch).authCheck("u", "t"),
    ).rejects.toThrow(NewtonAuthError)
  })

  it("defaults missing wire fields", async () => {
    const result = await client(
      (async () => new Response(JSON.stringify({ authenticated: true }), { status: 200 })) as typeof fetch,
    ).authCheck("u", "t")
    expect(result).toEqual({
      authenticated: true,
      authorized: false,
      uid: "",
      firstName: "",
      lastName: "",
      email: "",
      clientCacheTtlSeconds: 0,
      sessionTtlSeconds: 0,
      shouldClearSession: false,
    })
  })
})
