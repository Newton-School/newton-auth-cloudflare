import { describe, expect, it } from "vitest"
import {
  buildSessionCookieValue,
  buildStateCookieValue,
  deleteCookie,
  parseCookieHeader,
  parseSessionCookieValue,
  parseStateCookieValue,
  serializeCookie,
  setCookie,
} from "../src/cookies.js"
import { InvalidSessionError, InvalidStateError } from "../src/errors.js"

const SECRET = "signing-secret"
const CLIENT_ID = "app_client_id"
const NOW = 1_710_000_000

describe("state cookie", () => {
  it("round-trips", async () => {
    const value = await buildStateCookieValue("st123", "/protected?x=1", SECRET, NOW)
    const payload = await parseStateCookieValue(value, SECRET, NOW + 100)
    expect(payload).toEqual({ state: "st123", redirect_uri: "/protected?x=1", exp: NOW + 300 })
  })

  it("rejects expired state", async () => {
    const value = await buildStateCookieValue("st123", "/p", SECRET, NOW)
    await expect(parseStateCookieValue(value, SECRET, NOW + 301)).rejects.toThrow(InvalidStateError)
  })

  it("rejects tampered signature", async () => {
    const value = await buildStateCookieValue("st123", "/p", SECRET, NOW)
    await expect(parseStateCookieValue(value.slice(0, -2) + "ff", SECRET, NOW)).rejects.toThrow(InvalidStateError)
    await expect(parseStateCookieValue(value, "other-secret", NOW)).rejects.toThrow(InvalidStateError)
  })
})

describe("session cookie", () => {
  it("round-trips snake_case payload", async () => {
    const value = await buildSessionCookieValue("usr_1", "tok", true, 86400, SECRET, CLIENT_ID, NOW)
    const payload = await parseSessionCookieValue(value, SECRET, CLIENT_ID, NOW + 10)
    expect(payload.uid).toBe("usr_1")
    expect(payload.platform_token).toBe("tok")
    expect(payload.authorized).toBe(true)
    expect(payload.session_ttl_seconds).toBe(86400)
    expect(payload.issued_at).toBe(NOW)
    expect(payload.nonce).toBeTruthy()
  })

  it("rejects expired session", async () => {
    const value = await buildSessionCookieValue("usr_1", "tok", true, 100, SECRET, CLIENT_ID, NOW)
    await expect(parseSessionCookieValue(value, SECRET, CLIENT_ID, NOW + 101)).rejects.toThrow(InvalidSessionError)
  })

  it("rejects non-positive ttl and empty uid/token", async () => {
    const zeroTtl = await buildSessionCookieValue("usr_1", "tok", true, 0, SECRET, CLIENT_ID, NOW)
    await expect(parseSessionCookieValue(zeroTtl, SECRET, CLIENT_ID, NOW)).rejects.toThrow(InvalidSessionError)
    const noUid = await buildSessionCookieValue("", "tok", true, 100, SECRET, CLIENT_ID, NOW)
    await expect(parseSessionCookieValue(noUid, SECRET, CLIENT_ID, NOW)).rejects.toThrow(InvalidSessionError)
    const noTok = await buildSessionCookieValue("usr_1", "", true, 100, SECRET, CLIENT_ID, NOW)
    await expect(parseSessionCookieValue(noTok, SECRET, CLIENT_ID, NOW)).rejects.toThrow(InvalidSessionError)
  })

  it("rejects wrong client id (AAD mismatch) and tamper", async () => {
    const value = await buildSessionCookieValue("usr_1", "tok", true, 100, SECRET, CLIENT_ID, NOW)
    await expect(parseSessionCookieValue(value, SECRET, "other_client", NOW)).rejects.toThrow(InvalidSessionError)
    await expect(parseSessionCookieValue("v2.garbage", SECRET, CLIENT_ID, NOW)).rejects.toThrow(InvalidSessionError)
    await expect(parseSessionCookieValue("", SECRET, CLIENT_ID, NOW)).rejects.toThrow(InvalidSessionError)
  })
})

describe("cookie instructions", () => {
  it("serializes set-cookies with hardened attributes", () => {
    expect(serializeCookie(setCookie("newton_session", "abc", 86400))).toBe(
      "newton_session=abc; Path=/; Max-Age=86400; HttpOnly; Secure; SameSite=Lax",
    )
  })

  it("serializes deletions with epoch expiry", () => {
    expect(serializeCookie(deleteCookie("newton_state"))).toBe(
      "newton_state=; Path=/; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; Secure; SameSite=Lax",
    )
  })
})

describe("parseCookieHeader", () => {
  it("parses standard headers", () => {
    expect(parseCookieHeader("a=1; b=2")).toEqual({ a: "1", b: "2" })
    expect(parseCookieHeader("a=x=y; b=2")).toEqual({ a: "x=y", b: "2" })
    expect(parseCookieHeader(undefined)).toEqual({})
    expect(parseCookieHeader(null)).toEqual({})
    expect(parseCookieHeader("")).toEqual({})
    expect(parseCookieHeader("bare; a=1")).toEqual({ a: "1" })
  })
})
