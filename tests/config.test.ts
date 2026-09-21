import { describe, expect, it } from "vitest"
import { resolveConfig } from "../src/config.js"
import { ConfigError } from "../src/errors.js"

const base = {
  clientId: "cid",
  clientSecret: "csecret",
  callbackSecret: "cbsecret",
  newtonApiBase: "https://auth.newtonschool.co/api/v1",
}

describe("resolveConfig", () => {
  it("applies defaults", () => {
    const cfg = resolveConfig(base)
    expect(cfg.loginPath).toBe("/newton/login")
    expect(cfg.callbackPath).toBe("/newton/callback")
    expect(cfg.sessionCookieName).toBe("newton_session")
    expect(cfg.stateCookieName).toBe("newton_state")
    expect(cfg.cacheMaxMb).toBe(1)
    expect(cfg.authTimeoutMs).toBe(10_000)
    expect(cfg.sessionSigningSecret).toBe("csecret")
    expect(cfg.issuer).toBe("https://auth.newtonschool.co")
    expect(cfg.fetch).toBe(globalThis.fetch)
  })

  it("strips trailing slash from newtonApiBase", () => {
    const cfg = resolveConfig({ ...base, newtonApiBase: "https://auth.newtonschool.co/api/v1///" })
    expect(cfg.newtonApiBase).toBe("https://auth.newtonschool.co/api/v1")
  })

  it("honors explicit overrides", () => {
    const myFetch = (() => Promise.reject(new Error("x"))) as unknown as typeof fetch
    const cfg = resolveConfig({
      ...base,
      sessionSigningSecret: "other",
      loginPath: "/auth/login",
      callbackPath: "/auth/cb",
      sessionCookieName: "sess",
      stateCookieName: "st",
      cacheMaxMb: 0,
      authTimeoutMs: 500,
      fetch: myFetch,
    })
    expect(cfg.sessionSigningSecret).toBe("other")
    expect(cfg.loginPath).toBe("/auth/login")
    expect(cfg.cacheMaxMb).toBe(0)
    expect(cfg.authTimeoutMs).toBe(500)
    expect(cfg.fetch).toBe(myFetch)
  })

  it("rejects missing required fields", () => {
    expect(() => resolveConfig({ ...base, clientId: "" })).toThrow(ConfigError)
    expect(() => resolveConfig({ ...base, clientSecret: "" })).toThrow(ConfigError)
    expect(() => resolveConfig({ ...base, callbackSecret: "" })).toThrow(ConfigError)
    expect(() => resolveConfig({ ...base, newtonApiBase: "" })).toThrow(ConfigError)
  })

  it("rejects invalid paths and numbers", () => {
    expect(() => resolveConfig({ ...base, loginPath: "login" })).toThrow(ConfigError)
    expect(() => resolveConfig({ ...base, callbackPath: "cb" })).toThrow(ConfigError)
    expect(() => resolveConfig({ ...base, cacheMaxMb: -1 })).toThrow(ConfigError)
    expect(() => resolveConfig({ ...base, authTimeoutMs: 0 })).toThrow(ConfigError)
    expect(() => resolveConfig({ ...base, newtonApiBase: "not a url" })).toThrow(ConfigError)
  })
})
