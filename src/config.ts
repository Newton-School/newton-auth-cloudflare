import { deriveIssuerFromBaseUrl } from "./crypto.js"
import { ConfigError } from "./errors.js"

export interface NewtonAuthConfig {
  clientId: string
  clientSecret: string
  callbackSecret: string
  newtonApiBase: string
  sessionSigningSecret?: string
  loginPath?: string
  callbackPath?: string
  sessionCookieName?: string
  stateCookieName?: string
  cacheMaxMb?: number
  authTimeoutMs?: number
  fetch?: typeof fetch
}

export interface ResolvedConfig {
  clientId: string
  clientSecret: string
  callbackSecret: string
  newtonApiBase: string
  sessionSigningSecret: string
  loginPath: string
  callbackPath: string
  sessionCookieName: string
  stateCookieName: string
  cacheMaxMb: number
  authTimeoutMs: number
  fetch: typeof fetch
  issuer: string
}

export function resolveConfig(cfg: NewtonAuthConfig): ResolvedConfig {
  const resolved: ResolvedConfig = {
    clientId: cfg.clientId,
    clientSecret: cfg.clientSecret,
    callbackSecret: cfg.callbackSecret,
    newtonApiBase: (cfg.newtonApiBase ?? "").replace(/\/+$/, ""),
    sessionSigningSecret: cfg.sessionSigningSecret || cfg.clientSecret,
    loginPath: cfg.loginPath ?? "/newton/login",
    callbackPath: cfg.callbackPath ?? "/newton/callback",
    sessionCookieName: cfg.sessionCookieName ?? "newton_session",
    stateCookieName: cfg.stateCookieName ?? "newton_state",
    cacheMaxMb: cfg.cacheMaxMb ?? 1,
    authTimeoutMs: cfg.authTimeoutMs ?? 10_000,
    fetch: cfg.fetch ?? globalThis.fetch,
    issuer: "",
  }

  if (!resolved.clientId) throw new ConfigError("client id is required")
  if (!resolved.clientSecret) throw new ConfigError("client secret is required")
  if (!resolved.callbackSecret) throw new ConfigError("callback secret is required")
  if (!resolved.newtonApiBase) throw new ConfigError("newton api base is required")
  if (!resolved.loginPath.startsWith("/")) throw new ConfigError("login path must start with /")
  if (!resolved.callbackPath.startsWith("/")) throw new ConfigError("callback path must start with /")
  if (resolved.cacheMaxMb < 0) throw new ConfigError("cache max mb must be >= 0")
  if (resolved.authTimeoutMs <= 0) throw new ConfigError("auth timeout must be > 0")

  resolved.issuer = deriveIssuerFromBaseUrl(resolved.newtonApiBase)
  return resolved
}
