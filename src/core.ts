import { LruCache } from "./cache.js"
import { resolveConfig, type NewtonAuthConfig, type ResolvedConfig } from "./config.js"
import {
  buildSessionCookieValue,
  buildStateCookieValue,
  deleteCookie,
  parseSessionCookieValue,
  parseStateCookieValue,
  setCookie,
} from "./cookies.js"
import { b64urlEncode, decryptCallbackAssertion, randomBytes } from "./crypto.js"
import { InvalidStateError, NewtonAuthError } from "./errors.js"
import { AuthHttpClient } from "./http-client.js"
import type {
  AuthCheckResponse,
  AuthRequestData,
  AuthResult,
  CallbackResult,
  CookieInstruction,
  LoginRedirect,
  SessionPayload,
} from "./models.js"

export class NewtonAuth {
  readonly config: ResolvedConfig
  private readonly httpClient: AuthHttpClient
  private readonly cache: LruCache

  constructor(cfg: NewtonAuthConfig) {
    this.config = resolveConfig(cfg)
    this.httpClient = new AuthHttpClient(this.config)
    this.cache = new LruCache(this.config.cacheMaxMb)
  }

  async authenticate(req: AuthRequestData): Promise<AuthResult> {
    const cookieValue = req.cookies[this.config.sessionCookieName]
    if (!cookieValue) {
      return emptyResult(false)
    }

    let session: SessionPayload
    try {
      session = await parseSessionCookieValue(cookieValue, this.config.sessionSigningSecret, this.config.clientId)
    } catch {
      return emptyResult(true)
    }

    const cached = this.cache.get(session.uid)
    if (cached) {
      return authCheckToResult(cached, session)
    }

    const authCheck = await this.httpClient.authCheck(session.uid, session.platform_token)
    this.cache.set(session.uid, authCheck)
    return authCheckToResult(authCheck, session)
  }

  async buildLoginRedirect(req: AuthRequestData, redirectUri?: string): Promise<LoginRedirect> {
    const state = b64urlEncode(randomBytes(24))
    const postLoginRedirect = redirectUri || currentPath(req)
    this.validateLoginRedirectTarget(postLoginRedirect)
    const stateCookieValue = await buildStateCookieValue(state, postLoginRedirect, this.config.sessionSigningSecret)

    const location = new URL(`${this.config.newtonApiBase}/platform-auth/login`)
    location.searchParams.set("client_id", this.config.clientId)
    location.searchParams.set("state", state)
    location.searchParams.set("redirect_uri", `${req.proto}://${req.host}${this.config.callbackPath}`)

    return {
      location: location.toString(),
      stateCookie: setCookie(this.config.stateCookieName, stateCookieValue, 300),
    }
  }

  async handleCallback(req: AuthRequestData): Promise<CallbackResult> {
    const stateParam = req.query["state"] ?? ""
    const identity = req.query["identity"] ?? ""

    const stateCookieValue = req.cookies[this.config.stateCookieName]
    if (!stateCookieValue) throw new InvalidStateError()
    const stateData = await parseStateCookieValue(stateCookieValue, this.config.sessionSigningSecret)
    if (!stateParam || stateParam !== stateData.state) throw new InvalidStateError()
    if (!isLocalPath(stateData.redirect_uri)) throw new InvalidStateError()

    const assertion = await decryptCallbackAssertion(
      identity,
      this.config.callbackSecret,
      this.config.clientId,
      this.config.issuer,
    )

    if (!assertion.authenticated) {
      // Login completed but there is no authenticated user (e.g. no Newton
      // account). Establish no session; let the app render an unauthenticated state.
      return {
        authenticated: false,
        redirectUri: stateData.redirect_uri,
        user: null,
        clientCacheTtlSeconds: assertion.client_cache_ttl_seconds,
        sessionTtlSeconds: assertion.session_ttl_seconds,
        sessionCookie: null,
        clearStateCookie: deleteCookie(this.config.stateCookieName),
      }
    }

    const sessionCookieValue = await buildSessionCookieValue(
      assertion.sub,
      assertion.platform_token,
      assertion.authorized,
      assertion.session_ttl_seconds,
      this.config.sessionSigningSecret,
      this.config.clientId,
    )

    this.cache.set(assertion.sub, {
      authenticated: assertion.authenticated,
      authorized: assertion.authorized,
      uid: assertion.sub,
      firstName: assertion.first_name ?? "",
      lastName: assertion.last_name ?? "",
      email: assertion.email ?? "",
      clientCacheTtlSeconds: assertion.client_cache_ttl_seconds,
      sessionTtlSeconds: assertion.session_ttl_seconds,
      shouldClearSession: false,
    })

    return {
      authenticated: true,
      redirectUri: stateData.redirect_uri,
      user: {
        uid: assertion.sub,
        authorized: assertion.authorized,
        firstName: assertion.first_name ?? "",
        lastName: assertion.last_name ?? "",
        email: assertion.email ?? "",
      },
      clientCacheTtlSeconds: assertion.client_cache_ttl_seconds,
      sessionTtlSeconds: assertion.session_ttl_seconds,
      sessionCookie: setCookie(this.config.sessionCookieName, sessionCookieValue, assertion.session_ttl_seconds),
      clearStateCookie: deleteCookie(this.config.stateCookieName),
    }
  }

  clearSessionCookies(): CookieInstruction[] {
    return [deleteCookie(this.config.sessionCookieName), deleteCookie(this.config.stateCookieName)]
  }

  /**
   * The post-login target must be a path on this app: it may not be the login
   * route itself (a loop) and may not point off-site (an open redirect).
   */
  validateLoginRedirectTarget(next: string): void {
    if (!isLocalPath(next) || next === this.config.loginPath) {
      throw new NewtonAuthError("invalid login redirect target")
    }
  }
}

// A same-origin absolute path: one leading "/", so no scheme, no
// protocol-relative "//host", and no "/\host" (which browsers read as "//host").
function isLocalPath(next: string): boolean {
  return next.startsWith("/") && !next.startsWith("//") && !next.startsWith("/\\")
}

function emptyResult(shouldClearSession: boolean): AuthResult {
  return {
    authenticated: false,
    authorized: false,
    shouldClearSession,
    user: null,
    clientCacheTtlSeconds: 0,
    sessionTtlSeconds: 0,
  }
}

function authCheckToResult(data: AuthCheckResponse, session: SessionPayload): AuthResult {
  return {
    authenticated: data.authenticated,
    authorized: data.authorized,
    shouldClearSession: data.shouldClearSession,
    clientCacheTtlSeconds: data.clientCacheTtlSeconds,
    sessionTtlSeconds: data.sessionTtlSeconds || session.session_ttl_seconds,
    user: data.authenticated
      ? {
          uid: session.uid,
          authorized: data.authorized,
          firstName: data.firstName,
          lastName: data.lastName,
          email: data.email,
        }
      : null,
  }
}

function currentPath(req: AuthRequestData): string {
  const qs = new URLSearchParams(req.query).toString()
  return qs ? `${req.path}?${qs}` : req.path
}
