import { parseCookieHeader, serializeCookie } from "../cookies.js"
import type { NewtonAuth } from "../core.js"
import type { AuthRequestData, AuthResult, CookieInstruction, NewtonUser } from "../models.js"

export interface WorkerHandlerOptions {
  onUnauthenticated?: (request: Request, result: AuthResult) => Response | Promise<Response>
  onUnauthorized?: (request: Request, result: AuthResult) => Response | Promise<Response>
  /**
   * Gate on authentication alone. When true, an authenticated but unauthorized
   * user is allowed through instead of being rejected with 403, for apps that
   * manage their own authorization. Unauthenticated users are still rejected with 401.
   */
  authenticatedOnly?: boolean
}

export interface WorkerAdapterOptions {
  /**
   * Derive host and scheme from X-Forwarded-Host / X-Forwarded-Proto instead of
   * the request URL. Off by default: a Worker sees the real inbound URL, and a
   * client can send those headers itself. Turn on only behind a proxy you control.
   */
  trustForwardedHeaders?: boolean
}

function firstForwardedValue(header: string | null): string {
  return header ? (header.split(",")[0] ?? "").trim() : ""
}

export function requestDataFromWebRequest(request: Request, opts: WorkerAdapterOptions = {}): AuthRequestData {
  const url = new URL(request.url)
  const query: Record<string, string> = {}
  url.searchParams.forEach((value, key) => {
    query[key] = value
  })
  const forwardedHost = opts.trustForwardedHeaders ? firstForwardedValue(request.headers.get("x-forwarded-host")) : ""
  const forwardedProto = opts.trustForwardedHeaders ? firstForwardedValue(request.headers.get("x-forwarded-proto")) : ""
  return {
    path: url.pathname,
    query,
    cookies: parseCookieHeader(request.headers.get("cookie")),
    host: forwardedHost || url.host,
    proto: forwardedProto || url.protocol.replace(":", ""),
  }
}

export function withCookies(response: Response, cookies: CookieInstruction[]): Response {
  for (const cookie of cookies) {
    response.headers.append("set-cookie", serializeCookie(cookie))
  }
  return response
}

function redirect(location: string, cookies: CookieInstruction[]): Response {
  return withCookies(new Response(null, { status: 302, headers: { location } }), cookies)
}

function text(status: number, message: string, cookies: CookieInstruction[] = []): Response {
  return withCookies(
    new Response(message, { status, headers: { "content-type": "text/plain; charset=utf-8" } }),
    cookies,
  )
}

/**
 * A 302 to the SDK's login route that returns the user to the page they asked for.
 * Use it as `onUnauthenticated` for browser navigations; keep the 401 default for APIs and assets.
 */
export function redirectToLogin(auth: NewtonAuth, request: Request, result?: AuthResult): Response {
  const url = new URL(request.url)
  const next = url.pathname === auth.config.loginPath ? "/" : `${url.pathname}${url.search}`
  const location = `${auth.config.loginPath}?next=${encodeURIComponent(next)}`
  return redirect(location, result?.shouldClearSession ? auth.clearSessionCookies() : [])
}

export function createWorkerHandlers(auth: NewtonAuth, adapterOpts: WorkerAdapterOptions = {}) {
  const requestData = (request: Request) => requestDataFromWebRequest(request, adapterOpts)

  const loginGET = async (request: Request): Promise<Response> => {
    const data = requestData(request)
    const next = data.query["next"] || "/"
    try {
      auth.validateLoginRedirectTarget(next)
    } catch (err) {
      return text(400, err instanceof Error ? err.message : "invalid login redirect target")
    }
    try {
      const { location, stateCookie } = await auth.buildLoginRedirect(data, next)
      return redirect(location, [stateCookie])
    } catch {
      return text(500, "failed to start login")
    }
  }

  const callbackGET = async (request: Request): Promise<Response> => {
    try {
      const result = await auth.handleCallback(requestData(request))
      if (!result.authenticated) {
        return text(401, "account_not_found", [result.clearStateCookie, ...auth.clearSessionCookies()])
      }
      return redirect(result.redirectUri, [result.sessionCookie!, result.clearStateCookie])
    } catch {
      return text(400, "invalid auth callback", auth.clearSessionCookies())
    }
  }

  /** Answers the SDK's own login and callback routes; returns null for every other request. */
  const handleAuthRoutes = async (request: Request): Promise<Response | null> => {
    const { pathname } = new URL(request.url)
    if (pathname !== auth.config.loginPath && pathname !== auth.config.callbackPath) return null
    if (request.method !== "GET") return text(405, "Method Not Allowed")
    return pathname === auth.config.loginPath ? loginGET(request) : callbackGET(request)
  }

  const authenticate = (request: Request): Promise<AuthResult> => auth.authenticate(requestData(request))

  const withAuth = (
    handler: (request: Request, user: NewtonUser) => Response | Promise<Response>,
    opts: WorkerHandlerOptions = {},
  ) => {
    return async (request: Request): Promise<Response> => {
      let result: AuthResult
      try {
        result = await authenticate(request)
      } catch {
        return text(500, "authentication failed")
      }
      if (!result.authenticated) {
        if (opts.onUnauthenticated) return opts.onUnauthenticated(request, result)
        return text(401, "authentication required", result.shouldClearSession ? auth.clearSessionCookies() : [])
      }
      if (!result.authorized && !opts.authenticatedOnly) {
        if (opts.onUnauthorized) return opts.onUnauthorized(request, result)
        return text(403, "forbidden", result.shouldClearSession ? auth.clearSessionCookies() : [])
      }
      return handler(request, result.user!)
    }
  }

  return { auth, loginGET, callbackGET, handleAuthRoutes, authenticate, withAuth }
}
