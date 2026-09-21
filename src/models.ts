export interface NewtonUser {
  uid: string
  authorized: boolean
  firstName: string
  lastName: string
  email: string
}

export interface AuthResult {
  authenticated: boolean
  authorized: boolean
  shouldClearSession: boolean
  user: NewtonUser | null
  clientCacheTtlSeconds: number
  sessionTtlSeconds: number
}

/** A cookie to set (or delete when maxAge <= 0). Always Path=/; HttpOnly; Secure; SameSite=Lax. */
export interface CookieInstruction {
  name: string
  value: string
  maxAge: number
}

/** Framework-agnostic request data, derived from the Worker's inbound Request. */
export interface AuthRequestData {
  path: string
  query: Record<string, string>
  cookies: Record<string, string>
  host: string
  proto: string
}

export interface LoginRedirect {
  location: string
  stateCookie: CookieInstruction
}

export interface CallbackResult {
  /** False when the login completed but the user is not authenticated (e.g. no Newton account). */
  authenticated: boolean
  redirectUri: string
  /** Null when not authenticated. */
  user: NewtonUser | null
  clientCacheTtlSeconds: number
  sessionTtlSeconds: number
  /** Null when not authenticated (no session is established). */
  sessionCookie: CookieInstruction | null
  clearStateCookie: CookieInstruction
}

export interface AuthCheckResponse {
  authenticated: boolean
  authorized: boolean
  uid: string
  firstName: string
  lastName: string
  email: string
  clientCacheTtlSeconds: number
  sessionTtlSeconds: number
  shouldClearSession: boolean
}

export interface SessionPayload {
  uid: string
  platform_token: string
  authorized: boolean
  session_ttl_seconds: number
  issued_at: number
  nonce: string
}

export interface StatePayload {
  state: string
  redirect_uri: string
  exp: number
}

export interface CallbackAssertion {
  sub: string
  aud: string
  iss: string
  authenticated: boolean
  authorized: boolean
  client_cache_ttl_seconds: number
  session_ttl_seconds: number
  platform_token: string
  first_name?: string
  last_name?: string
  email?: string
  iat: number
  exp: number
  nonce?: string
}
