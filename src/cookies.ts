import {
  b64urlEncode,
  decryptValue,
  encryptValue,
  randomBytes,
  signValue,
  utf8Encode,
  verifySignedValue,
} from "./crypto.js"
import { InvalidSessionError, InvalidStateError } from "./errors.js"
import type { CookieInstruction, SessionPayload, StatePayload } from "./models.js"

const STATE_COOKIE_TTL_SECONDS = 300

function nowSeconds(): number {
  return Math.floor(Date.now() / 1000)
}

export async function buildStateCookieValue(
  state: string,
  redirectUri: string,
  secret: string,
  nowSec: number = nowSeconds(),
): Promise<string> {
  const payload: StatePayload = { state, redirect_uri: redirectUri, exp: nowSec + STATE_COOKIE_TTL_SECONDS }
  return signValue(payload, secret)
}

export async function parseStateCookieValue(
  value: string,
  secret: string,
  nowSec: number = nowSeconds(),
): Promise<StatePayload> {
  let payload: StatePayload
  try {
    payload = await verifySignedValue<StatePayload>(value, secret)
  } catch {
    throw new InvalidStateError()
  }
  if (nowSec > payload.exp) throw new InvalidStateError()
  return payload
}

export async function buildSessionCookieValue(
  uid: string,
  platformToken: string,
  authorized: boolean,
  sessionTtlSeconds: number,
  secret: string,
  clientId: string,
  nowSec: number = nowSeconds(),
): Promise<string> {
  const payload: SessionPayload = {
    uid,
    platform_token: platformToken,
    authorized,
    session_ttl_seconds: sessionTtlSeconds,
    issued_at: nowSec,
    nonce: b64urlEncode(randomBytes(16)),
  }
  return encryptValue(payload, secret, utf8Encode(clientId))
}

export async function parseSessionCookieValue(
  value: string,
  secret: string,
  clientId: string,
  nowSec: number = nowSeconds(),
): Promise<SessionPayload> {
  const payload = await decryptValue<SessionPayload>(value, secret, utf8Encode(clientId))
  if (payload.session_ttl_seconds <= 0 || nowSec > payload.issued_at + payload.session_ttl_seconds) {
    throw new InvalidSessionError()
  }
  if (!payload.uid || !payload.platform_token) throw new InvalidSessionError()
  return payload
}

export function setCookie(name: string, value: string, maxAge: number): CookieInstruction {
  return { name, value, maxAge }
}

export function deleteCookie(name: string): CookieInstruction {
  return { name, value: "", maxAge: 0 }
}

export function serializeCookie(cookie: CookieInstruction): string {
  const parts = [`${cookie.name}=${cookie.value}`, "Path=/", `Max-Age=${Math.max(cookie.maxAge, 0)}`]
  if (cookie.maxAge <= 0) parts.push("Expires=Thu, 01 Jan 1970 00:00:00 GMT")
  parts.push("HttpOnly", "Secure", "SameSite=Lax")
  return parts.join("; ")
}

export function parseCookieHeader(header: string | null | undefined): Record<string, string> {
  const cookies: Record<string, string> = {}
  if (!header) return cookies
  for (const part of header.split(";")) {
    const eq = part.indexOf("=")
    if (eq < 0) continue
    const name = part.slice(0, eq).trim()
    if (!name) continue
    cookies[name] = part.slice(eq + 1).trim()
  }
  return cookies
}
