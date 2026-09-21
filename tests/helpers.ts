import { createCipheriv, createHash, randomBytes } from "node:crypto"

export const CLIENT_ID = "app_client_id"
export const CLIENT_SECRET = "client-secret"
export const CALLBACK_SECRET = "callback-secret"
export const BASE = "https://auth.newtonschool.co/api/v1"
export const ISSUER = "https://auth.newtonschool.co"

/**
 * Independent re-implementation of newton-api's assertion sealing
 * (v1.<nonce>.<ct||tag>.<aad>), written with raw node:crypto so the SDK's
 * WebCrypto decryption is tested against the documented algorithm, not itself.
 */
export function sealServerSide(payload: unknown, secret: string, aadStr: string): string {
  const key = createHash("sha256").update(secret).digest()
  const nonce = randomBytes(12)
  const aad = Buffer.from(aadStr, "utf8")
  const cipher = createCipheriv("aes-256-gcm", key, nonce)
  cipher.setAAD(aad)
  const ct = Buffer.concat([cipher.update(JSON.stringify(payload), "utf8"), cipher.final(), cipher.getAuthTag()])
  const b64 = (b: Buffer) => b.toString("base64url")
  return `v1.${b64(nonce)}.${b64(ct)}.${b64(aad)}`
}

export function validAssertion(overrides: Record<string, unknown> = {}) {
  const now = Math.floor(Date.now() / 1000)
  return {
    sub: "usr_1",
    aud: CLIENT_ID,
    iss: ISSUER,
    authenticated: true,
    authorized: true,
    client_cache_ttl_seconds: 60,
    session_ttl_seconds: 86400,
    platform_token: "tok",
    first_name: "Ada",
    last_name: "Lovelace",
    email: "ada@example.com",
    iat: now - 5,
    exp: now + 55,
    nonce: "n",
    ...overrides,
  }
}

export function okCheckResponse(overrides: Record<string, unknown> = {}) {
  return new Response(
    JSON.stringify({
      authenticated: true,
      authorized: true,
      uid: "usr_1",
      first_name: "Ada",
      last_name: "Lovelace",
      email: "ada@example.com",
      client_cache_ttl_seconds: 60,
      session_ttl_seconds: 86400,
      should_clear_session: false,
      ...overrides,
    }),
    { status: 200 },
  )
}

/** Extracts cookie name=value pairs from Set-Cookie headers. */
export function setCookieMap(headers: string[]): Record<string, { value: string; raw: string }> {
  const map: Record<string, { value: string; raw: string }> = {}
  for (const raw of headers) {
    const [pair] = raw.split(";")
    const eq = pair!.indexOf("=")
    map[pair!.slice(0, eq)] = { value: pair!.slice(eq + 1), raw }
  }
  return map
}
