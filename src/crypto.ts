// Wire-format primitives shared with newton-auth-python / -golang / -nodejs,
// implemented on WebCrypto so they run inside a Cloudflare Worker:
//   sealed value:      v2.<b64url nonce>.<b64url ct||tag>            AES-256-GCM, key = SHA-256(secret), AAD = client id
//   signed value:      <b64url payload>.<hex HMAC-SHA256(payload)>
//   callback identity: v1.<b64url nonce>.<b64url ct||tag>.<b64url aad>  sealed by newton-api with the callback secret
import { ConfigError, InvalidCallbackAssertionError, InvalidSessionError } from "./errors.js"
import type { CallbackAssertion } from "./models.js"

const SESSION_WIRE_VERSION = "v2"
const GCM_TAG_LENGTH = 16
const GCM_TAG_LENGTH_BITS = GCM_TAG_LENGTH * 8
const HMAC_SHA256_LENGTH = 32

const encoder = new TextEncoder()
const decoder = new TextDecoder("utf-8", { fatal: true })

export function utf8Encode(value: string): Uint8Array {
  return encoder.encode(value)
}

export function utf8Decode(bytes: Uint8Array): string {
  return decoder.decode(bytes)
}

export function randomBytes(length: number): Uint8Array {
  const out = new Uint8Array(length)
  crypto.getRandomValues(out)
  return out
}

function bytesToBinaryString(bytes: Uint8Array): string {
  let out = ""
  for (let i = 0; i < bytes.length; i += 0x8000) {
    out += String.fromCharCode(...bytes.subarray(i, i + 0x8000))
  }
  return out
}

function binaryStringToBytes(binary: string): Uint8Array {
  const out = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i)
  return out
}

/** Standard base64 with padding (used for the Basic auth header). */
export function b64Encode(bytes: Uint8Array): string {
  return btoa(bytesToBinaryString(bytes))
}

export function b64urlEncode(bytes: Uint8Array): string {
  return b64Encode(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "")
}

export function b64urlDecode(value: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]*$/.test(value) || value.length % 4 === 1) throw new InvalidSessionError("invalid base64url")
  const padded = value.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (value.length % 4)) % 4)
  try {
    return binaryStringToBytes(atob(padded))
  } catch {
    throw new InvalidSessionError("invalid base64url")
  }
}

function hexEncode(bytes: Uint8Array): string {
  let out = ""
  for (const b of bytes) out += b.toString(16).padStart(2, "0")
  return out
}

function hexDecode(value: string): Uint8Array | null {
  if (value.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(value)) return null
  const out = new Uint8Array(value.length / 2)
  for (let i = 0; i < out.length; i++) out[i] = parseInt(value.slice(i * 2, i * 2 + 2), 16)
  return out
}

async function aesKeyFor(secret: string): Promise<CryptoKey> {
  const digest = await crypto.subtle.digest("SHA-256", utf8Encode(secret))
  return crypto.subtle.importKey("raw", digest, { name: "AES-GCM" }, false, ["encrypt", "decrypt"])
}

async function hmacKeyFor(secret: string): Promise<CryptoKey> {
  return crypto.subtle.importKey("raw", utf8Encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"])
}

export async function encryptValue(payload: unknown, secret: string, aad: Uint8Array): Promise<string> {
  const nonce = randomBytes(12)
  const key = await aesKeyFor(secret)
  const params: AesGcmParams = { name: "AES-GCM", iv: nonce, additionalData: aad, tagLength: GCM_TAG_LENGTH_BITS }
  const ctWithTag = new Uint8Array(await crypto.subtle.encrypt(params, key, utf8Encode(JSON.stringify(payload))))
  return `${SESSION_WIRE_VERSION}.${b64urlEncode(nonce)}.${b64urlEncode(ctWithTag)}`
}

export async function decryptValue<T>(value: string, secret: string, aad: Uint8Array): Promise<T> {
  const parts = value.split(".")
  if (parts.length !== 3 || parts[0] !== SESSION_WIRE_VERSION) throw new InvalidSessionError()
  return gcmOpen<T>(parts[1]!, parts[2]!, secret, aad, () => new InvalidSessionError())
}

async function gcmOpen<T>(
  nonceB64: string,
  ctB64: string,
  secret: string,
  aad: Uint8Array,
  err: () => Error,
): Promise<T> {
  let nonce: Uint8Array
  let ctWithTag: Uint8Array
  try {
    nonce = b64urlDecode(nonceB64)
    ctWithTag = b64urlDecode(ctB64)
  } catch {
    throw err()
  }
  if (nonce.length === 0 || ctWithTag.length < GCM_TAG_LENGTH) throw err()
  try {
    const key = await aesKeyFor(secret)
    const params: AesGcmParams = { name: "AES-GCM", iv: nonce, additionalData: aad, tagLength: GCM_TAG_LENGTH_BITS }
    const plaintext = new Uint8Array(await crypto.subtle.decrypt(params, key, ctWithTag))
    return JSON.parse(utf8Decode(plaintext)) as T
  } catch {
    throw err()
  }
}

export async function signValue(payload: unknown, secret: string): Promise<string> {
  const payloadValue = b64urlEncode(utf8Encode(JSON.stringify(payload)))
  const signature = new Uint8Array(await crypto.subtle.sign("HMAC", await hmacKeyFor(secret), utf8Encode(payloadValue)))
  return `${payloadValue}.${hexEncode(signature)}`
}

export async function verifySignedValue<T>(value: string, secret: string): Promise<T> {
  const lastDot = value.lastIndexOf(".")
  if (!value || lastDot < 0) throw new InvalidSessionError()
  const payloadValue = value.slice(0, lastDot)
  const signature = hexDecode(value.slice(lastDot + 1))
  if (!signature || signature.length !== HMAC_SHA256_LENGTH) throw new InvalidSessionError()
  // subtle.verify is constant-time, so no hand-rolled comparison is needed.
  const valid = await crypto.subtle.verify("HMAC", await hmacKeyFor(secret), signature, utf8Encode(payloadValue))
  if (!valid) throw new InvalidSessionError()
  try {
    return JSON.parse(utf8Decode(b64urlDecode(payloadValue))) as T
  } catch {
    throw new InvalidSessionError()
  }
}

export async function decryptCallbackAssertion(
  identity: string,
  callbackSecret: string,
  clientId: string,
  expectedIssuer: string,
  nowSec: number = Math.floor(Date.now() / 1000),
): Promise<CallbackAssertion> {
  if (!identity) throw new InvalidCallbackAssertionError()
  const parts = identity.split(".")
  if (parts.length !== 4 || parts[0] !== "v1") throw new InvalidCallbackAssertionError()
  let aad: Uint8Array
  try {
    aad = b64urlDecode(parts[3]!)
  } catch {
    throw new InvalidCallbackAssertionError()
  }
  let aadText: string
  try {
    aadText = utf8Decode(aad)
  } catch {
    throw new InvalidCallbackAssertionError("assertion audience mismatch")
  }
  if (aadText !== clientId) throw new InvalidCallbackAssertionError("assertion audience mismatch")
  const assertion = await gcmOpen<CallbackAssertion>(
    parts[1]!,
    parts[2]!,
    callbackSecret,
    aad,
    () => new InvalidCallbackAssertionError("assertion decryption failed"),
  )
  if (assertion.aud !== clientId) throw new InvalidCallbackAssertionError("assertion aud mismatch")
  if (assertion.iss !== expectedIssuer) throw new InvalidCallbackAssertionError("assertion issuer mismatch")
  if (nowSec > assertion.exp) throw new InvalidCallbackAssertionError("assertion expired")
  if (assertion.iat > nowSec + 30) throw new InvalidCallbackAssertionError("assertion issued in future")
  // An authenticated=false assertion means the login completed but the user is
  // not authenticated (e.g. no Newton account); it carries no uid/token.
  if (assertion.authenticated && (!assertion.sub || !assertion.platform_token)) {
    throw new InvalidCallbackAssertionError("assertion missing required fields")
  }
  return assertion
}

export function deriveIssuerFromBaseUrl(baseUrl: string): string {
  try {
    return new URL(baseUrl).origin
  } catch {
    throw new ConfigError("invalid newton api base")
  }
}
