import { describe, expect, it } from "vitest"
import {
  b64urlDecode,
  b64urlEncode,
  decryptCallbackAssertion,
  decryptValue,
  deriveIssuerFromBaseUrl,
  encryptValue,
  signValue,
  utf8Encode,
  verifySignedValue,
} from "../src/crypto.js"
import { ConfigError, InvalidCallbackAssertionError, InvalidSessionError } from "../src/errors.js"
import { CALLBACK_SECRET, CLIENT_ID, ISSUER, sealServerSide } from "./helpers.js"

const NOW = 1_710_000_000

function validAssertion(overrides: Record<string, unknown> = {}) {
  return {
    sub: "usr_abc123",
    aud: CLIENT_ID,
    iss: ISSUER,
    authenticated: true,
    authorized: true,
    client_cache_ttl_seconds: 60,
    session_ttl_seconds: 86400,
    platform_token: "dot_token",
    first_name: "Ada",
    last_name: "Lovelace",
    email: "ada@example.com",
    iat: NOW - 5,
    exp: NOW + 55,
    nonce: "n",
    ...overrides,
  }
}

describe("b64url", () => {
  it("round-trips unpadded and matches Node's base64url", () => {
    const bytes = new Uint8Array([0xff, 0xee, 0x01, 0x02, 0x03])
    const enc = b64urlEncode(bytes)
    expect(enc).not.toContain("=")
    expect(enc).toBe(Buffer.from(bytes).toString("base64url"))
    expect(b64urlDecode(enc)).toEqual(bytes)
    for (const n of [0, 1, 2, 3, 4, 5, 70_000]) {
      const buf = Buffer.alloc(n, 0xab)
      expect(b64urlEncode(new Uint8Array(buf))).toBe(buf.toString("base64url"))
    }
  })

  it("rejects non-base64url characters and impossible lengths", () => {
    expect(() => b64urlDecode("abc+/=")).toThrow(InvalidSessionError)
    expect(() => b64urlDecode("abcde")).toThrow(InvalidSessionError)
  })
})

describe("signValue / verifySignedValue", () => {
  it("round-trips", async () => {
    const signed = await signValue({ a: 1, b: "x" }, "secret")
    expect(await verifySignedValue<{ a: number; b: string }>(signed, "secret")).toEqual({ a: 1, b: "x" })
  })

  it("rejects tampered payload", async () => {
    const signed = await signValue({ a: 1 }, "secret")
    const [payload, sig] = signed.split(".")
    const tampered = b64urlEncode(utf8Encode(JSON.stringify({ a: 2 }))) + "." + sig
    await expect(verifySignedValue(tampered, "secret")).rejects.toThrow(InvalidSessionError)
    await expect(verifySignedValue(payload + ".deadbeef", "secret")).rejects.toThrow(InvalidSessionError)
  })

  it("rejects wrong secret and malformed values", async () => {
    const signed = await signValue({ a: 1 }, "secret")
    await expect(verifySignedValue(signed, "other")).rejects.toThrow(InvalidSessionError)
    await expect(verifySignedValue("", "secret")).rejects.toThrow(InvalidSessionError)
    await expect(verifySignedValue("no-dot-here", "secret")).rejects.toThrow(InvalidSessionError)
  })
})

describe("encryptValue / decryptValue", () => {
  const aad = utf8Encode(CLIENT_ID)

  it("round-trips with v2 wire format", async () => {
    const value = await encryptValue({ uid: "u1" }, "secret", aad)
    expect(value.startsWith("v2.")).toBe(true)
    expect(value.split(".")).toHaveLength(3)
    expect(await decryptValue<{ uid: string }>(value, "secret", aad)).toEqual({ uid: "u1" })
  })

  it("rejects tamper, wrong secret, wrong aad, wrong version", async () => {
    const value = await encryptValue({ uid: "u1" }, "secret", aad)
    await expect(decryptValue(value, "other", aad)).rejects.toThrow(InvalidSessionError)
    await expect(decryptValue(value, "secret", utf8Encode("other"))).rejects.toThrow(InvalidSessionError)
    await expect(decryptValue(value.replace("v2.", "v1."), "secret", aad)).rejects.toThrow(InvalidSessionError)
    const parts = value.split(".")
    const ct = b64urlDecode(parts[2]!)
    ct[0]! ^= 0xff
    await expect(decryptValue(`v2.${parts[1]}.${b64urlEncode(ct)}`, "secret", aad)).rejects.toThrow(InvalidSessionError)
  })
})

describe("decryptCallbackAssertion", () => {
  it("decrypts a server-sealed assertion", async () => {
    const identity = sealServerSide(validAssertion(), CALLBACK_SECRET, CLIENT_ID)
    const assertion = await decryptCallbackAssertion(identity, CALLBACK_SECRET, CLIENT_ID, ISSUER, NOW)
    expect(assertion.sub).toBe("usr_abc123")
    expect(assertion.platform_token).toBe("dot_token")
    expect(assertion.first_name).toBe("Ada")
  })

  const reject = async (identity: string, message?: string) => {
    await expect(decryptCallbackAssertion(identity, CALLBACK_SECRET, CLIENT_ID, ISSUER, NOW)).rejects.toThrow(
      message ? expect.objectContaining({ message: expect.stringContaining(message) }) : InvalidCallbackAssertionError,
    )
  }

  it("rejects empty / malformed / wrong version", async () => {
    await reject("")
    await reject("v1.only.three")
    const identity = sealServerSide(validAssertion(), CALLBACK_SECRET, CLIENT_ID)
    await reject(identity.replace(/^v1\./, "v9."))
  })

  it("rejects AAD not matching client id", async () => {
    await reject(sealServerSide(validAssertion(), CALLBACK_SECRET, "other_client"), "audience mismatch")
  })

  it("rejects payload aud mismatch", async () => {
    await reject(sealServerSide(validAssertion({ aud: "someone_else" }), CALLBACK_SECRET, CLIENT_ID), "aud mismatch")
  })

  it("rejects issuer mismatch", async () => {
    await reject(
      sealServerSide(validAssertion({ iss: "https://evil.example.com" }), CALLBACK_SECRET, CLIENT_ID),
      "issuer mismatch",
    )
  })

  it("rejects expired assertion", async () => {
    await reject(sealServerSide(validAssertion({ exp: NOW - 1 }), CALLBACK_SECRET, CLIENT_ID), "expired")
  })

  it("rejects iat too far in the future", async () => {
    await reject(sealServerSide(validAssertion({ iat: NOW + 31 }), CALLBACK_SECRET, CLIENT_ID), "issued in future")
    const ok = sealServerSide(validAssertion({ iat: NOW + 30 }), CALLBACK_SECRET, CLIENT_ID)
    expect((await decryptCallbackAssertion(ok, CALLBACK_SECRET, CLIENT_ID, ISSUER, NOW)).sub).toBe("usr_abc123")
  })

  it("rejects missing sub / platform_token", async () => {
    await reject(sealServerSide(validAssertion({ sub: "" }), CALLBACK_SECRET, CLIENT_ID), "missing required fields")
    await reject(
      sealServerSide(validAssertion({ platform_token: "" }), CALLBACK_SECRET, CLIENT_ID),
      "missing required fields",
    )
  })

  it("rejects wrong callback secret", async () => {
    await reject(sealServerSide(validAssertion(), "wrong-secret", CLIENT_ID), "decryption failed")
  })
})

describe("deriveIssuerFromBaseUrl", () => {
  it("derives scheme://host origin", () => {
    expect(deriveIssuerFromBaseUrl("https://auth.newtonschool.co/api/v1")).toBe("https://auth.newtonschool.co")
    expect(deriveIssuerFromBaseUrl("http://localhost:8000/api/v1/")).toBe("http://localhost:8000")
  })

  it("throws ConfigError on garbage", () => {
    expect(() => deriveIssuerFromBaseUrl("not a url")).toThrow(ConfigError)
  })
})
