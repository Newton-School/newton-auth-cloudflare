import { describe, expect, it } from "vitest"
import { LruCache } from "../src/cache.js"
import type { AuthCheckResponse } from "../src/models.js"

function entry(uid: string, ttl = 60, extra: Partial<AuthCheckResponse> = {}): AuthCheckResponse {
  return {
    authenticated: true,
    authorized: true,
    uid,
    firstName: "",
    lastName: "",
    email: "",
    clientCacheTtlSeconds: ttl,
    sessionTtlSeconds: 86400,
    shouldClearSession: false,
    ...extra,
  }
}

const NOW = 1_710_000_000_000 // ms

describe("LruCache", () => {
  it("returns cached entries within TTL", () => {
    const cache = new LruCache(1)
    cache.set("u1", entry("u1", 60), NOW)
    expect(cache.get("u1", NOW + 59_000)?.uid).toBe("u1")
  })

  it("misses unknown keys", () => {
    const cache = new LruCache(1)
    expect(cache.get("nope", NOW)).toBeNull()
  })

  it("expires entries after clientCacheTtlSeconds", () => {
    const cache = new LruCache(1)
    cache.set("u1", entry("u1", 60), NOW)
    expect(cache.get("u1", NOW + 60_001)).toBeNull()
    // and the expired entry is removed, not resurrected
    expect(cache.get("u1", NOW)).toBeNull()
  })

  it("treats ttl 0 as uncacheable", () => {
    const cache = new LruCache(1)
    cache.set("u1", entry("u1", 0), NOW)
    expect(cache.get("u1", NOW)).toBeNull()
  })

  it("evicts least-recently-used entries when over budget", () => {
    // Budget of exactly ~2 entries: approx size = 128 + key + uid + 64 = 196 for "u1"
    const cache = new LruCache(400 / (1024 * 1024))
    cache.set("u1", entry("u1"), NOW)
    cache.set("u2", entry("u2"), NOW)
    // touch u1 so u2 becomes LRU
    expect(cache.get("u1", NOW)?.uid).toBe("u1")
    cache.set("u3", entry("u3"), NOW)
    expect(cache.get("u2", NOW)).toBeNull()
    expect(cache.get("u1", NOW)?.uid).toBe("u1")
    expect(cache.get("u3", NOW)?.uid).toBe("u3")
  })

  it("updates existing keys in place", () => {
    const cache = new LruCache(1)
    cache.set("u1", entry("u1", 60, { authorized: true }), NOW)
    cache.set("u1", entry("u1", 60, { authorized: false }), NOW)
    expect(cache.get("u1", NOW)?.authorized).toBe(false)
  })

  it("disables caching entirely with maxMb 0", () => {
    const cache = new LruCache(0)
    cache.set("u1", entry("u1"), NOW)
    expect(cache.get("u1", NOW)).toBeNull()
  })
})
