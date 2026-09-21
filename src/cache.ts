import type { AuthCheckResponse } from "./models.js"

interface CacheEntry {
  value: AuthCheckResponse
  cachedAtMs: number
  approxSize: number
}

function approximateEntrySize(key: string, value: AuthCheckResponse): number {
  return 128 + key.length + value.uid.length + value.firstName.length + value.lastName.length + value.email.length + 64
}

/**
 * Byte-bounded LRU keyed by uid. TTL is per-entry and server-driven
 * (clientCacheTtlSeconds); ttl <= 0 means the entry is never served.
 * Map insertion order doubles as recency order: reads re-insert.
 *
 * In a Worker this lives in isolate memory: it is shared by the requests one
 * isolate serves and dropped whenever the isolate is recycled. It only ever
 * saves auth-check round-trips; correctness never depends on a hit.
 */
export class LruCache {
  private readonly maxBytes: number
  private size = 0
  private readonly entries = new Map<string, CacheEntry>()

  constructor(maxMb: number) {
    this.maxBytes = Math.max(maxMb, 0) * 1024 * 1024
  }

  get(key: string, nowMs: number = Date.now()): AuthCheckResponse | null {
    const entry = this.entries.get(key)
    if (!entry) return null
    const ttl = entry.value.clientCacheTtlSeconds
    if (ttl <= 0 || nowMs - entry.cachedAtMs > ttl * 1000) {
      this.remove(key, entry)
      return null
    }
    this.entries.delete(key)
    this.entries.set(key, entry)
    return entry.value
  }

  set(key: string, value: AuthCheckResponse, nowMs: number = Date.now()): void {
    const existing = this.entries.get(key)
    if (existing) this.remove(key, existing)
    const entry: CacheEntry = { value, cachedAtMs: nowMs, approxSize: approximateEntrySize(key, value) }
    this.entries.set(key, entry)
    this.size += entry.approxSize
    this.evict()
  }

  private evict(): void {
    while (this.size > this.maxBytes && this.entries.size > 0) {
      const oldestKey = this.entries.keys().next().value as string
      this.remove(oldestKey, this.entries.get(oldestKey)!)
    }
  }

  private remove(key: string, entry: CacheEntry): void {
    this.entries.delete(key)
    this.size -= entry.approxSize
  }
}
