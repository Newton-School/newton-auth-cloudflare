import type { ResolvedConfig } from "./config.js"
import { b64Encode, utf8Encode } from "./crypto.js"
import { NewtonAuthError } from "./errors.js"
import type { AuthCheckResponse } from "./models.js"

interface AuthCheckWire {
  authenticated?: boolean
  authorized?: boolean
  uid?: string
  first_name?: string
  last_name?: string
  email?: string
  client_cache_ttl_seconds?: number
  session_ttl_seconds?: number
  should_clear_session?: boolean
}

export class AuthHttpClient {
  constructor(private readonly config: ResolvedConfig) {}

  async authCheck(uid: string, platformToken: string): Promise<AuthCheckResponse> {
    const { newtonApiBase, clientId, clientSecret, authTimeoutMs, fetch } = this.config
    const response = await fetch(`${newtonApiBase}/platform-auth/auth/check/`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: "Basic " + b64Encode(utf8Encode(`${clientId}:${clientSecret}`)),
      },
      body: JSON.stringify({ uid, platform_token: platformToken }),
      signal: AbortSignal.timeout(authTimeoutMs),
    })

    if (response.status === 401) {
      return {
        authenticated: false,
        authorized: false,
        uid,
        firstName: "",
        lastName: "",
        email: "",
        clientCacheTtlSeconds: 60,
        sessionTtlSeconds: 86400,
        shouldClearSession: true,
      }
    }
    if (response.status < 200 || response.status >= 300) {
      throw new NewtonAuthError(`auth check failed with status ${response.status}`)
    }

    const wire = (await response.json()) as AuthCheckWire
    return {
      authenticated: wire.authenticated ?? false,
      authorized: wire.authorized ?? false,
      uid: wire.uid ?? "",
      firstName: wire.first_name ?? "",
      lastName: wire.last_name ?? "",
      email: wire.email ?? "",
      clientCacheTtlSeconds: wire.client_cache_ttl_seconds ?? 0,
      sessionTtlSeconds: wire.session_ttl_seconds ?? 0,
      shouldClearSession: wire.should_clear_session ?? false,
    }
  }
}
