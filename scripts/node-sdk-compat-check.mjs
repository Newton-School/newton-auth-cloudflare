// Cross-SDK wire-compatibility check against newton-auth-nodejs.
// Usage: node scripts/node-sdk-compat-check.mjs <path-to-newton-auth-nodejs>
// The Node SDK must be built (npm run build) so its dist/ exists. Cookies built
// by either SDK must parse in the other, and both must reject the other's
// cookies under a different client id.
import { pathToFileURL } from "node:url"
import { resolve } from "node:path"
import * as worker from "../dist/index.js"
import { buildSessionCookieValue as workerBuildSession } from "../dist/index.js"

const [nodeSdkPath = "../newton-auth-nodejs"] = process.argv.slice(2)
const nodeSdk = await import(pathToFileURL(resolve(nodeSdkPath, "dist/index.js")).href)

const CLIENT_ID = "app_client_id"
const CLIENT_SECRET = "client-secret"
const CALLBACK_SECRET = "callback-secret"
const BASE = "https://auth.newtonschool.co/api/v1"
const config = { clientId: CLIENT_ID, clientSecret: CLIENT_SECRET, callbackSecret: CALLBACK_SECRET, newtonApiBase: BASE }

const nodeAuth = new nodeSdk.NewtonAuth({ ...config, fetch: async () => new Response("no", { status: 401 }) })
const workerAuth = new worker.NewtonAuth({ ...config, fetch: async () => new Response("no", { status: 401 }) })

// 1. Node login redirect (state cookie) -> Worker callback, and the reverse.
// Neither SDK exposes an assertion sealer, so the callback itself is exercised
// with the state cookie only: a wrong-state rejection proves the cookie parsed.
const nodeLogin = nodeAuth.buildLoginRedirect({ path: "/p", query: {}, cookies: {}, host: "h", proto: "https" }, "/p?x=1")
const nodeState = new URL(nodeLogin.location).searchParams.get("state")
try {
  await workerAuth.handleCallback({
    path: "/newton/callback", query: { state: nodeState, identity: "" }, cookies: { newton_state: nodeLogin.stateCookie.value },
    host: "h", proto: "https",
  })
  throw new Error("expected assertion failure")
} catch (err) {
  if (err?.name !== "InvalidCallbackAssertionError") throw new Error("node state cookie not accepted by worker: " + err)
}
console.log("OK node state cookie -> worker (state accepted, empty identity rejected)")

const workerLogin = await workerAuth.buildLoginRedirect({ path: "/p", query: {}, cookies: {}, host: "h", proto: "https" }, "/p?x=1")
const workerState = new URL(workerLogin.location).searchParams.get("state")
try {
  await nodeAuth.handleCallback({
    path: "/newton/callback", query: { state: workerState, identity: "" }, cookies: { newton_state: workerLogin.stateCookie.value },
    host: "h", proto: "https",
  })
  throw new Error("expected assertion failure")
} catch (err) {
  if (err?.name !== "InvalidCallbackAssertionError") throw new Error("worker state cookie not accepted by node: " + err)
}
console.log("OK worker state cookie -> node (state accepted, empty identity rejected)")

// 2. Session cookies both ways. The Node SDK does not export its cookie
// builders, so its authenticate() is the parser: a 401 auth-check maps to
// shouldClearSession=true only when the cookie itself decrypted.
const workerSession = await workerBuildSession("usr_w", "tok_w", true, 86400, CLIENT_SECRET, CLIENT_ID)
const nodeResult = await nodeAuth.authenticate({ path: "/p", query: {}, cookies: { newton_session: workerSession }, host: "h", proto: "https" })
const nodeParsedWorkerCookie = nodeResult.authenticated === false && nodeResult.shouldClearSession === true
const nodeAuthOk = new nodeSdk.NewtonAuth({
  ...config,
  fetch: async () => new Response(JSON.stringify({ authenticated: true, authorized: true, uid: "usr_w", client_cache_ttl_seconds: 0, session_ttl_seconds: 86400 }), { status: 200 }),
})
const nodeOk = await nodeAuthOk.authenticate({ path: "/p", query: {}, cookies: { newton_session: workerSession }, host: "h", proto: "https" })
if (!nodeParsedWorkerCookie || nodeOk.user?.uid !== "usr_w") {
  throw new Error("worker session cookie -> node authenticate failed: " + JSON.stringify(nodeOk))
}
console.log("OK worker session cookie -> node authenticate")

const wrongClient = new worker.NewtonAuth({ ...config, clientId: "other_client", fetch: async () => new Response("", { status: 200 }) })
const rejected = await wrongClient.authenticate({ path: "/p", query: {}, cookies: { newton_session: workerSession }, host: "h", proto: "https" })
if (rejected.authenticated || !rejected.shouldClearSession) throw new Error("AAD mismatch not rejected")
console.log("OK session cookie rejected under a different client id")

console.log("wire-compat (node): ALL CHECKS PASSED")
