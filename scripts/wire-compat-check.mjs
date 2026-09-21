// Cross-SDK wire-compatibility check against newton-auth-python.
// Usage: node scripts/wire-compat-check.mjs <path-to-newton-auth-python> <python-bin>
// Generates a callback assertion + session/state cookies with the Python SDK
// and parses them with this SDK, then round-trips a JS-built session cookie
// back through the Python SDK.
import { execFileSync } from "node:child_process"
import { NewtonAuth } from "../dist/index.js"

const [pySdkPath = "../newton-auth-python", pythonBin = "python3"] = process.argv.slice(2)

const CLIENT_ID = "app_client_id"
const CLIENT_SECRET = "client-secret"
const CALLBACK_SECRET = "callback-secret"
const BASE = "https://auth.newtonschool.co/api/v1"

const pyGenerate = `
import json, sys, time
sys.path.insert(0, "src")
from newton_auth import crypto, cookies

now = int(time.time())
assertion = {
    "sub": "usr_py", "aud": "${CLIENT_ID}", "iss": "https://auth.newtonschool.co",
    "authenticated": True, "authorized": True,
    "client_cache_ttl_seconds": 60, "session_ttl_seconds": 86400,
    "platform_token": "tok_py", "first_name": "Py", "last_name": "Thon",
    "email": "py@example.com", "iat": now - 5, "exp": now + 55, "nonce": "n",
}
nonce = crypto.random_bytes(12) if hasattr(crypto, "random_bytes") else __import__("os").urandom(12)
aad = "${CLIENT_ID}".encode()
ct = crypto._aesgcm_for("${CALLBACK_SECRET}").encrypt(nonce, json.dumps(assertion).encode(), aad)
identity = "v1." + crypto.b64url_encode(nonce) + "." + crypto.b64url_encode(ct) + "." + crypto.b64url_encode(aad)

session_cookie = cookies.build_session_cookie_value(
    "usr_py", "tok_py", True, 86400, "${CLIENT_SECRET}", "${CLIENT_ID}")
state_cookie = cookies.build_state_cookie_value("st_py", "/protected?x=1", "${CLIENT_SECRET}")
print(json.dumps({"identity": identity, "session_cookie": session_cookie, "state_cookie": state_cookie}))
`

const fixtures = JSON.parse(execFileSync(pythonBin, ["-c", pyGenerate], { cwd: pySdkPath, encoding: "utf8" }).trim())

const auth = new NewtonAuth({
  clientId: CLIENT_ID,
  clientSecret: CLIENT_SECRET,
  callbackSecret: CALLBACK_SECRET,
  newtonApiBase: BASE,
})

// 1. Python-sealed assertion + Python state cookie -> handleCallback
const callback = await auth.handleCallback({
  path: "/newton/callback",
  query: { state: "st_py", identity: fixtures.identity },
  cookies: { newton_state: fixtures.state_cookie },
  host: "app.example.com",
  proto: "https",
})
if (callback.user.uid !== "usr_py" || callback.redirectUri !== "/protected?x=1" || callback.user.firstName !== "Py") {
  throw new Error("python->worker callback mismatch: " + JSON.stringify(callback))
}
console.log("OK python assertion + state cookie -> worker handleCallback")

// 2. Python-built session cookie -> authenticate (mock auth-check)
const auth2 = new NewtonAuth({
  clientId: CLIENT_ID,
  clientSecret: CLIENT_SECRET,
  callbackSecret: CALLBACK_SECRET,
  newtonApiBase: BASE,
  fetch: async () =>
    new Response(
      JSON.stringify({ authenticated: true, authorized: true, uid: "usr_py", client_cache_ttl_seconds: 60, session_ttl_seconds: 86400 }),
      { status: 200 },
    ),
})
const result = await auth2.authenticate({
  path: "/p", query: {}, cookies: { newton_session: fixtures.session_cookie }, host: "h", proto: "https",
})
if (!result.authenticated || result.user?.uid !== "usr_py") {
  throw new Error("python session cookie -> worker authenticate failed: " + JSON.stringify(result))
}
console.log("OK python session cookie -> worker authenticate")

// 3. Worker-built session cookie -> Python parse
const jsSession = callback.sessionCookie.value
const pyParse = `
import json, sys
sys.path.insert(0, "src")
from newton_auth import cookies
payload = cookies.parse_session_cookie_value(${JSON.stringify(jsSession)}, "${CLIENT_SECRET}", "${CLIENT_ID}")
print(json.dumps({"uid": payload["uid"], "platform_token": payload["platform_token"]}))
`
const parsed = JSON.parse(execFileSync(pythonBin, ["-c", pyParse], { cwd: pySdkPath, encoding: "utf8" }).trim())
if (parsed.uid !== "usr_py" || parsed.platform_token !== "tok_py") {
  throw new Error("worker session cookie -> python parse mismatch: " + JSON.stringify(parsed))
}
console.log("OK worker session cookie -> python parse")
console.log("wire-compat (python): ALL CHECKS PASSED")
