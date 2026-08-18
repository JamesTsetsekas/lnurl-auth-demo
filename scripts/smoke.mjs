import assert from "node:assert/strict";

import { secp256k1 } from "@noble/curves/secp256k1.js";
import { bech32 } from "bech32";

const baseUrl = new URL(process.argv[2] ?? "http://localhost:8888");

function decodeLnurl(value) {
  const decoded = bech32.decode(value, 2_000);
  assert.equal(decoded.prefix.toLowerCase(), "lnurl");
  return Buffer.from(bech32.fromWords(decoded.words)).toString("utf8");
}

function hex(bytes) {
  return Buffer.from(bytes).toString("hex");
}

function cookieHeader(response) {
  const setCookie = response.headers.get("set-cookie");
  assert.ok(setCookie, "login did not set a browser session cookie");
  assert.match(setCookie, /HttpOnly/);
  assert.match(setCookie, /SameSite=Lax/);
  if (baseUrl.protocol === "https:") assert.match(setCookie, /Secure/);
  return setCookie.split(";", 1)[0];
}

const root = await fetch(new URL("/", baseUrl), { redirect: "manual" });
assert.equal(root.status, 200);
assert.match(root.headers.get("content-security-policy") ?? "", /default-src 'self'/);
assert.match(await root.text(), /Your wallet is your login/);

const login = await fetch(new URL("/login", baseUrl), { redirect: "manual" });
assert.equal(login.status, 200);
assert.match(login.headers.get("cache-control") ?? "", /no-store/);
const cookie = cookieHeader(login);
const loginHtml = await login.text();
const lnurlMatch = loginHtml.match(/href="lightning:(LNURL[^"]+)"/);
assert.ok(lnurlMatch?.[1], "login page did not contain an LNURL wallet link");

const callbackUrl = new URL(decodeLnurl(lnurlMatch[1]));
const k1Hex = callbackUrl.searchParams.get("k1") ?? "";
assert.match(k1Hex, /^[0-9a-f]{64}$/i);
assert.equal(callbackUrl.searchParams.get("tag"), "login");
assert.equal(callbackUrl.searchParams.get("action"), "login");

const secretKey = secp256k1.utils.randomSecretKey();
const publicKey = secp256k1.getPublicKey(secretKey, true);
const signature = secp256k1.sign(Buffer.from(k1Hex, "hex"), secretKey, {
  format: "der",
  lowS: false,
  prehash: false,
});
callbackUrl.searchParams.set("key", hex(publicKey));
callbackUrl.searchParams.set("sig", hex(signature));

const callback = await fetch(callbackUrl, { redirect: "manual" });
assert.equal(callback.status, 200);
assert.deepEqual(await callback.json(), { status: "OK" });

const status = await fetch(new URL("/auth/status", baseUrl), {
  headers: { Cookie: cookie },
  redirect: "manual",
});
assert.equal(status.status, 200);
assert.deepEqual(await status.json(), { status: "authenticated" });

const unrelatedStatus = await fetch(new URL("/auth/status", baseUrl));
assert.deepEqual(await unrelatedStatus.json(), { status: "anonymous" });

const success = await fetch(new URL("/success", baseUrl), {
  headers: { Cookie: cookie },
  redirect: "manual",
});
assert.equal(success.status, 200);
assert.match(await success.text(), /Lightning login complete/);

const logout = await fetch(new URL("/logout", baseUrl), {
  headers: { Cookie: cookie },
  method: "POST",
  redirect: "manual",
});
assert.equal(logout.status, 303);
assert.equal(logout.headers.get("location"), "/");

const clearedStatus = await fetch(new URL("/auth/status", baseUrl), {
  headers: { Cookie: cookie },
});
assert.deepEqual(await clearedStatus.json(), { status: "anonymous" });

console.log(JSON.stringify({
  baseUrl: baseUrl.origin,
  checks: [
    "static site",
    "security headers",
    "LNURL decode",
    "wallet signature callback",
    "browser session binding",
    "success page",
    "logout cleanup",
  ],
  status: "passed",
}, null, 2));
