import assert from "node:assert/strict";
import { test } from "node:test";

import type { AuthStore } from "../netlify/functions/_shared/auth-store.js";
import {
  decodeLoginUrl,
  handleAuthRequest,
} from "../netlify/functions/_shared/auth-app.js";

const SESSION_ID = "a".repeat(64);
const K1 = "e2af6254a8df433264fa23f67eb8188635d15ce883e8fc020989d5f82ae6f11e";
const PUBLIC_KEY = "02c3b844b8104f0c1b15c507774c9ba7fc609f58f343b9b149122e944dd20c9362";
const SIGNATURE = "304402203767faf494f110b139293d9bab3c50e07b3bf33c463d4aa767256cd09132dc5102205821f8efacdb5c595b92ada255876d9201e126e2f31a140d44561cc1f7e9e43d";
const BASE_TIME = Date.UTC(2026, 7, 18, 17, 0, 0);

class MemoryAuthStore implements AuthStore {
  readonly values = new Map<string, unknown>();

  async delete(key: string): Promise<void> {
    this.values.delete(key);
  }

  async get<T>(key: string): Promise<T | null> {
    return (this.values.get(key) as T | undefined) ?? null;
  }

  async setJSON(key: string, value: unknown): Promise<void> {
    this.values.set(key, structuredClone(value));
  }
}

function cookieFrom(response: Response): string {
  const setCookie = response.headers.get("set-cookie");
  assert.ok(setCookie, "expected a Set-Cookie header");
  return setCookie.split(";", 1)[0] ?? "";
}

function request(path: string, init: RequestInit = {}): Request {
  return new Request(`https://lightninglogin.netlify.app${path}`, init);
}

function deterministicOptions(now = BASE_TIME) {
  const values = [SESSION_ID, K1];
  return {
    now: () => now,
    randomHex: () => {
      const value = values.shift();
      if (!value) throw new Error("random sequence exhausted");
      return value;
    },
    toDataUrl: async () => "data:image/png;base64,AA==",
  };
}

function walletCallback(signature = SIGNATURE): string {
  const params = new URLSearchParams({
    action: "login",
    k1: K1,
    key: PUBLIC_KEY,
    sig: signature,
    tag: "login",
  });
  return `/auth/callback?${params}`;
}

test("creates a valid, browser-bound LNURL-auth challenge", async () => {
  const store = new MemoryAuthStore();
  const login = await handleAuthRequest(request("/login"), store, deterministicOptions());

  assert.equal(login.status, 200);
  assert.match(login.headers.get("cache-control") ?? "", /no-store/);
  const setCookie = login.headers.get("set-cookie") ?? "";
  assert.match(setCookie, /HttpOnly/);
  assert.match(setCookie, /SameSite=Lax/);
  assert.match(setCookie, /Secure/);
  assert.doesNotMatch(setCookie, new RegExp(K1, "i"));

  const body = await login.text();
  const match = body.match(/href="lightning:(LNURL[^"]+)"/);
  assert.ok(match?.[1], "expected a Lightning LNURL link");
  const callback = new URL(decodeLoginUrl(match[1]));
  assert.equal(callback.origin, "https://lightninglogin.netlify.app");
  assert.equal(callback.pathname, "/auth/callback");
  assert.equal(callback.searchParams.get("tag"), "login");
  assert.equal(callback.searchParams.get("action"), "login");
  assert.equal(callback.searchParams.get("k1"), K1);

  const unrelatedBrowser = await handleAuthRequest(request("/auth/status"), store);
  assert.deepEqual(await unrelatedBrowser.json(), { status: "anonymous" });
});

test("completes the official LUD-04 signature flow and logs out", async () => {
  const store = new MemoryAuthStore();
  const login = await handleAuthRequest(request("/login"), store, deterministicOptions());
  const cookie = cookieFrom(login);

  const pending = await handleAuthRequest(
    request("/auth/status", { headers: { Cookie: cookie } }),
    store,
    { now: () => BASE_TIME },
  );
  assert.deepEqual(await pending.json(), { status: "pending" });

  const callback = await handleAuthRequest(
    request(walletCallback()),
    store,
    { now: () => BASE_TIME + 1_000 },
  );
  assert.equal(callback.status, 200);
  assert.deepEqual(await callback.json(), { status: "OK" });

  const authenticated = await handleAuthRequest(
    request("/auth/status", { headers: { Cookie: cookie } }),
    store,
    { now: () => BASE_TIME + 2_000 },
  );
  assert.deepEqual(await authenticated.json(), { status: "authenticated" });

  const success = await handleAuthRequest(
    request("/success", { headers: { Cookie: cookie } }),
    store,
    { now: () => BASE_TIME + 2_000 },
  );
  assert.equal(success.status, 200);
  assert.match(await success.text(), new RegExp(PUBLIC_KEY));

  const unrelatedSuccess = await handleAuthRequest(request("/success"), store);
  assert.equal(unrelatedSuccess.status, 303);
  assert.equal(unrelatedSuccess.headers.get("location"), "/");

  const logout = await handleAuthRequest(
    request("/logout", { headers: { Cookie: cookie }, method: "POST" }),
    store,
  );
  assert.equal(logout.status, 303);
  assert.match(logout.headers.get("set-cookie") ?? "", /Max-Age=0/);

  const afterLogout = await handleAuthRequest(
    request("/auth/status", { headers: { Cookie: cookie } }),
    store,
  );
  assert.deepEqual(await afterLogout.json(), { status: "anonymous" });
});

test("rejects an invalid wallet signature without authenticating the browser", async () => {
  const store = new MemoryAuthStore();
  const login = await handleAuthRequest(request("/login"), store, deterministicOptions());
  const cookie = cookieFrom(login);
  const invalidSignature = `${SIGNATURE.slice(0, -2)}00`;

  const callback = await handleAuthRequest(
    request(walletCallback(invalidSignature)),
    store,
    { now: () => BASE_TIME + 1_000 },
  );
  assert.equal(callback.status, 400);
  assert.deepEqual(await callback.json(), {
    reason: "Signature verification failed.",
    status: "ERROR",
  });

  const status = await handleAuthRequest(
    request("/auth/status", { headers: { Cookie: cookie } }),
    store,
    { now: () => BASE_TIME + 2_000 },
  );
  assert.deepEqual(await status.json(), { status: "pending" });
});

test("expires abandoned challenges and enforces endpoint methods", async () => {
  const store = new MemoryAuthStore();
  const login = await handleAuthRequest(request("/login"), store, deterministicOptions());
  const cookie = cookieFrom(login);

  const expired = await handleAuthRequest(
    request("/auth/status", { headers: { Cookie: cookie } }),
    store,
    { now: () => BASE_TIME + 10 * 60 * 1_000 },
  );
  assert.deepEqual(await expired.json(), { status: "expired" });
  assert.equal(store.values.size, 0);

  const wrongMethod = await handleAuthRequest(request("/logout"), store);
  assert.equal(wrongMethod.status, 405);
  assert.equal(wrongMethod.headers.get("allow"), "POST");
});
