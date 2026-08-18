import { randomBytes } from "node:crypto";

import { secp256k1 } from "@noble/curves/secp256k1.js";
import { bech32 } from "bech32";
import QRCode from "qrcode";

import type { AuthStore } from "./auth-store.js";

const CHALLENGE_TTL_MS = 10 * 60 * 1000;
const AUTHENTICATED_TTL_MS = 60 * 60 * 1000;
const COOKIE_NAME = "lightninglogin_session";
const HEX_32_BYTES = /^[0-9a-f]{64}$/i;
const COMPRESSED_PUBLIC_KEY = /^(02|03)[0-9a-f]{64}$/i;
const DER_SIGNATURE = /^30[0-9a-f]{136,142}$/i;

function encodeLnurl(value: string): string {
  return bech32.encode("lnurl", bech32.toWords(Buffer.from(value, "utf8")), 2_000);
}

function decodeLnurl(value: string): string {
  const decoded = bech32.decode(value, 2_000);
  if (decoded.prefix.toLowerCase() !== "lnurl") throw new Error("Invalid LNURL prefix");
  return Buffer.from(bech32.fromWords(decoded.words)).toString("utf8");
}

function verifySignature(signature: string, k1: string, publicKey: string): boolean {
  return secp256k1.verify(
    Buffer.from(signature, "hex"),
    Buffer.from(k1, "hex"),
    Buffer.from(publicKey, "hex"),
    { format: "der", lowS: false, prehash: false },
  );
}

interface AuthSession {
  createdAt: number;
  expiresAt: number;
  id: string;
  k1: string;
  linkingPublicKey?: string;
  state: "pending" | "authenticated";
  version: 1;
}

interface Challenge {
  expiresAt: number;
  k1: string;
  sessionId: string;
  version: 1;
}

interface HandlerOptions {
  callbackOrigin?: string;
  now?: () => number;
  randomHex?: () => string;
  toDataUrl?: typeof QRCode.toDataURL;
}

function challengeKey(k1: string): string {
  return `challenge/${k1.toLowerCase()}`;
}

function sessionKey(sessionId: string): string {
  return `session/${sessionId.toLowerCase()}`;
}

function html(strings: TemplateStringsArray, ...values: string[]): string {
  return strings.reduce(
    (result, part, index) => result + part + (values[index] ?? ""),
    "",
  );
}

function page(title: string, content: string): string {
  return html`<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="color-scheme" content="dark">
    <link rel="icon" href="/img/favicon.ico">
    <link rel="stylesheet" href="/css/style.css">
    <title>${title} · Lightning Login</title>
  </head>
  <body>
    <header class="site-header">
      <a class="brand" href="/" aria-label="Lightning Login home"><span aria-hidden="true">⚡</span> Lightning Login</a>
      <a class="text-link" href="/learn/">How it works</a>
    </header>
    <main class="shell">${content}</main>
    <footer class="site-footer">
      <span>No password. No payment. No wallet balance is shared.</span>
      <a href="https://github.com/lightning-login/lnurl-auth-demo">Based on the open-source demo</a>
    </footer>
  </body>
</html>`;
}

function noStoreHeaders(contentType: string): Headers {
  return new Headers({
    "Cache-Control": "no-store",
    "Content-Type": contentType,
  });
}

function htmlResponse(body: string, status = 200, extraHeaders?: HeadersInit): Response {
  const headers = noStoreHeaders("text/html; charset=utf-8");
  if (extraHeaders) {
    new Headers(extraHeaders).forEach((value, key) => headers.append(key, value));
  }
  return new Response(body, { headers, status });
}

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    headers: noStoreHeaders("application/json; charset=utf-8"),
    status,
  });
}

function redirect(location: string, cookie?: string): Response {
  const headers = noStoreHeaders("text/plain; charset=utf-8");
  headers.set("Location", location);
  if (cookie) headers.set("Set-Cookie", cookie);
  return new Response(null, { headers, status: 303 });
}

function methodNotAllowed(allowed: string): Response {
  return new Response("Method not allowed", {
    headers: {
      Allow: allowed,
      "Cache-Control": "no-store",
      "Content-Type": "text/plain; charset=utf-8",
    },
    status: 405,
  });
}

function parseCookies(request: Request): Map<string, string> {
  const cookies = new Map<string, string>();
  for (const pair of (request.headers.get("cookie") ?? "").split(";")) {
    const separator = pair.indexOf("=");
    if (separator === -1) continue;
    const name = pair.slice(0, separator).trim();
    const value = pair.slice(separator + 1).trim();
    if (name) cookies.set(name, value);
  }
  return cookies;
}

function getSessionId(request: Request): string | null {
  const sessionId = parseCookies(request).get(COOKIE_NAME);
  return sessionId && HEX_32_BYTES.test(sessionId) ? sessionId.toLowerCase() : null;
}

function sessionCookie(request: Request, sessionId: string, maxAgeSeconds: number): string {
  const secure = new URL(request.url).protocol === "https:" ? "; Secure" : "";
  return `${COOKIE_NAME}=${sessionId}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAgeSeconds}; Priority=High${secure}`;
}

function expiredSessionCookie(request: Request): string {
  return sessionCookie(request, "", 0);
}

async function getSession(request: Request, store: AuthStore): Promise<AuthSession | null> {
  const sessionId = getSessionId(request);
  if (!sessionId) return null;
  return store.get<AuthSession>(sessionKey(sessionId));
}

async function deleteSession(store: AuthStore, session: AuthSession): Promise<void> {
  await Promise.all([
    store.delete(sessionKey(session.id)),
    store.delete(challengeKey(session.k1)),
  ]);
}

async function createSession(
  store: AuthStore,
  now: number,
  randomHex: () => string,
): Promise<AuthSession> {
  const session: AuthSession = {
    createdAt: now,
    expiresAt: now + CHALLENGE_TTL_MS,
    id: randomHex(),
    k1: randomHex(),
    state: "pending",
    version: 1,
  };
  const challenge: Challenge = {
    expiresAt: session.expiresAt,
    k1: session.k1,
    sessionId: session.id,
    version: 1,
  };

  await Promise.all([
    store.setJSON(sessionKey(session.id), session),
    store.setJSON(challengeKey(session.k1), challenge),
  ]);
  return session;
}

function isExpired(session: AuthSession | Challenge, now: number): boolean {
  return session.expiresAt <= now;
}

function errorReason(reason: string, status = 400): Response {
  return jsonResponse({ reason, status: "ERROR" }, status);
}

function validateCallback(url: URL):
  | { k1: string; key: string; sig: string }
  | { error: Response } {
  const tag = url.searchParams.get("tag");
  const k1 = url.searchParams.get("k1") ?? "";
  const key = url.searchParams.get("key") ?? "";
  const sig = url.searchParams.get("sig") ?? "";

  if (tag !== "login") return { error: errorReason("Invalid LNURL-auth tag.") };
  if (!HEX_32_BYTES.test(k1)) return { error: errorReason("Invalid challenge.") };
  if (!COMPRESSED_PUBLIC_KEY.test(key)) return { error: errorReason("Invalid linking public key.") };
  if (!DER_SIGNATURE.test(sig)) return { error: errorReason("Invalid signature encoding.") };

  try {
    if (!verifySignature(sig, k1, key)) {
      return { error: errorReason("Signature verification failed.") };
    }
  } catch {
    return { error: errorReason("Signature verification failed.") };
  }

  return { k1: k1.toLowerCase(), key: key.toLowerCase(), sig: sig.toLowerCase() };
}

async function renderLogin(
  request: Request,
  session: AuthSession,
  callbackOrigin: string,
  toDataUrl: typeof QRCode.toDataURL,
): Promise<Response> {
  const callback = new URL("/auth/callback", callbackOrigin);
  callback.searchParams.set("tag", "login");
  callback.searchParams.set("k1", session.k1);
  callback.searchParams.set("action", "login");
  const encoded = encodeLnurl(callback.toString()).toUpperCase();
  const walletUri = `lightning:${encoded}`;
  const qrCode = await toDataUrl(walletUri, {
    color: { dark: "#111111", light: "#ffffff" },
    errorCorrectionLevel: "M",
    margin: 2,
    width: 320,
  });

  const body = page(
    "Scan with your wallet",
    html`<section class="login-grid">
      <div class="copy-block">
        <p class="eyebrow">LNURL-auth demo</p>
        <h1>Scan. Approve. You’re in.</h1>
        <p class="lede">Open a Lightning wallet that supports LNURL-auth and scan this one-time challenge. You will not be asked to pay.</p>
        <ol class="steps">
          <li>Scan the QR code</li>
          <li>Approve the login in your wallet</li>
          <li>This page completes automatically</li>
        </ol>
        <p id="login-status" class="status" role="status" aria-live="polite">Waiting for your wallet…</p>
      </div>
      <div class="qr-card">
        <a class="qr-link" href="${walletUri}" aria-label="Open this login request in your Lightning wallet">
          <img src="${qrCode}" width="320" height="320" alt="QR code for this Lightning login request">
        </a>
        <a class="button button-primary mobile-wallet" href="${walletUri}">Open Lightning wallet</a>
        <a class="button button-secondary" href="/">Cancel</a>
        <p class="expires">Challenge expires in 10 minutes.</p>
      </div>
    </section>
    <script src="/poll.js" defer></script>`,
  );
  return htmlResponse(body, 200, {
    "Set-Cookie": sessionCookie(request, session.id, CHALLENGE_TTL_MS / 1000),
  });
}

async function handleLogin(
  request: Request,
  store: AuthStore,
  now: number,
  randomHex: () => string,
  callbackOrigin: string,
  toDataUrl: typeof QRCode.toDataURL,
): Promise<Response> {
  if (request.method !== "GET") return methodNotAllowed("GET");

  let session = await getSession(request, store);
  if (session && isExpired(session, now)) {
    await deleteSession(store, session);
    session = null;
  }
  if (session?.state === "authenticated") return redirect("/success");
  session ??= await createSession(store, now, randomHex);
  return renderLogin(request, session, callbackOrigin, toDataUrl);
}

async function handleCallback(request: Request, store: AuthStore, now: number): Promise<Response> {
  if (request.method !== "GET") return methodNotAllowed("GET");
  const validated = validateCallback(new URL(request.url));
  if ("error" in validated) return validated.error;

  const challenge = await store.get<Challenge>(challengeKey(validated.k1));
  if (!challenge || isExpired(challenge, now)) {
    if (challenge) await store.delete(challengeKey(validated.k1));
    return errorReason("Unknown or expired challenge.", 404);
  }

  const session = await store.get<AuthSession>(sessionKey(challenge.sessionId));
  if (!session || isExpired(session, now) || session.k1 !== validated.k1) {
    await store.delete(challengeKey(validated.k1));
    return errorReason("Unknown or expired challenge.", 404);
  }

  if (
    session.state === "authenticated" &&
    session.linkingPublicKey !== validated.key
  ) {
    return errorReason("Challenge has already been used.", 409);
  }

  const authenticated: AuthSession = {
    ...session,
    expiresAt: now + AUTHENTICATED_TTL_MS,
    linkingPublicKey: validated.key,
    state: "authenticated",
  };
  await store.setJSON(sessionKey(authenticated.id), authenticated);
  return jsonResponse({ status: "OK" });
}

async function handleStatus(request: Request, store: AuthStore, now: number): Promise<Response> {
  if (request.method !== "GET") return methodNotAllowed("GET");
  const session = await getSession(request, store);
  if (!session) return jsonResponse({ status: "anonymous" });
  if (isExpired(session, now)) {
    await deleteSession(store, session);
    return jsonResponse({ status: "expired" });
  }
  return jsonResponse({ status: session.state });
}

async function handleSuccess(request: Request, store: AuthStore, now: number): Promise<Response> {
  if (request.method !== "GET") return methodNotAllowed("GET");
  const session = await getSession(request, store);
  if (!session || session.state !== "authenticated" || isExpired(session, now)) {
    if (session && isExpired(session, now)) await deleteSession(store, session);
    return redirect("/", expiredSessionCookie(request));
  }

  const key = session.linkingPublicKey ?? "";
  const body = page(
    "Login complete",
    html`<section class="success-card">
      <div class="success-mark" aria-hidden="true">✓</div>
      <p class="eyebrow">Authenticated</p>
      <h1>Lightning login complete.</h1>
      <p class="lede">Your wallet proved control of a site-specific key. No password or payment was involved.</p>
      <div class="key-card">
        <span>Wallet linking key</span>
        <code>${key}</code>
      </div>
      <div class="actions">
        <a class="button button-secondary" href="/learn/">Learn how it works</a>
        <form action="/logout" method="post">
          <button class="button button-primary" type="submit">Log out</button>
        </form>
      </div>
    </section>`,
  );
  return htmlResponse(body);
}

async function handleLogout(request: Request, store: AuthStore): Promise<Response> {
  if (request.method !== "POST") return methodNotAllowed("POST");
  const session = await getSession(request, store);
  if (session) await deleteSession(store, session);
  return redirect("/", expiredSessionCookie(request));
}

export async function handleAuthRequest(
  request: Request,
  store: AuthStore,
  options: HandlerOptions = {},
): Promise<Response> {
  const now = options.now?.() ?? Date.now();
  const randomHex = options.randomHex ?? (() => randomBytes(32).toString("hex"));
  const toDataUrl = options.toDataUrl ?? QRCode.toDataURL;
  const callbackOrigin = options.callbackOrigin ?? new URL(request.url).origin;
  const pathname = new URL(request.url).pathname.replace(/\/$/, "") || "/";

  switch (pathname) {
    case "/login":
      return handleLogin(request, store, now, randomHex, callbackOrigin, toDataUrl);
    case "/auth/callback":
      return handleCallback(request, store, now);
    case "/auth/status":
      return handleStatus(request, store, now);
    case "/success":
      return handleSuccess(request, store, now);
    case "/logout":
      return handleLogout(request, store);
    default:
      return new Response("Not found", { status: 404 });
  }
}

export function decodeLoginUrl(encoded: string): string {
  return decodeLnurl(encoded);
}
