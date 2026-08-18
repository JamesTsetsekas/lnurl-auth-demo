# Lightning Login

A small, production-hosted [LNURL-auth](https://github.com/lnurl/luds/blob/luds/04.md) demo. Scan a one-time QR code with a compatible Lightning wallet, approve the login, and authenticate without a password or payment.

This is a Netlify-native modernization of the original [`lightning-login/lnurl-auth-demo`](https://github.com/lightning-login/lnurl-auth-demo). Its MIT license and history are preserved.

## How it is built

- Static HTML, CSS, and browser polling in `public/`
- A modern Netlify Function for challenge creation, wallet callbacks, status, success, and logout
- Strong-consistency Netlify Blobs for site-scoped, expiring session state
- Pure JavaScript secp256k1 verification with `@noble/curves`
- Node.js 22.12 or newer

The browser receives a random, HttpOnly session cookie that is not encoded in the QR. The wallet sees only the public, one-time `k1` challenge. Login challenges expire after ten minutes; authenticated demo sessions expire after one hour.

This is intentionally a demo, not a drop-in account system. Netlify Blobs does not provide transactional compare-and-swap, so a production identity system that needs strict single-consumer semantics should use a transactional database or atomic key-value store.

## Local development

```bash
npm install
npm test
npm run typecheck
npx netlify dev
```

Netlify Dev provides the local Blobs sandbox and Functions runtime. A real wallet test needs a public HTTPS URL, so use a Netlify deploy preview for the final scan.

## Deploy

Link the checkout to the existing Netlify site once, then deploy a preview before production:

```bash
npx netlify link --id cb5df8e2-8616-4dc6-aef3-6ac0a76ce8fe
npx netlify deploy --build
npx netlify deploy --build --prod
```

The production hostname is `https://lightninglogin.netlify.app`. Wallet linking keys are hostname-specific, so treat that as the canonical demo URL.

## Security and privacy notes

- The callback verifies a DER-encoded secp256k1 signature over the raw 32-byte `k1`.
- Challenge, callback, polling, success, and logout responses are not cached.
- Session cookies are HttpOnly, SameSite=Lax, and Secure on HTTPS.
- The app does not log or send linking keys to analytics or third-party avatar services.
- No invoice is created and no wallet balance or payment history is requested.
