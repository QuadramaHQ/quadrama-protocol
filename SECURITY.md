# Security Policy

## Supported versions

Only the current `main` branch is supported. The reference deployment
at `https://quadrama.ch/` tracks `main`. Older tags do not receive
back-ported security fixes.

## Reporting a vulnerability

Please report security issues **privately** to:

**quadrama.sec@outlook.com**

Please include:

- a description of the issue,
- reproduction steps,
- the potential impact, and
- an optional suggested fix.

Do **not** open a public GitHub issue for a vulnerability before a
fix is available.

We aim to acknowledge a report within a few business days. There is
no commercial bug-bounty programme; Quadrama is a private,
non-commercial open-source project. We will credit you in the release
notes unless you ask to remain anonymous.

## Scope

In scope:

- the WebSocket relay (`server.js`);
- the browser client (`public/app.js`, `public/index.html`,
  `public/i18n.js`);
- the legal pages (`public/datenschutz.html`,
  `public/impressum.html`) where they make security or privacy
  claims;
- the docs in this repository (`README.md`, `SECURITY.md`,
  `docs/TECHNICAL.md`, `docs/THREAT_MODEL.md`,
  `docs/AUDIT_SUMMARY.md`);
- the test suite (`tests/*.js`).

Out of scope:

- compromised or malicious browser extensions, browser bugs,
  device-level malware, or operating-system compromise;
- social-engineering attacks against either peer (e.g. an attacker
  who tricks a victim into reading out a fabricated Safety Code);
- the upstream `tweetnacl` and `ws` libraries themselves — please
  report those to the respective projects (if a CVE later affects
  Quadrama, a separate pinned-version notice will ship here);
- nginx, TLS, or hosting-provider configuration on third-party
  deployments;
- denial-of-service via raw network flooding upstream of the relay.

## Disclosure

We practise coordinated disclosure. Please give a reasonable window
(typically 90 days, less when a fix has shipped and been verified)
before publishing details.

## Operator hardening

The relay reads the following environment variables. None are
strictly required, but a public deployment should set the first two.

| Variable | Purpose |
|---|---|
| `QUADRAMA_ALLOWED_ORIGINS` | Comma-separated list of allowed WebSocket origins. Without it any origin can connect. |
| `QUADRAMA_TRUST_PROXY` | Set to `1` when the relay sits behind a trusted reverse proxy that overwrites `X-Real-IP` / `X-Forwarded-For`. Otherwise these headers are ignored to prevent IP spoofing. |
| `QUADRAMA_VERBOSE` | Set to `1` to emit operational logs (joins, rate-limit hits). Default is silent. |
| `QUADRAMA_MAX_CONNS_PER_IP` | Per-IP simultaneous socket cap (default `5`). |
| `QUADRAMA_MAX_JOINS_PER_MIN` | Per-IP join attempts per minute (default `10`). |
| `QUADRAMA_JOIN_WINDOW_MS` | Window length for the above (default `60000`). |
| `HOST`, `PORT` | Bind address / port (default `0.0.0.0` / `8080`). |

## Cryptographic primitives

Documented in `docs/TECHNICAL.md`. Quadrama uses Ed25519 for identity
signatures, X25519 for ephemeral key agreement, HKDF-SHA-256 for the
Double Ratchet, XSalsa20-Poly1305 for message bodies, and SHA-256 for
the Safety Code and header MAC.
