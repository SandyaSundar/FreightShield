# FreightShield — Phase 10 Security Hardening

## What is enforced
| Area | Control |
|---|---|
| JWT | HS256 pinned (no `none`/alg confusion); required `iss`, `aud`, `iat`, `nbf`, `exp`, `jti`, `sub`; 10 s leeway; tokens > 4 KB rejected; TTL clamped to 5–720 min; secret ≥ 32 chars (app refuses to start in production otherwise). |
| Sessions | Role/active flag read from the DB on every request; logout revokes the token's `jti` server-side (`revoked_tokens`), so a stolen cookie dies at logout. |
| Cookies | `fs_session` + `fs_csrf` are `HttpOnly`, `Path=/api`; production: `Secure; SameSite=None` (cross-site SPA), dev: `SameSite=Lax`. Logout deletes with matching attributes. |
| CSRF | Double-submit token: returned in `/auth/google` and `/auth/me` body, kept in SPA memory, sent as `X-CSRF-Token`, compared in constant time with the cookie. Unsafe cookie requests from an Origin not in `CORS_ALLOWED_ORIGINS` are rejected. Bearer-authenticated clients are exempt. |
| Rate limiting | Per-IP sliding window: sign-in 10/min, AI 20/min, all other API 300/min (`/api/health` exempt); 429 + `Retry-After`. |
| Input validation | Pydantic schemas on all bodies/params; body cap 1 MB (413); URL cap 2048 (414); validation errors never echo submitted values. |
| Headers | `nosniff`, `X-Frame-Options: DENY`, strict API CSP, `Referrer-Policy: no-referrer`, `Permissions-Policy`, COOP, `Cache-Control: no-store`, HSTS in production. Frontend ships a CSP meta tag. |
| CORS | Explicit origins only (`*` is stripped), explicit methods/headers. |
| Secrets | Server-side env only; none returned by any endpoint (tested); OpenAPI/docs disabled in production; unhandled errors return a generic message. |

## New settings (all optional)
`AUTH_JWT_ISSUER`, `AUTH_JWT_AUDIENCE`, `CSRF_COOKIE_NAME`, `RATE_LIMIT_ENABLED`, `RATE_LIMIT_PER_MINUTE`,
`RATE_LIMIT_AUTH_PER_MINUTE`, `RATE_LIMIT_AI_PER_MINUTE`, `MAX_BODY_BYTES`, `TRUST_PROXY` (set `true` only behind a
reverse proxy you control, so rate limits and audit IPs use `X-Forwarded-For`).

## Upgrade note
Sessions issued before Phase 10 lack the new claims, so every user signs in once again after deploy.

## Remaining risks (not fixed in code)
1. Rate limiter and revocation list are per process — use Redis/shared store if you run several workers/instances.
2. `connect-src` in the frontend CSP allows any `https:` origin because the API URL is configured at runtime; pin it to your API host when deploying.
3. The uploaded Phase 9 archive contained `data/freightshield.db` (live data incl. user emails and audit logs). It is excluded from this package; do not ship or commit it.
4. HS256 uses one shared secret: rotate `AUTH_JWT_SECRET` if ever exposed (this signs everyone out).
5. Optional AI agents (`requirements-ai.txt`, crewai) were not dependency-audited here; audit them before enabling.
6. FreightShield has no app-enforced MFA. Google (and Workspace policy for managed accounts) controls 2-Step Verification; enforce it in Google Workspace for admins, and use `SELF_SIGNUP_ENABLED=false` if you depend on Workspace policy. See `docs/GOOGLE_AUTH.md`.
7. Self-sign-up (`/api/auth/google/signup`) creates only the permission-less `user` role; Admin/Vendor are admin-provisioned.
