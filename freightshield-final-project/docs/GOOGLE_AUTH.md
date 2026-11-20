# Google sign-in, self-sign-up and MFA

## What changed
| Item | Detail |
|---|---|
| New endpoint (additive) | `POST /api/auth/google/signup` with body `{"credential": "<Google ID token>"}`. Response is the same shape as `/api/auth/google` (profile + `csrf_token`) and sets the same httpOnly session and CSRF cookies. |
| Existing `POST /api/auth/google` | Unchanged: sign-in only, still returns 403 for an unregistered or disabled email. |
| `GET /api/auth/status` | Unchanged. |
| New env var | `SELF_SIGNUP_ENABLED` (default `true`). `false` makes the signup endpoint return 403 (invite-only); the login page then shows that message when someone tries to create an account. |
| Frontend | The login screen gets a "Sign in / Create account" toggle; it uses the existing Google Identity Services button and sends the ID token to the matching endpoint. |

## Security properties
- The backend verifies the Google ID token (signature via Google's JWKS, issuer, audience = `GOOGLE_CLIENT_ID`, expiry, verified email). The browser's claimed email, user ID or role is never used. Extra JSON fields such as `role` are ignored.
- Self-registered accounts always get the `user` role (a constant in `routes/auth.py`, not configurable and not client-supplied). That role has no security-data permissions. Admin and Vendor accounts are still created only by an administrator (`/api/users`, `python -m app.cli`); vendor agent assignment is unchanged.
- Signup never modifies an existing account (409 if the email exists), so it cannot be used to escalate or take over Admin/Vendor accounts.
- Sessions are unchanged: httpOnly cookie, `SameSite`/`Secure` per `APP_ENV`, server-side revocation on logout, role read from the database on every request, CSRF double-submit on state-changing calls, per-IP rate limit on `/api/auth/google*`.
- `/api/auth/google/signup` is CSRF-exempt for the same reason `/api/auth/google` is: there is no session yet and the Google credential cannot be forged cross-site. All other state-changing routes still require the CSRF token.
- Signups, denials and logins are written to the audit log (`signup` action).
- No Google tokens are stored in the browser or database; the ID token is used once and discarded.

## Configuration (where each value goes)
| Value | Where | Secret? |
|---|---|---|
| `VITE_GOOGLE_CLIENT_ID` | root `.env` (frontend) | No, public |
| `GOOGLE_CLIENT_ID` | `backend/.env` | No, public. Same value as above |
| `AUTH_JWT_SECRET` | `backend/.env` | **Yes**, 32+ random chars. Generate locally: `python -c "import secrets; print(secrets.token_urlsafe(48))"` |
| Google **Client Secret** | **Not used** | The ID-token (Google Identity Services) flow needs only the Client ID. Do not add the secret anywhere. If a Client Secret was ever pasted into chat, email, or a ticket, rotate it in Google Cloud Console (APIs & Services > Credentials). |

In Google Cloud Console, create an OAuth client of type **Web application** and add:
- **Authorized JavaScript origins**: `http://localhost:5173`, `http://127.0.0.1:5173` (and your production HTTPS origin). If you use another dev port, add it too, and add the same origins to `CORS_ALLOWED_ORIGINS` in `backend/.env`.
- Authorized redirect URIs are **not needed** for this flow.
- Configure the OAuth consent screen. While it is in "Testing" mode only listed test users can sign in; publish it for general self-sign-up.

## Run locally
Windows PowerShell:
```powershell
# backend
cd backend
python -m venv .venv; .\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env   # then edit GOOGLE_CLIENT_ID and AUTH_JWT_SECRET
uvicorn app.main:app --reload --port 8000
# frontend (new terminal, project root)
Copy-Item .env.example .env   # then edit VITE_GOOGLE_CLIENT_ID
npm install; npm run dev
```
Linux/macOS:
```bash
cd backend && python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env   # edit GOOGLE_CLIENT_ID and AUTH_JWT_SECRET
uvicorn app.main:app --reload --port 8000
# new terminal, project root
cp .env.example .env   # edit VITE_GOOGLE_CLIENT_ID
npm install && npm run dev
```
Tests: `cd backend && pip install -r requirements-dev.txt && python -m pytest`; frontend: `npm test`.

## Multi-factor authentication: what this does and does not do
- **FreightShield does not implement or enforce its own MFA.** There is no second-factor flow in the app.
- With Google Sign-In, whether a user is asked for 2-Step Verification, a passkey or a security key is decided by Google (and, for managed accounts, by the organisation's Google Workspace policies). The ID token does not let this app force, or reliably prove, that a given sign-in used a second factor, so the app cannot universally enforce Google-account MFA.
- Accounts that self-register with a personal Google account are protected only by whatever that user has set up with Google.
- **To require MFA for a Workspace organisation** (admin.google.com, as a Super Admin): Security > Authentication > 2-step verification > turn on "Allow users to turn on 2-Step Verification", then set **Enforcement** to "On" (optionally with a new-user enrolment period) for the relevant organisational units or groups; consider "Allow only security keys" or passkeys for administrators. Also review Security > Authentication > Login challenges.
- **To limit sign-in to your organisation:** because the app accepts any verified Google account when `SELF_SIGNUP_ENABLED=true`, and Workspace policies only cover your own users, set `SELF_SIGNUP_ENABLED=false` (invite-only) if you rely on Workspace MFA to protect access, and register accounts via an administrator. Restricting the OAuth consent screen to "Internal" (Workspace only) also confines sign-in to your domain.
- A separate in-app second factor (e.g. TOTP) would be a distinct feature and is not included.
