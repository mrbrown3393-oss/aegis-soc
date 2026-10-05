# Getting Started

These steps start the backend and the React development server. Use a separate local database because startup creates synthetic training records.

## Prerequisites

- Git and Python 3.11 or later.
- A running MongoDB instance; the existing project setup specifies MongoDB 6 or later.
- Node.js and npm for the React client.
- A TOTP authenticator for first sign-in; MFA is enabled by default.

## 1. Get the project and Python environment

~~~bash
git clone https://github.com/mrbrown3393-oss/aegis-soc.git
cd aegis-soc
python3 -m venv .venv
source .venv/bin/activate
cd backend
python -m pip install -r requirements.txt
cp .env.example .env
~~~

The backend reads `.env` from the current working directory. Run it from `backend/`.

## 2. Configure the local environment

Edit `backend/.env`. For a local MongoDB instance without TLS, use:

~~~dotenv
AEGIS_ENV=development
MONGO_URL=mongodb://127.0.0.1:27017
DB_NAME=aegis_soc_local
MONGO_TLS=false
MONGO_TLS_ALLOW_INVALID_CERTS=false
FRONTEND_URL=http://localhost:5173
CORS_ORIGINS=http://localhost:5173
SSO_BASE_URL=http://localhost:3000
MFA_REQUIRED=true
~~~

Set `ADMIN_EMAIL`, `ADMIN_PASSWORD`, `ANALYST_EMAIL`, and `ANALYST_PASSWORD` to your own account details. Choose distinct passwords of 12–72 UTF-8 bytes. Set independent, random `JWT_SECRET` and `MFA_MASTER_SECRET` values. To generate one secret locally:

~~~bash
python -c "import secrets; print(secrets.token_hex(32))"
~~~

Run that command separately for each secret and keep the values in your private configuration. Do not publish passwords, MFA setup secrets, or cookie files in the wiki or repository.

`MONGO_TLS=false` is only for an isolated development database. Production requires TLS and valid certificates; see [Deployment](Deployment.md).

## 3. Start the API

~~~bash
uvicorn server:app --host 127.0.0.1 --port 3000 --reload
~~~

Port 3000 matches the API proxy currently configured in `client/vite.config.ts`. The older README uses port 8001; if you choose that port, also change the client's API proxy target.

Check the API:

~~~bash
curl --fail http://localhost:3000/api/
~~~

Expected JSON:

~~~json
{"status":"ok","service":"aegis-soc-api","version":"2.2.0"}
~~~

In development, the app configures `/docs` and `/redoc`; the schema is at `/openapi.json`. Production disables the interactive documentation routes.

## 4. Start the client

In a second terminal, from the repository root:

~~~bash
cd client
npm install
npm run dev
~~~

Open [http://localhost:5173](http://localhost:5173). The client server proxies `/api` to `http://localhost:3000`.

The current client expects several routes and response shapes that differ from the backend. Starting both processes does not resolve those differences; use the concrete mappings on [Troubleshooting](Troubleshooting.md) before treating the console as integrated.

## 5. Complete first sign-in

| Step | Request | Result |
| --- | --- | --- |
| Password sign-in | `POST /api/auth/login` with `email` and `password` | With MFA enabled, a pending MFA cookie and `mfaRequired: true` |
| First-time enrollment | `GET /api/auth/mfa/setup` using the pending cookie | TOTP secret and `otpauth` enrollment URI |
| Complete MFA | `POST /api/auth/mfa/verify` with `{"code":"CURRENT_TOTP_CODE"}` and the pending cookie | Access and refresh cookies; account summary |
| Verify session | `GET /api/auth/me` using the access cookie | Current user object |
| Privileged action | `POST /api/auth/step-up` with a fresh TOTP code | A session-bound step-up cookie, valid for 10 minutes |

Keep the same browser/device headers throughout a session. Authenticated mutations must carry an `Origin` or `Referer` matching a configured frontend origin. Command-line clients must retain cookies and include that origin too.

The bootstrap account created from `ADMIN_EMAIL` has the `owner` role. The analyst account belongs to the `private` tenant. Existing accounts are not recreated when you change bootstrap environment variables.

## Training data

The initial seeder creates 2 users, 120 threats, 36 vulnerabilities, 24 incidents, 60 assets, 21 compliance records, and 80 synthetic audit rows when its startup conditions are met. It skips user seeding when users exist and skips demo seeding when threats exist.

For a fresh training environment, choose a new `DB_NAME`. Do not reset a working database to refresh training records.

Sources: [config.py](https://github.com/mrbrown3393-oss/aegis-soc/blob/main/backend/config.py), [seed.py](https://github.com/mrbrown3393-oss/aegis-soc/blob/main/backend/seed.py), [auth.py](https://github.com/mrbrown3393-oss/aegis-soc/blob/main/backend/routers/auth.py), [Vite configuration](https://github.com/mrbrown3393-oss/aegis-soc/blob/main/client/vite.config.ts).
