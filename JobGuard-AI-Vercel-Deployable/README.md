# JobGuard AI

**Before You Trust the Offer, Verify the Evidence.**

JobGuard AI is an evidence-oriented recruitment-fraud verification application built with React/TypeScript/Vite and FastAPI/SQLite.

## Project layout

Run commands from the directory containing `backend/`, `frontend/`, `tests/`, and `README.md`.

- `backend/` — FastAPI API, SQLite authentication, document analysis, URL inspection, and fraud engines.
- `frontend/` — React, TypeScript, Tailwind CSS, and Vite application.
- `tests/` — Backend unittest suite and 112-case benchmark.
- `supabase/schema.sql` — Optional PostgreSQL report schema with RLS.

## Backend setup

Python 3.11 is required.

```bash
cd /path/to/jobguard-ai
python -m pip install -r backend/requirements.txt
python -m uvicorn backend.main:app --host 0.0.0.0 --port 8000
```

Open `http://localhost:8000`. API documentation is available at `http://localhost:8000/docs`.

## Frontend development

Node.js 20.19 or newer is required.

```bash
cd /path/to/jobguard-ai/frontend
npm ci
npm run dev
```

The Vite development server runs on `http://localhost:5173` by default.

## Frontend production build

```bash
cd /path/to/jobguard-ai/frontend
npm ci
npm run build
```

The build creates `frontend/dist/` and the FastAPI application serves that bundle at `/`.

## Tests

Run backend tests from the project root:

```bash
python -m unittest discover -s tests -v
python -m compileall backend
```

Run frontend tests from the project root or frontend directory:

```bash
cd /path/to/jobguard-ai/frontend
npm ci
npm run build
cd ..
node --test tests/test_frontend.mjs
```

## Environment variables

Copy `.env.example` to `.env` for local overrides. A real `.env` is never required for the core local analysis.

| Variable | Purpose |
|---|---|
| `CORS_ORIGINS` | Comma-separated trusted origins. Required explicitly in production. |
| `ENVIRONMENT` | Set to `production` on HTTPS deployments. |
| `COOKIE_SECURE` | Set to `true` for secure HTTPS cookies. |
| `APP_BASE_URL` | Public application URL used in account email links. |
| `SMTP_HOST` | SMTP server host. |
| `SMTP_PORT` | SMTP server port. Default: `587`. |
| `SMTP_USERNAME` | Optional SMTP login. |
| `SMTP_PASSWORD` | Optional SMTP password. |
| `SMTP_FROM` | Sender address. |
| `SMTP_USE_SSL` | Use SMTP over SSL instead of STARTTLS. |
| `ENABLE_*_CHECK` | Optional environment-gated external verification provider flags. |
| `OPENCORPORATES_API_KEY`, `GOOGLE_SAFE_BROWSING_API_KEY`, `VIRUSTOTAL_API_KEY` | Optional provider credentials. |

Never commit `.env`, API keys, SMTP passwords, access tokens, or the local SQLite database.

## Authentication and email recovery

SQLite authentication is local and works without Supabase. Password reset and email verification messages are sent only when `APP_BASE_URL`, `SMTP_HOST`, and `SMTP_FROM` are configured. If SMTP is unavailable, the API reports that recovery is unavailable and does not expose a private token.

## Docker

```bash
cd /path/to/jobguard-ai
# Copy and edit configuration if needed:
cp .env.example .env
docker compose up --build
```

Docker availability and `.env` support vary by environment. The application exposes port `8000`.

## ZIP and Python-host deployment

The submission ZIP places the project files at the archive root. Extract it, then use the root `requirements.txt` to install dependencies. The `Procfile` starts the API on the host-provided `PORT` (or `8000` locally); the included production frontend bundle is served by FastAPI.

```bash
python -m pip install -r requirements.txt
uvicorn backend.main:app --host 0.0.0.0 --port "${PORT:-8000}"
```

Set deployment-specific environment variables in the hosting service rather than adding secrets to the ZIP.

## Optional services

- External employer and threat-intelligence providers are disabled unless explicitly configured.
- The core 112-case benchmark runs locally without credentials.
- Supabase is optional and uses `supabase/schema.sql`; it is not required for SQLite authentication or local verification.
- SMTP is optional. Password recovery is unavailable until a valid SMTP configuration is provided.

## Transparency limitations

- The 0–100 risk index is an explainable heuristic, not a calibrated fraud probability.
- Unknown employers are marked Unverified, not fraudulent.
- External providers remain unavailable or honestly limited when credentials/network access are absent.


## Deploy to Vercel (single-project deployment)

This repository is pre-configured for single-project deployment on Vercel with `vercel.json` and `api/index.py`:

- **Frontend (Vercel CDN):** `vercel.json` builds the Vite + React app (`frontend/`) and serves `frontend/dist` directly from Vercel's CDN with SPA routing and immutable asset caching.
- **Backend (Vercel Python Serverless Function):** `api/index.py` exports the FastAPI ASGI application (`backend.main:app`) and `vercel.json` rewrites `/api/*`, `/docs`, `/redoc`, and `/openapi.json` to `/api/index.py`.
- **Automatic Vercel Origin & HTTPS Support:** When `VERCEL=1`, the backend automatically allows `VERCEL_URL`, `VERCEL_BRANCH_URL`, and `VERCEL_PROJECT_PRODUCTION_URL`, respects `X-Forwarded-Proto`/`X-Forwarded-Host` proxy headers, defaults cookies to `Secure=true`, and lazily initializes `/tmp/jobguard.db` on cold starts.

### Deployment steps

1. Push this project to GitHub/GitLab/Bitbucket (or run `npx vercel --prod` from the project root).
2. Import the repository at [vercel.com/new](https://vercel.com/new) with **Root Directory** set to `.` (the folder containing `vercel.json`, `api/`, `backend/`, `frontend/`, and `requirements.txt`).
3. Leave Build Command and Output Directory on their defaults — `vercel.json` configures them automatically.
4. Optionally add environment variables in Vercel Project Settings:
   - `ENVIRONMENT=production`
   - `CORS_ORIGINS` (only needed if you attach a custom domain beyond Vercel's built-in URLs)
   - `APP_BASE_URL` (optional; defaults to `VERCEL_PROJECT_PRODUCTION_URL` / `VERCEL_URL`)
   - Optional provider/AI/SMTP keys (`GEMINI_API_KEY`, `OPENAI_API_KEY`, `SMTP_*`, etc.)
5. Click **Deploy**.

### Important Vercel serverless notes

- **Database persistence:** Vercel Functions have a read-only bundle filesystem and ephemeral `/tmp` storage. When `VERCEL=1`, SQLite uses `/tmp/jobguard.db` so auth and saved reports work without crashing, but data in `/tmp` is not durable across cold starts or instances. For persistent production accounts and saved reports, connect an external database (e.g., Supabase/PostgreSQL).
- **Upload payload limit:** Vercel Serverless Functions enforce a 4.5 MB request body limit on `/api/extract/document` and `/api/call/analyze`.
