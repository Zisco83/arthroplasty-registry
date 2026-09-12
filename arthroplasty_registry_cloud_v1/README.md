# Arthroplasty Registry — Cloud-ready v1.0

This package upgrades the supplied browser prototype into a server-backed web application. The existing UI is retained; registry records, authentication, audit events and uploaded radiographs are stored on the server/cloud, not browser `localStorage`.

## Architecture

Browser → HTTPS → FastAPI → PostgreSQL

- Existing HTML/JS registry UI retained.
- PostgreSQL is the system of record.
- `registry_records.record` uses JSONB to preserve the existing nested web record model and avoid a destructive rewrite.
- Users, audit logs and images are relational tables.
- Passwords are Argon2 hashes.
- Authentication is an HttpOnly signed session cookie.
- Admin-only deletion and user management endpoints are included.
- `/healthz` is available for cloud health checks.

## Important clinical-data warning

This is a deployment-ready engineering baseline, **not a validated clinical information system**. Before entering identifiable patient data, complete your institution's data-protection/privacy review, access-control review, backup/restore test, retention policy, incident-response plan, and any required ethics/regulatory approvals. For larger deployments, move images from PostgreSQL BYTEA to encrypted object storage and add field-level audit/versioning.

## Local test with PostgreSQL

1. Install Docker Desktop.
2. Start PostgreSQL:

```bash
docker run --name arthroplasty-postgres -e POSTGRES_USER=registry -e POSTGRES_PASSWORD=change-me -e POSTGRES_DB=arthroplasty_registry -p 5432:5432 -d postgres:16
```

3. Copy `.env.example` to `.env` and set `DATABASE_URL` to:

`postgresql+psycopg://registry:change-me@localhost:5432/arthroplasty_registry`

4. Build/run:

```bash
docker build -t arthroplasty-registry .
docker run --env-file .env -p 8000:8000 arthroplasty-registry
```

Open `http://localhost:8000`.

## Deploy on Render

The included `render.yaml` defines the web service. Create a managed PostgreSQL database in Render, copy its internal connection string into `DATABASE_URL`, and set a strong `BOOTSTRAP_ADMIN_PASSWORD`. Deploy the repository containing this folder.

Set `COOKIE_SECURE=true` in HTTPS production.

## Other cloud hosts

The Dockerfile is portable to Railway, Fly.io, Azure Container Apps, Google Cloud Run, AWS App Runner/ECS, or a VPS. The only required runtime secrets are `DATABASE_URL` and `SECRET_KEY`, plus the bootstrap administrator credentials for first startup.

## Database migration

`db/migrations/001_initial.sql` creates:

- `users`
- `registry_records`
- `images`
- `audit_log`

The migration is automatically applied at startup. The schema intentionally keeps the existing UI's nested record object in PostgreSQL JSONB. This makes the first cloud migration low-risk. A later v2 can normalize clinical domains into patient/procedure/pre-op/intra-op/follow-up/implant tables without changing the public UI/API contract.

## User management

After first login, administrators can use the API endpoints to create users. A dedicated admin UI can be added in the next hardening iteration.

## No browser database

The cloud version explicitly removes the prototype's localStorage storage adapter. All patient record saves, reads, deletes, activity retrieval and imaging operations call the server API.
