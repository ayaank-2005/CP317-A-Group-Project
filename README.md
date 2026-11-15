# CP317-A-Group-Project

ScamShield: check suspicious messages, browse a public database of reported
scams, report new ones and track their review status.

## Running locally

Requirements: Go 1.22+ and PostgreSQL 14+ (with the `pgcrypto` and `pg_trgm`
extensions, included in the standard `postgresql-contrib` package).

```bash
# 1. Create the database, its schema and the demo accounts
createdb scamshield
psql -d scamshield -v ON_ERROR_STOP=1 -f ScamShield_DB.sql
psql -d scamshield -v ON_ERROR_STOP=1 -f dev_seed.sql

# 2. Start the server (serves the site and the /api endpoints)
DATABASE_URL="postgres://localhost/scamshield" go run ./cmd/scamshield

# 3. Open http://localhost:8080
```

Demo accounts (from `dev_seed.sql`, development only):

| Email               | Password      | Role      |
| ------------------- | ------------- | --------- |
| `alice@example.com` | `password123` | user      |
| `mod@example.com`   | `password123` | moderator |

Try it: sign in as Alice and submit a few reports, then sign in as the
moderator and approve, reject or merge them from **Moderate**. Alice's
**My Reports** page shows each report's status, and Approved and Merged
reports link to the public report in the Database.

Server options: `-addr` / `ADDR` (default `:8080`), `-static` / `STATIC_DIR`
(default `.`, the folder holding `index.html`), `-secure-cookies` /
`SECURE_COOKIES=1` when served over HTTPS.

## Tests

```bash
go test ./internal/...
```

The API tests in `internal/server` need a Postgres server where they can
create a throwaway database; they are skipped unless `TEST_DATABASE_URL` is
set, for example:

```bash
TEST_DATABASE_URL="postgres://localhost/postgres" go test ./internal/...
```

## Layout

- `index.html`, `*.js`, `*.css`: the single-page site (hash routes such as `#database`, `#my-reports`)
- `cmd/scamshield`: the web server
- `internal/server`: JSON API (auth, reports, My Reports, moderation)
- `internal/reportstatus`: report IDs and the Pending / Approved / Rejected / Merged rules
- `internal/redact`: masks personal details in submitted reports
- `ScamShield_DB.sql`: database schema; `dev_seed.sql`: local demo accounts
