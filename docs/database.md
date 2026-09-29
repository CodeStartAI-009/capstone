# Scan history database

## Choice

**SQLite** (Python standard library `sqlite3`), one file at `DATABASE_PATH`
(default `instance/scan_history.db`, git-ignored).
- It needs no server and no extra dependency, which suits a local capstone
  deployment.
- WAL journal mode lets the dashboard read while scans are being written.
- A new connection is opened per operation, which is safe with Flask's threaded
  server.

A multi-user deployment would need a server database (for example PostgreSQL).
Only `database/` would change: the routes use `services/history_service.py`,
and all SQL is in `database/repository.py`.

## Code layout

| File | Responsibility |
|---|---|
| `database/models.py` | Schema (version 2), migrations, allowed values |
| `database/database.py` | `Database`: connections, initialisation, migrations; wraps every SQLite error in `DatabaseError` |
| `database/repository.py` | `ScanRepository`: all SQL (add, get, paginated list with filter/search, delete, clear, stats); every value is a bound parameter |
| `services/history_service.py` | `HistoryService`: builds the record from a prediction, **redacts secrets**, turns storage failures into `HistoryUnavailableError` |
| `backend/routes/history.py` | HTTP endpoints, parameter validation |

## Schema (`scan_history`, `PRAGMA user_version = 2`)

| Column | Type | Content |
|---|---|---|
| `id` | INTEGER PK AUTOINCREMENT | Scan id (never reused) |
| `scanned_at` | TEXT | ISO-8601 UTC time of the scan (same value as the API response's `scanned_at`) |
| `url` | TEXT | URL as submitted (trimmed), **redacted** |
| `normalized_url` | TEXT | Normalised URL, **redacted** |
| `host` | TEXT | Host name |
| `prediction` | TEXT, CHECK | `Safe` / `Suspicious` / `Phishing` |
| `risk_level` | TEXT, CHECK | `Low` / `Medium` / `High` |
| `confidence` | REAL | Model probability for the reported side of the threshold |
| `phishing_probability` | REAL | Model P(phishing) |
| `model_version` | TEXT | e.g. `2.0.0` (from `model_metadata.json`) |
| `processing_ms` | REAL | Server-side extraction + inference time |
| `source` | TEXT, CHECK | `web` / `extension` / `api` |
| `features` | TEXT (JSON) | The 17 model input values |
| `indicators` | TEXT (JSON) | The explanation items shown to the user: severity, source, feature/check, message |

Indexes cover `scanned_at` and `prediction`.

Migrations: a version-1 database from the first release (columns up to
`source`) is upgraded in place on start-up with `ALTER TABLE … ADD COLUMN`. Old
rows keep NULL in the new columns. This is covered by
`tests/test_database.py::test_v1_database_is_migrated_in_place`.

## History lifecycle

1. `POST /api/predict` validates the URL, runs the predictor and builds the
   response.
2. Unless the request has `"record": false`, `HistoryService.record()` redacts
   the URLs and inserts one row. Every scan gets its own row, so scanning the
   same URL twice creates two rows.
3. The response includes `"history": {"saved": true, "id": 42}`. If the
   database fails, the prediction is still returned (HTTP 200) with
   `"history": {"saved": false}`. The cause is logged on the server and never
   sent to the client.
4. Rows are listed, viewed and deleted through the endpoints below. There is no
   automatic expiry; `DELETE /api/history` clears everything.

If the database can't be opened at start-up (e.g. an unwritable path), the API
still starts and predicts. History endpoints return 503 `HISTORY_UNAVAILABLE`,
and initialisation is retried on each call.

## Endpoints

| Method and path | Result |
|---|---|
| `GET /api/history?page=1&limit=20&prediction=Phishing&q=paypal` | `{"success", "items", "page", "limit", "total", "pages"}`, newest first. `limit` 1–100 (`HISTORY_LIMIT`); `page` ≥ 1; `prediction` ∈ Safe/Suspicious/Phishing; `q` (≤ 200 chars) matches URL or host literally (LIKE wildcards are escaped). Items are summaries, without `features`/`indicators`. |
| `GET /api/history/<id>` | `{"success": true, "item": {...all columns...}}` |
| `DELETE /api/history/<id>` | `{"success": true, "deleted": 1}` |
| `DELETE /api/history` | `{"success": true, "deleted": <n>}` |
| `GET /api/stats?days=30` | Totals by prediction, risk level and source; first/last scan time; `daily` counts per prediction for the last `days` (1–365) days, used by the dashboard charts |

| Error | When |
|---|---|
| 400 `INVALID_PARAMETER` | Bad `page`, `limit`, `prediction`, `q` or `days` |
| 400 `INVALID_ID` | Id not a positive integer (e.g. `abc`, `0`, `1.5`, `1 OR 1=1`) |
| 404 `SCAN_NOT_FOUND` | No row with that id |
| 503 `HISTORY_UNAVAILABLE` | Database cannot be read or written |

There is no authentication. Anyone who can reach the API can read and clear the
history, which is acceptable for the intended single-user local deployment.
Cross-site pages can't call these endpoints from a browser: `DELETE` requires a
CORS preflight, which is refused for origins not in `CLIENT_ORIGIN`. A shared
deployment would need authentication first.

## Privacy

- **Never stored:** IP addresses, user agents, request headers, cookies, page
  contents (pages are never fetched), or the raw request body.
- **Redaction before storage.** Scanned URLs can contain secrets such as reset
  tokens, session ids, or a victim's e-mail address in a phishing link, so
  `redact_url()` applies these rules:

  | Part | Example input | Stored as |
  |---|---|---|
  | Userinfo password | `https://user:pw@host/` | `https://user@host/` |
  | Query values | `?token=abc&email=a@b.c` | `?token=[redacted]&email=[redacted]` |
  | Fragment | `#…` | dropped |

  The API response still shows the URL as submitted. A test scans a URL
  containing a password and a token and checks that neither appears in the
  database file.
- **Residual risk:** URL *paths* are stored unchanged, and a few sites put
  tokens in the path.
- **Extension:** it sends `"record": true` only for scans the user starts. It
  has no automatic background scanning (see `docs/extension.md`).
- **Retention:** the history is a local file, and the user can delete single
  scans or clear everything from the dashboard.
