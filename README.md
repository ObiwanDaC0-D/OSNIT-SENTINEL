# Sentinel — OSINT Research Lab

Local-first FastAPI/SQLite research notebook in **OSNIT-SENTINEL**. For self-audits, explicitly authorized audits, public professional publications, and domain research. No private-person dossiers, sensitive personal data aggregation, identity inference, account-registration probing, or leaked-data collection.

## Run locally

Python 3.12+ recommended. From the repository directory:

```sh
python3.12 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python -m sentinel
```

Open http://127.0.0.1:8765. The UI and assets run locally without CDNs, telemetry, or cloud deployment. Stop with Ctrl+C.

## Workflow

1. Create a case describing its purpose and authorization.
2. Research a username (authorized audit cases only), professional name, publication, or domain. Confirm disclosure before submitting a query.
3. Review sources and enter cited evidence, excerpts, event dates, and a verification rationale. A matching name/username is not proof of identity.
4. Connect two evidence records with an explicit relationship and rationale. Explore the interactive graph and chronological timeline; undated records follow dated ones.
5. Export a JSON report locally or delete the case and its records.

## Implemented capabilities and honest limits

- GitHub username existence adapter: timeout, no redirect following, explicit unavailable/rate-limit errors; collects no profile details. Candidates require review before saving.
- Professional and document research: automatically retrieves up to 10 Crossref publication metadata matches per query. Name searches are candidate author matches, not identity confirmation.
- Domain research: concurrently retrieves A, AAAA, MX, NS, and CAA answers through Google Public DNS. No active scanning or contact-detail collection.
- Findings are automatically saved as unverified evidence with source citations and check timestamps. Publication/DNS repeats reuse matching source/title records; changed records should be reviewed separately. Username checks currently add a new dated observation each run.
- Source status distinguishes publicly accessible metadata, access restricted (401/403), and availability unconfirmed (errors/rate limits). It does not claim to know whether linked full text is publicly available. Restricted endpoints are skipped without bypass attempts.
- Email exposure: **provider-hosted verification handoff** to Have I Been Pwned. Complete the provider's email verification/notification flow for an address you control, then manually record a minimal audit conclusion. Sentinel does not itself verify ownership, query breach APIs, or accept/store an email address. A checkbox is not ownership verification.
- Document evidence: manually supplied public citations and text excerpts. No file upload, PDF extraction, OCR, or metadata extraction.
- Cases, evidence classifications, capture timestamps, SHA-256 record fingerprints, relationship rationales, JSON reports, deletion, and persistent SQLite storage.
- The SHA-256 value fingerprints the submitted evidence fields; it does not certify the source, preserve a remote page, or provide a tamper-proof audit trail.
- Optional Ollama, Sherlock, broad multi-provider scanning, concurrent job queues, and broad web crawling are not included. The relationship view uses local SVG rather than Cytoscape to avoid an extra dependency.

## Data protection

The default database is `~/.local/share/sentinel/cases.sqlite3`, **outside the checkout**, with mode 0600. Set `SENTINEL_DB` to an absolute private path if needed. Keep it outside cloud-synced folders and source control. The database is not encrypted; use device encryption and private backups. Deletion removes application records but is not forensic secure erasure of SQLite pages or backups.

The supported launcher binds to loopback only and disables access logs. The app rejects remote clients, untrusted Host values, cross-origin requests, and mutations missing a custom request header. It uses a restrictive content security policy, no-store responses, escaped DOM text, parameterized SQL, and same-case relationship validation. No arbitrary user URL is fetched server-side. This is a single-user desktop service, not a multi-user authenticated server: do not deploy it, bind it publicly, or place it behind a proxy. Other programs running as your local user can access it.

External links and username queries disclose research inputs to the selected providers. Source pages may contain personal information; record only authorized, relevant, non-sensitive evidence. Exports contain private case data. Do not commit them. `.gitignore` excludes databases, credentials, exports, logs, and runtime folders; it is a guardrail, not a substitute for reviewing staged files. No credentials are needed for the included adapter.

## Tests

```sh
.venv/bin/python -m pytest -q
```

Tests use temporary databases and mocked provider responses, with synthetic `example.org` citations. They cover persistence, exports, deletion, case isolation, record hashes, input validation, verification rationale, local request protections, authorized scope, and provider failure handling. They never submit real email addresses or case data to providers.

## Architecture

`sentinel/app.py`: API factory, validation, SQLite transactions, research adapter and source handoffs. `sentinel/static/`: responsive, dependency-free UI. `sentinel/__main__.py`: supported local launcher. `tests/`: functional/security regression checks. Provider handoffs return leads distinct from evidence. Automatic identity correlation is intentionally absent.

Provider specifications: https://www.crossref.org/documentation/retrieve-metadata/rest-api and https://developers.google.com/speed/public-dns/docs/doh/json .
