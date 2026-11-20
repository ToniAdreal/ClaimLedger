# ClaimLedger

Evidence before confidence. A small, human-led review desk for technical claims in reports.

## Two builds, not one export

This package is an independent Python/SQLite reference implementation. A separate Momen prototype uses the same product concept, but this code was not exported from Momen and does not connect to its database. Neither build automatically verifies facts. No LLM, paid API, email or SMS is integrated.

## Run locally

Requires Python 3.10 or later. The application uses only the standard library.

```sh
python3 app.py
```

Open http://127.0.0.1:8080. Choose a username of 3-40 letters, numbers, underscores, dots or hyphens and a password of at least 12 characters, then click Create account. There is no email address requirement and no password recovery. Do not reuse an important password in this prototype.

Data is stored in `claimledger.sqlite3`. Override it with `CLAIMLEDGER_DB=/absolute/path/to/database.sqlite3`. The host and port can be set with `HOST` and `PORT`. Back up the database before changing or deleting it. The default binds only to the local computer.

## What works

- Username/password signup and login, salted scrypt password hashes, 24-hour sessions and logout.
- Private, persistent review creation, reading, editing and deletion.
- Claim creation, editing and deletion. New claims always start Unverified, even if a caller supplies a verdict.
- Human-selected Supported, Contradicted and Unverified verdicts, with reviewer notes.
- Evidence excerpts and HTTP(S) source links, with removal.
- Dynamic status counts and a warning when contradicted or unverified claims remain.
- Foreign-key cascade deletion of children when a review or claim is deleted.
- A visibly fictional demo with one claim of each verdict.
- Owner checks on every review, claim and evidence data operation.
- Responsive desktop and mobile layout.

Evidence is supplied by the reviewer. URLs are saved and displayed, never fetched, crawled or independently checked. Supported is a user's judgement, not an assurance from ClaimLedger. Demo links use reserved example.invalid addresses and deliberately do not resolve. Do not upload confidential or sensitive material to a public demo.

## Tests

```sh
python3 -m unittest discover -s tests -v
```

30 HTTP/database integration tests cover login and expiry, anonymous denial, two-user isolation on reads and writes, default Unverified, human verdict changes, notes, review edits, evidence, unsafe URL rejection, cascade deletion, CSRF and Origin checks, demo, logout and fresh-connection persistence. Tests use a temporary database, not the real local data file.

Optional browser test requires Node.js and Playwright. It creates an isolated temporary server/database and removes the database afterwards.

```sh
npm install --no-save playwright
npx playwright install chromium
node tests/ui.cjs
```

Set `SCREENSHOT_DIR` to choose where desktop and mobile screenshots are saved. The test exercises signup, demo, claim creation, verdict change, note persistence after reload, evidence addition, claim deletion, phone overflow and JavaScript errors. An automated pass is not a security audit.

## Screen-only demo outline

1. Create an account and load the clearly labelled synthetic demo.
2. Show the one Supported, one Contradicted and one Unverified counts and the follow-up warning.
3. Add a claim and show that its initial verdict is Unverified.
4. Attach a reviewer-provided excerpt and URL. State explicitly that the URL is not fetched.
5. Save a note and make a human verdict change. Reload and reopen the review to demonstrate persistence.
6. Delete the test claim with confirmation. Explain owner isolation and the automated two-user tests.

## Limits and deployment caution

This is a hackathon prototype, not production-audited software. The standard-library server is for local evaluation. Before an internet deployment, add a production server/reverse proxy with HTTPS, set `COOKIE_SECURE=1`, enforce login/signup rate limits and request timeouts/body limits at the proxy, add storage quotas and backups, and provide operational monitoring. Do not run multiple independent app replicas against separate SQLite files. There is no account deletion UI, password reset, revision history, automated claim extraction or URL validation beyond basic HTTP(S) syntax. Review deletion is permanent.

No production hosting is included. Do not put SQLite on an ephemeral free-host filesystem and claim the data is durable. A deployment needs verified persistent storage. Source publication does not itself grant a separate open-source licence; no licence is asserted in this package pending the owner's choice.

Built with AI coding assistance. The product keeps verdict decisions human-led and makes no automated fact-checking claim.
