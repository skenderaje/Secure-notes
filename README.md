# SecureNotes

[![security](https://github.com/skenderaje/Secure-notes/actions/workflows/security.yml/badge.svg)](https://github.com/skenderaje/Secure-notes/actions/workflows/security.yml)

A small notes app built to be secured end to end: threat-modelled, tested, scanned in CI
and deployed. The app is deliberately simple so the security work is easy to follow.

> Status: **phase 4 of 5** — app, security tests, threat model, CI security pipeline and a
> find-and-fix pull request done. Deployment is next.

## Roadmap

| Phase | What | Status |
|---|---|---|
| 1 | App with security controls, each covered by a test | ✅ Done |
| 2 | [Threat model](docs/threat-model.md): STRIDE per element, mapped to MITRE ATT&CK, with a [data-flow diagram](docs/threat-model-dfd.html) of the trust boundaries | ✅ Done |
| 3 | [GitHub Actions pipeline](.github/workflows/security.yml) that fails the build on high-severity findings | ✅ Done |
| 4 | A vulnerability found and fixed through a pull request — [finding 001](docs/findings/001-search-sql-injection.md) | ✅ Done |
| 5 | Live deployment and a secure-SDLC write-up | Next |

## Threat model

[`docs/threat-model.md`](docs/threat-model.md) lists the assets, actors and trust boundaries,
then walks through 23 STRIDE threats. Each one names its mitigation and the test that proves
it, or is marked open. The open risks (dependency and secret scanning, global rate limiting,
audit logging, MFA) feed the next phases.

The polished [data-flow diagram](docs/threat-model-dfd.html) is a standalone HTML file: download
it or open it from a local clone to view it. The Mermaid diagrams in the document render
directly on GitHub.

## Features

- Sign up, log in, log out
- Create, edit and delete private notes — each user sees only their own

## Security controls so far

| Risk | Control | Test |
|---|---|---|
| Stolen password database | Argon2id password hashes | `test_password_is_hashed_with_argon2` |
| Weak passwords | 12–128 characters, must differ from username | `test_weak_password_rejected` |
| Password guessing | 5 failed logins per username + IP per 15 min | `test_login_is_throttled_after_five_failures` |
| Account enumeration | Same error and status for unknown user and wrong password; dummy hash keeps timing similar | `test_login_error_does_not_reveal_which_part_was_wrong` |
| Session fixation | Session cleared and recreated on login | `test_session_is_renewed_on_login` |
| Session theft | Signed cookie, `HttpOnly`, `SameSite=Lax`, `Secure` in production, 8 h lifetime | `test_session_cookie_flags` |
| CSRF | Per-session token on every form, compared in constant time | `test_post_without_csrf_token_is_rejected` |
| IDOR (reading or changing another user's note) | Ownership checked inside the database query; foreign notes return 404 | `test_cannot_open/edit/delete_someone_elses_note` |
| Stored XSS | Jinja2 autoescaping + strict Content-Security-Policy with no inline scripts | `test_note_content_is_html_escaped` |
| Clickjacking, MIME sniffing, leaks via cache/referrer | `frame-ancestors 'none'`, `X-Frame-Options`, `nosniff`, `no-store`, `no-referrer` | `test_security_headers_present` |
| Oversized input | Length limits on every field | `test_overlong_note_rejected` |
| Secrets in code | `SECRET_KEY` and database URL from the environment; app refuses to start in production without a key | — |
| Information disclosure | API docs disabled in production | — |

## CI security pipeline

[`.github/workflows/security.yml`](.github/workflows/security.yml) runs on every push to `main`,
on every pull request and once a week. Any failing gate blocks the change.

| Gate | Tool | Fails the build when |
|---|---|---|
| Security tests | pytest | any control's test fails |
| Code scan (SAST) | Bandit | a high-severity finding with at least medium confidence, or any string-built SQL (B608) |
| Dependency audit (SCA) | pip-audit | any pinned runtime dependency has a known vulnerability |
| Secret scan | gitleaks | a secret appears anywhere in the git history |

Hardening of the pipeline itself: read-only token by default (only the secret scan may comment
on pull requests), third-party actions pinned to full commit SHAs, checkout credentials not
persisted. The weekly run catches vulnerabilities published after a change was merged.

**First real finding.** Before the pipeline went live, pip-audit flagged the dependencies
pinned in phase 1: `python-multipart 0.0.20` (6 advisories) and `starlette 0.41.3`
(7 advisories, pulled in by FastAPI). Upgrading to `python-multipart 0.0.33` and
`starlette 1.10.0` cleared them. The upgrade also changed when Starlette sends the session
cookie (only when the session changes), which broke a test; the cookie flags were still
correct, so the test now checks the two responses that set the cookie.

## Findings

| ID | Finding | Severity | Introduced → fixed |
|---|---|---|---|
| [001](docs/findings/001-search-sql-injection.md) | SQL injection in note search let any user read every note | High | PR #3 → PR #4 |

Finding 001 was **seeded on purpose** to practise the full loop: review the diff, prove the
bug with a failing test, fix it, and close the gap that let it through CI (Bandit rated it
medium, below the high-only gate; string-built SQL is now blocked at any severity).

## Run locally

Requires Python 3.12.

```bash
python -m venv .venv
.venv/Scripts/pip install -r requirements-dev.txt     # Windows; use .venv/bin on macOS/Linux
.venv/Scripts/python -m pytest
.venv/Scripts/python -m uvicorn app.main:app --port 8001
```

Then open http://127.0.0.1:8001.

## Stack

FastAPI · SQLAlchemy (SQLite locally, Postgres in production) · Jinja2 · argon2-cffi
