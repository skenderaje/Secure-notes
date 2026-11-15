# Finding 001 — SQL injection in note search

| | |
|---|---|
| **Severity** | High — any signed-in user can read every other user's notes |
| **CWE** | CWE-89: SQL Injection |
| **OWASP Top 10** | A03:2021 — Injection |
| **ATT&CK** | T1190 Exploit Public-Facing Application → T1213 Data from Information Repositories |
| **Introduced** | PR #3 (`a72baed`), *Add title search to the notes page* |
| **Fixed** | PR #4 (this change) |
| **Status** | Fixed, regression-tested, CI rule added |

> **Exercise disclosure.** This vulnerability was seeded on purpose in PR #3 to practise the
> full find → prove → fix → prevent loop. The commit message and a code comment said so.
> Everything below — the review, the failing tests, the fix and the CI gap — is real.

## Summary

`GET /notes/search?q=` built its SQL by pasting the search term into the query string. A
single quote in the search closed the string literal, and the rest of the input ran as SQL.
The owner filter could then be bypassed, returning other users' notes.

## Where

`app/main.py`, `search_notes()` as merged in PR #3:

```python
sql = text(f"SELECT id FROM notes WHERE owner_id = {user.id} AND title LIKE '%{q}%' ORDER BY updated_at DESC")
```

## Proof of concept

Signed in as **bob**, search for:

```text
' OR 1=1 --
```

The query becomes:

```sql
SELECT id FROM notes
WHERE owner_id = 2 AND title LIKE '%' OR 1=1 --%' ORDER BY ...
```

`AND` binds tighter than `OR`, so the condition is `(bob's notes AND any title) OR true`, and
`--` comments out the rest. Every note in the database comes back, and the page renders
alice's titles and contents for bob.

The regression test `test_search_cannot_read_other_users_notes_via_sql_injection` reproduces
this with three payloads (tautology with comment, tautology without comment, `UNION SELECT`).
Against the PR #3 code it **fails** — bob's page contains "Alice secret". A second test showed
that `%` and `_` in a search were treated as wildcards (`%` matched every title).

## How it was found

Code review of the PR #3 diff, flagging the classic pattern: an f-string (user input)
passed to `sqlalchemy.text()`. The CI pipeline did **not** stop it:

| Gate | Result on PR #3 | Why |
|---|---|---|
| pytest | ✅ passed | The only search test covered the normal case |
| Bandit | ✅ passed | B608 was reported as **Medium severity / Low confidence**; the gate only fails on High |
| pip-audit, gitleaks | ✅ passed | Not their job |

## Fix

The search term now travels as a **bound parameter** through the ORM, never as SQL text, and
the owner filter is part of the same query:

```python
select(Note).where(Note.owner_id == user.id, Note.title.ilike(like_pattern(q), escape="\\"))
```

`like_pattern()` escapes `\`, `%` and `_` so they match literally. No `text()` call remains in
the app.

## Prevention

| Change | Effect |
|---|---|
| Regression tests (3 injection payloads + wildcard test) | The bug cannot come back silently |
| New CI step: `bandit -r app --tests B608` | Any string-built SQL now fails the build at **any** severity or confidence |
| Threat model T3 updated | Records the finding and the extra control |

## Lessons

1. **Tests that only cover the happy path prove the feature, not its safety.** Every
   endpoint that takes input needs at least one hostile-input test.
2. **Severity thresholds are a trade-off.** A high-only gate keeps noise down but let a
   high-impact bug through. For a few well-understood checks — SQL built from strings is
   one — blocking at any severity costs little.
3. **Never format user input into SQL**, even "just for a LIKE". Use the ORM or bound
   parameters, and escape LIKE wildcards when the user should not control them.
