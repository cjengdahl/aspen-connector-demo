# AI Coding Instructions for the AI Code Assistant Tool

- Checklist (high-level revision plan)
  - Treat all server/HTTP inputs as tainted sources and require explicit safe handling in generated code.
  - Mandate parameterized queries or ORM usage for all SQL operations; forbid direct string concatenation with untrusted input.
  - Add concrete safe/forbidden Python examples and prompt rules so the assistant never suggests vulnerable SQL patterns.
  - Enforce automated SAST (e.g., semgrep) and CI checks (fail on python/Sqli) plus unit/fuzz tests for new DB code.
  - Provide guidance for dynamic identifiers (table/column names): use whitelists or safe mapping, never bind identifiers via substitution.
  - Require code-review checklist and developer notes explaining why generated code is safe (taint handling, parameters).

## Purpose and Scope
This file defines the coding, prompt, and CI policies the AI Code Assistant must follow to prevent SQL Injection (CWE-89 / scanner id: python/Sqli) in generated code, with emphasis on Python projects. These rules are mandatory for any code the assistant generates that interacts with SQL databases or accepts server/HTTP-provided input.

## High-level Security Policy
- Always assume server/HTTP inputs (query params, route params, form data, headers, cookies, JSON body) are tainted.
- Never generate code that constructs SQL commands by concatenating, interpolating, or formatting strings with tainted input.
- Always prefer parameterized queries, prepared statements, or a vetted ORM API that binds parameters safely.
- When identifiers (table names, column names, ORDER BY clauses) must vary, require an explicit whitelist mapping or safe switch logic — never interpolate raw user input into identifiers.
- Generated code must include minimal input validation (type checks, allowlists) where appropriate and document the reasoning.
- All generated DB code must pass automated SAST rules (e.g., semgrep rule id python/Sqli) and CI gates before merging.

## Taint Sources (treat these as untrusted)
- HTTP: query params, route params, form fields, JSON fields, headers, cookies
- Server inputs: environment variables only if explicitly trusted; otherwise validate
- Any input coming from external services, file uploads, or user-supplied content

## AI Prompt & Generation Rules (must be enforced by the assistant)
- Never produce SQL examples using string concatenation, f-strings, percent-formatting, or .format() with untrusted input.
- Always prefer and explicitly show parameter placeholders suitable to the DB driver or ORM used.
- If asked to generate raw SQL with dynamic identifiers, require and include an explicit whitelist mapping in the generated code.
- For Python, show one or more of these safe patterns: DB driver parameter binding (psycopg2/sqlite3/MySQLdb), SQLAlchemy ORM/Core with bound parameters.
- Annotate generated code with a short comment stating which inputs are considered tainted and how they are protected (e.g., “# user_id comes from request args — passed as DB parameter; safe from SQL injection”).

## Python safe examples (required patterns)

- psycopg2 (PostgreSQL)
```python
# Safe: parameterized query using placeholders
import psycopg2
conn = psycopg2.connect(dsn)
cur = conn.cursor()
cur.execute("SELECT * FROM users WHERE id = %s", (user_id,))
rows = cur.fetchall()
```

- sqlite3
```python
# Safe: parameterized query using ? placeholder
import sqlite3
conn = sqlite3.connect("db.sqlite")
cur = conn.cursor()
cur.execute("SELECT * FROM users WHERE username = ?", (username,))
```

- SQLAlchemy ORM (recommended)
```python
# Safe: ORM filter binding prevents SQL injection
from sqlalchemy.orm import Session
session = Session(engine)
user = session.query(User).filter(User.email == email).one_or_none()
```

- SQLAlchemy Core with bound parameters
```python
from sqlalchemy import text
stmt = text("SELECT * FROM users WHERE id = :id")
with engine.connect() as conn:
    result = conn.execute(stmt, {"id": user_id})
```

## Forbidden (examples the assistant must never generate)
- String concatenation / f-string with tainted input:
```python
# FORBIDDEN
query = f"SELECT * FROM users WHERE id = {user_id}"
cur.execute(query)
```
- Percent-formatting or .format() directly with request params:
```python
# FORBIDDEN
cur.execute("SELECT * FROM users WHERE name = '%s'" % name)
cur.execute("SELECT * FROM users WHERE name = '{}'".format(name))
```

## Dynamic identifiers (tables, columns, ORDER BY)
- If the identifier is derived from user input, the assistant must generate code that:
  - Uses an explicit allowlist mapping: map user-visible keys to internal identifiers.
  - Or uses conditional logic/switch to select from a fixed set of allowed queries.
- Example safe pattern:
```python
# Safe whitelist for table names
ALLOWED_TABLES = {"users": "users", "orders": "orders"}
table = ALLOWED_TABLES.get(request_table_param)
if table is None:
    raise ValueError("invalid table")
query = f"SELECT * FROM {table} WHERE id = %s"  # table now safe because validated
cur.execute("SELECT * FROM {} WHERE id = %s".format(table), (id_value,))
# Prefer instead to use ORM/abstractions to avoid formatted SQL entirely.
```
- Note: Even when validating identifiers, keep parameterized values for data fields.

## Input Validation and Sanitization Guidance
- Prefer type checks and domain validation (e.g., integer for IDs).
- For textual fields, prefer whitelisting or strict patterns (regex) where appropriate.
- Do not rely on escaping functions as the primary protection; prefer parameter binding.
- Document assumptions and validations in a short comment in generated code.

## Testing & CI Requirements
- All PRs that add or modify DB access must include:
  - Unit tests that exercise the DB access layer using representative inputs, including malicious payloads.
  - At least one test asserting that parameterization is used or that injection payloads do not alter behavior.
- Continuous Integration must run:
  - Static analysis (semgrep or equivalent) with rule(s) that detect SQL injection patterns (block merging if any match).
  - Example GitHub Actions step (must be included in repository CI):
```yaml
# Example: run semgrep and fail on findings (place in .github/workflows/ci.yml)
- name: Run semgrep
  uses: returntocorp/semgrep-action@v1
  with:
    config: "p/ci"
# Alternatively specify a local ruleset that includes python/Sqli rule id
```

## Example semgrep rule (to include in repo ruleset and CI)
- Include a semgrep rule to detect string formatting into execute() and similar:
```yaml
rules:
  - id: python-sqli-detect-execute-format
    message: "Potential SQL injection: do not format SQL with untrusted input; use parameterized queries or ORM"
    languages: [python]
    severity: ERROR
    patterns:
      - pattern: |
          $C.execute($SQL)
      - pattern-either:
          - pattern: $SQL = f"...{...}..."
          - pattern: $SQL = "...%s..." % ...
          - pattern: $SQL = "...{}".format(...)
          - pattern: f"...{...}..."
    metadata:
      cwe: "CWE-89"
      scanner-id: "python/Sqli"
```
- Ensure this rule set (or equivalent) is configured to block merges on any findings.

## Unit test example (pytest) for parameterization
```python
# tests/test_db_safety.py
def test_user_query_is_parameterized(db_connection, monkeypatch):
    # simulate attacker payload attempting typical SQL injection
    malicious = "1; DROP TABLE users; --"
    # call the code path that performs the query
    result = get_user_by_id(malicious)  # generated code should treat input as safe param
    # assert that the function returns None or raises appropriately, and DB is intact
    assert result is None or isinstance(result, dict)
```
- Encourage adding a small integration or in-memory DB test (sqlite) to ensure injection attempts do not execute unintended statements.

## Code Review & PR Checklist (must be completed by author)
- All new DB code uses parameterized queries or ORM APIs.
- No SQL constructed using string interpolation, concatenation, or format() with untrusted input.
- Any dynamic identifier uses an explicit allowlist and is documented.
- SAST (semgrep) scan passes with zero python/Sqli findings.
- Unit tests cover expected behavior and include injection payload cases.
- Generated code includes comments marking tainted sources and protections applied.

## Prompt-level enforcement for the AI Assistant
When given any prompt that might produce SQL code or database access:
- Verify the source of every value used in SQL — mark it tainted if from request/server/external input.
- If the prompt would lead to unsafe code, refuse and provide a secure alternative using parameterized binding or ORM.
- Always include a short comment explaining why the chosen approach is safe (e.g., binding placeholders).
- If the user explicitly requests “raw SQL with string interpolation”, refuse and require a justification and developer approval; propose a safe, equivalent implementation.

## Monitoring and Maintenance
- Keep rules and examples concise and update when new DB drivers or ORMs are introduced.
- Periodically review semgrep (or chosen SAST) rules to ensure coverage of new risky patterns.
- Log SAST findings; any regression that reintroduces python/Sqli must trigger an alert and rollback policy.

## Enforcement
- Any generated code that violates these rules must be rejected and must not be merged.
- CI must be configured to block merges for python/Sqli and equivalent SAST findings.
- Human reviewers must verify whitelists for dynamic identifier use and confirm tests exist before approving DB-related PRs.