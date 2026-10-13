# AI Code Assistant Security Instructions — SQL Injection Prevention

- Checklist (high-level revision plan)
  - Require the assistant to always treat Server/HTTP inputs as tainted and never interpolate them into SQL strings.
  - Enforce generation of parameterized queries or ORM-safe patterns; forbid string concatenation with untrusted input.
  - Provide concrete safe examples (Python DB-API, psycopg2, sqlite3, SQLAlchemy) and explicit unsafe examples.
  - Add CI/SAST checks (semgrep, Bandit) and pre-commit hooks; include a simple semgrep rule to catch likely SQLi patterns.
  - Require assistant behavior changes: ask clarifying questions, include a security checklist in responses with DB code, and refuse unsafe code.

## Scope and Purpose
These instructions govern the AI Code Assistant's generation of code or guidance that interacts with databases, with the explicit goal of preventing SQL Injection (CWE-89) in outputs. They apply to any generated examples, snippets, templates, and suggested practices for Python projects or tools that accept server/HTTP parameters.

## High-level Policies
- Treat any data originating from Server variables, HTTP parameters (query params, form data, headers, cookies), request bodies, or other external inputs as tainted by default.
- Always prefer parameterized queries, prepared statements, or ORM query building. Escaping alone is not sufficient unless performed by a vetted API and documented.
- Never generate code that constructs SQL by concatenating or formatting strings with tainted variables.
- If dynamic SQL identifiers (table/column names, ORDER BY direction) are necessary, require strict whitelist validation against known safe values before use.
- For any example or production guidance that touches DB queries, include:
  - A short rationale why the chosen pattern is safe.
  - A minimal test or validation strategy (unit test, SAST check).
  - A short "security checklist" that the user should verify before deployment.

## Assistant Generation Rules (must be enforced in templates/prompts)
- Always assume input is tainted. When asked to use values from Server/HTTP, the assistant must:
  - Use parameter binding placeholders and bind parameters via the DB API or ORM.
  - Or, require explicit whitelist validation for identifier-type inputs.
  - Or, request clarification if the user expects raw SQL construction.
- Do not produce code that:
  - Uses f-strings, "+" concatenation, or .format() to build SQL with untrusted variables.
  - Inserts user input directly into SQL statements or table/column identifiers without validation.
- If the user explicitly requests raw SQL construction for dynamic identifiers, the assistant must:
  - Refuse unless the user provides an explicit, verifiable whitelist and explains why parameterization is impossible.
  - Provide an example showing safe whitelist validation and escaping of identifiers (not via generic escaping functions).
- Always include at least one safe code example in Python (DB-API and an ORM), plus one unsafe example labeled "DO NOT USE" when demonstrating what to avoid.

## Taint Sources and Handling
- Mark the following as tainted by default:
  - HTTP request values: request.args, request.form, request.get_json(), request.headers, cookies.
  - Server environment variables and headers that can be set by users or proxies.
  - Any data read directly from client input, CLI args, or third-party services.
- Taint-handling rules:
  - Never remove the taint without explicit validation/normalization.
  - Validation strategies:
    - Whitelisting (preferred) for identifiers or limited sets.
    - Strong typing and range checks for numeric/ID inputs.
    - Canonicalization followed by strict sanity checks for expected formats.
  - After validation, the assistant should show the validation step and use only validated variables in SQL.

## Approved Secure Patterns (Python examples)

- psycopg2 (Postgres) — use parameterized query placeholders (%s)
```python
# Safe: parameterized query with psycopg2
import psycopg2

def get_user_by_email(conn, email):
    with conn.cursor() as cur:
        cur.execute("SELECT id, email FROM users WHERE email = %s", (email,))
        return cur.fetchone()
```

- sqlite3 — use ? placeholders
```python
# Safe: parameterized query with sqlite3
import sqlite3

def find_products(conn, category):
    cur = conn.cursor()
    cur.execute("SELECT id, name FROM products WHERE category = ?", (category,))
    return cur.fetchall()
```

- SQLAlchemy Core/ORM — use bind parameters or ORM filter methods
```python
# Safe: SQLAlchemy ORM
from sqlalchemy import select
from models import User  # declarative model

def get_user_by_username(session, username):
    return session.execute(select(User).where(User.username == username)).scalars().first()
```

- Dynamic identifiers (whitelist example)
```python
# Safe: validating identifiers via whitelist
ALLOWED_SORT = {"name": "name", "created": "created_at"}

def list_items(conn, sort_key):
    sort_col = ALLOWED_SORT.get(sort_key)
    if not sort_col:
        raise ValueError("invalid sort key")
    # safe to interpolate validated, constant column name
    sql = f"SELECT id, name FROM items ORDER BY {sort_col} LIMIT %s"
    cur = conn.cursor()
    cur.execute(sql, (100,))
    return cur.fetchall()
```

## Disallowed Patterns (explicitly forbidden)
- DO NOT produce code like the following:
```python
# DO NOT USE: unsafe string interpolation (SQL injection risk)
def get_user(conn, username):
    cur = conn.cursor()
    cur.execute(f"SELECT * FROM users WHERE username = '{username}'")  # unsafe
```
- DO NOT produce code that dynamically composes SQL from request parameters without validation.

## Testing, CI & Static Analysis Requirements
- CI must include automated SAST and linting that catches SQLi patterns before merge. Recommended tools:
  - semgrep with project rules for SQLi (see example rule below).
  - Bandit for Python security checks.
  - Unit tests that include malicious input cases asserting queries do not allow injection.
- Pre-commit configuration (example snippet) — require semgrep and bandit checks:
```yaml
# .pre-commit-config.yaml (example)
repos:
  - repo: https://github.com/returntocorp/semgrep
    rev: v1.XX.X
    hooks:
      - id: semgrep
  - repo: https://github.com/PyCQA/bandit
    rev: 1.7.5
    hooks:
      - id: bandit
```
- Example semgrep rule to detect string concatenation or f-strings with request params (adapt and expand for project):
```yaml
rules:
  - id: python-sqli-concat
    patterns:
      - pattern-either:
          - pattern: f"$SQL ... {request.*} ..."
          - pattern: "$SQL + request.*"
          - pattern: "request.* + $SQL"
    message: "Potential SQL injection: avoid concatenating request data into SQL; use parameterized queries or whitelist validation"
    languages: [python]
    severity: ERROR
```

## Assistant Response & Interaction Requirements
- When asked to generate DB-access code, the assistant must:
  - Ask clarifying questions when intent, allowed inputs, or environment (DB driver, ORM) is unclear.
  - Default to using parameterized examples for the specified DB driver.
  - Include a short "Security Checklist" in the response that the user must confirm (examples: taint origin, validation applied, SAST in CI).
  - If a user requests an unsafe pattern, the assistant must refuse and propose a secure alternative.
- Responses must explicitly call out which inputs are considered tainted and what validation was applied.

## Review, Approval & Traceability
- Changes to assistant prompts or templates that affect code generation must be reviewed by a security engineer.
- Each pull request that introduces or modifies DB code must:
  - Include tests for injection attempts.
  - Pass semgrep/Bandit in CI.
  - Include a security checklist in PR description confirming validation and query parameterization.

## References and Further Reading
- OWASP SQL Injection Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html
- Python DB-API parameterization: refer to driver docs (psycopg2, sqlite3, pymysql).
- Semgrep rules: https://semgrep.dev/docs/rules/

--- 
These instructions prioritize safety over convenience. They are minimal but mandatory: any assistant output that touches database queries must follow them.