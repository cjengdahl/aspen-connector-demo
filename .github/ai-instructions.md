# AI Code Assistant — Secure SQL Handling & SQL Injection (CWE-89) Mitigations

Checklist — high-level revision plan
- Require the assistant to never generate SQL that concatenates or interpolates untrusted input; always prefer parameterized queries or an ORM.
- Add explicit coding rules, anti-patterns, and safe examples for Python DB access (DB-API, psycopg2, sqlite3, SQLAlchemy).
- Enforce taint-aware prompts and output: label sources (HTTP params, headers, server vars) as tainted and show sanitization/validation steps or bind parameters.
- Integrate static checks and CI gates (semgrep, bandit) plus unit/fuzz tests that assert protection against injection strings.
- Require PR checklist and reviewer sign-off when raw SQL or dynamic identifiers are used, and provide semgrep rule snippets to detect regressions.

## Purpose and Scope
This instruction file defines strict, minimal, and actionable rules the AI Code Assistant must follow when generating Python code that interacts with SQL databases, to eliminate SQL Injection (CWE-89) risks introduced by the AI-generated code. These rules apply to generated code, suggested patches, examples, and templates.

## Principle Rules (must be enforced for every generated snippet)
- Never produce SQL statements that include untrusted data via string concatenation, f-strings, percent-formatting, or simple interpolation.
- Always prefer parameterized queries (DB-API placeholders, prepared statements) or a high-level ORM query builder.
- When dynamic SQL identifiers (table/column names, ORDER BY column, etc.) are required, only allow them via strict whitelists or mapped constants — never directly from user input.
- Treat all HTTP request data, headers, cookies, and server-provided parameters as tainted. The assistant must explicitly mark them as tainted and show binding/validation.
- If the assistant must generate raw SQL for complex operations, require an explicit justification in comments and include a security checklist (parameterization, tests, CI rules) inline.

## Required Output Behavior of the Assistant
When asked to produce database-accessing code the assistant must:
1. State whether the code uses parameterized queries, an ORM, or raw SQL.
2. If parameterized/ORM, provide a working code snippet showing proper bind parameters.
3. If raw SQL is used, include explicit comments showing:
   - source(s) of taint,
   - validation/whitelisting performed,
   - how parameters are bound,
   - rationale why raw SQL is necessary.
4. Add at least one unit test or test snippet that asserts taint inputs cannot alter query semantics (e.g., passes "' OR '1'='1" and verifies expected safe behavior).
5. Add a short note on CI scan expectations (semgrep/bandit entry or rule name).

## Prohibited Patterns (AI must refuse to produce)
- Any code that constructs SQL via concatenation or interpolation of user-controlled values:
  - "SELECT ... WHERE id = " + user_input
  - f"SELECT * FROM users WHERE name = '{name}'"
  - "query = '... %s ...' % name"
- Passing raw request parameters into ORM `.execute()` or cursor.execute(sql_string)` without parameters.
- Building SQL identifiers (table/column names) directly from inputs.
If a user requests such code, the assistant must refuse and provide secure alternatives.

## Safe Examples (Python)

- DB-API (psycopg2 / MySQLdb style) — always bind parameters:
```python
# Safe: use bind parameters; 'user_id' is tainted (e.g., from request.args)
def get_user(conn, user_id):
    with conn.cursor() as cur:
        cur.execute("SELECT id, username FROM users WHERE id = %s", (user_id,))
        return cur.fetchone()
```

- sqlite3 (uses ? placeholders):
```python
import sqlite3

def get_user(conn: sqlite3.Connection, username: str):
    cur = conn.cursor()
    cur.execute("SELECT id, email FROM users WHERE username = ?", (username,))
    return cur.fetchone()
```

- SQLAlchemy Core / ORM — prefer bound parameters or ORM filters:
```python
# Using SQLAlchemy ORM (safe)
from sqlalchemy.orm import Session
def get_user(session: Session, user_id: int):
    return session.query(User).filter(User.id == user_id).one_or_none()

# Using text with bindparams (safe)
from sqlalchemy import text
def get_user_by_name(session: Session, name: str):
    stmt = text("SELECT id, username FROM users WHERE username = :name")
    return session.execute(stmt, {"name": name}).fetchone()
```

- Safe dynamic identifier pattern — whitelist/mapping:
```python
ALLOWED_ORDER_COLUMNS = {"name": "name", "created": "created_at"}

def get_items(conn, order_by_key: str):
    # Whitelist user-chosen sort column
    column = ALLOWED_ORDER_COLUMNS.get(order_by_key)
    if column is None:
        raise ValueError("invalid order column")
    sql = f"SELECT id, name FROM items ORDER BY {column} LIMIT %s"
    with conn.cursor() as cur:
        cur.execute(sql, (100,))
        return cur.fetchall()
# Note: identifier chosen only from allowed constants, values still parameterized.
```

## Unsafe Example (forbidden) — DO NOT GENERATE
```python
# UNSAFE: vulnerable to SQL injection — do not output this pattern
def unsafe(conn, username):
    query = "SELECT id FROM users WHERE username = '%s'" % username
    conn.execute(query)
```

## Input Validation & Sanitization Guidance
- Prefer validation + parameterization, not escaping. Parameterization prevents injection by design.
- For numeric inputs, coerce and validate types (int casting with try/except) before binding.
- For constrained inputs (enums, sort keys), use whitelist mapping.
- Never rely on manual quoting or ad-hoc escaping of SQL values.

## Taint Awareness & Documentation in Code
- Mark tainted inputs in generated code with clear comments (e.g., "# tainted: request.args['id']").
- Show the transformation/validation steps (e.g., casting, regex whitelist, lookups).
- If sanitization is applied (rare), document why it is safe and include tests demonstrating behavior.

## Testing Requirements (AI must include at least one test snippet)
- Include unit tests that feed common SQL injection payloads (e.g., "' OR '1'='1", "1; DROP TABLE users;") and assert queries remain safe or inputs are rejected.
- Example pytest snippet:
```python
def test_get_user_rejects_injection(db_conn):
    malicious = "' OR '1'='1"
    # Should not return all users — either raises or returns None/specific user
    result = get_user(db_conn, malicious)
    assert result is None or isinstance(result, dict)
```

## CI / Static Analysis Requirements
- Every PR that modifies database-access code must run:
  - semgrep with custom SQLi rules (see sample rule below),
  - bandit for Python security checks,
  - unit tests and any provided fuzz tests.
- CI must fail the build if semgrep or bandit flags SQL injection risks.
- Add an explicit CI job that runs:
  - pip install semgrep bandit pytest
  - semgrep --config path/to/sqli-rules.yml
  - bandit -r path/to/module
  - pytest

Sample GitHub Actions step:
```yaml
- name: Security checks
  run: |
    pip install semgrep bandit pytest
    semgrep --config ./security/semgrep-sqli.yml
    bandit -r src/
    pytest -q
```

## Example semgrep rule (detect common SQL concat patterns)
Place this in security/semgrep-sqli.yml; CI must use it.
```yaml
rules:
  - id: python-sqli-exec-concat
    patterns:
      - pattern-either:
          - pattern: |
              $CURSOR.execute($SQL + $V)
          - pattern: |
              $CURSOR.execute(f$SQL)
          - pattern: |
              $CURSOR.execute($SQL % $V)
          - pattern: |
              $CURSOR.execute($SQL.format($V))
    message: "Potential SQL injection: avoid concatenation/formatting of SQL with untrusted input; use parameterized queries."
    languages: [python]
    severity: ERROR

  - id: python-sqli-raw-exec
    patterns:
      - pattern: |
          $CURSOR.execute($SQL)
      - where-not: |
          $CURSOR.execute($SQL, $PARAMS)
    message: "Raw SQL executed without parameters; ensure bind parameters or ORM are used."
    languages: [python]
    severity: ERROR
```

## Pull Request & Code Review Requirements
- All PRs that include DB access must include:
  - Short security rationale for chosen approach.
  - A demonstration/test that proves defense against injection strings.
  - Evidence that semgrep/bandit run and passed on the changes.
- Reviewers must validate:
  - No string concatenation with tainted data in SQL contexts.
  - Any dynamic identifiers use whitelists or mappings.
  - Unit tests for malicious input exist and pass.

## When Raw SQL Is Unavoidable
- Provide documented justification in code comments.
- Use prepared statements or parameter binding for ALL user-controlled values.
- If dynamic identifiers are required:
  - Validate against a strict whitelist or a fixed mapping table in code (never accept raw input).
  - Log the decision and add a reviewer checklist item.
- Add additional manual code review sign-off in PR.

## Logging & Secrets
- Never log raw queries with user-supplied data.
- Do not include DB credentials or secrets in generated examples; show placeholders and reference secret management (env vars, vault).
- Example safe pattern:
```python
# BAD: never log raw SQL with values
# logger.info("Executing: %s", query % params)  # DON'T do this

# GOOD: log statement without sensitive data
logger.info("Executing users query with sanitized params")
```

## Dependency & Linter Guidance
- Prefer maintained DB clients and ORMs.
- Keep dependencies up-to-date and ensure SCA (software composition analysis) is part of CI.
- Use linters and formatters to keep code readable; security checks are separate.

## Assistant Prompting Constraints (how the AI should guide itself)
- On any prompt that touches DB access, do:
  1. Identify tainted sources and state them.
  2. Offer the safest option first (ORM/parameterized query).
  3. If user insists on raw SQL, require them to provide justification and explicitly ask for whitelist values for identifiers.
  4. Generate tests and CI config snippets automatically.
  5. If asked to produce a code sample that violates the above rules, refuse and provide secure alternatives.

## Appendix: Minimal Review Checklist (for PR footer)
- semgrep/bandit passed for new/changed files? [yes/no]
- Unit/fuzz tests included for malicious inputs? [yes/no]
- Any raw SQL? If yes, justification and reviewer sign-off included? [yes/no]
- Dynamic identifiers whitelisted/mapped? [yes/no]

End of instruction file.