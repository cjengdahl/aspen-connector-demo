# AI Code Assistant: Secure-Code Generation Policy and Guidance (SQLi Mitigation)

- Review generated code for any SQL construction that inserts external input into query strings; replace with parameterized queries or ORM methods.
- Enforce server/HTTP input as tainted sources and require validation/whitelisting before use in any query context.
- Add automated static checks (regex/SAST/bandit) and CI gates to block PRs containing raw SQL concatenation patterns.
- Provide explicit safe/unsafe Python examples, parameterization patterns, and safe handling of dynamic identifiers.
- Require tests and logging rules that avoid leaking raw SQL or sensitive parameters.

## Purpose
This instruction file directs the AI Code Assistant to never produce code that introduces SQL Injection (CWE-89) vulnerabilities. It is concise, actionable, and tailored to Python projects where HTTP/server parameters or environment values are sources of taint.

## High-level rules (must be enforced for every generation)
- Treat all external inputs (HTTP params, request body, headers, cookies, query string, environment variables) as tainted.
- Never construct SQL statements by concatenating or interpolating tainted values into SQL strings.
  - Forbid: f-strings, str.format(), % formatting, or string concatenation when composing SQL with tainted data.
- Always use parameterized queries (DB-API parameter substitution) or ORM query builders that separate query text from data.
- If an identifier (table/column name, ORDER BY direction) must be dynamic, use a strict whitelist mapping — never allow direct substitution of tainted values into identifiers.
- Validate and/or coerce inputs to expected types/values (whitelists, enums, numeric casts) before using them in queries.
- Do not log raw SQL with embedded parameters; mask or omit sensitive values.

## Tainted sources (examples)
Consider these sources tainted and requiring validation/parameterization:
- Flask/Django: request.args, request.form, request.values, request.json, request.headers, request.cookies
- WSGI/HTTP server variables
- os.environ and other environment inputs
- Command-line args, uploaded files, WebSocket input, messages from external services

## Forbidden patterns (do not generate)
The assistant must not generate code matching these insecure patterns:
- SQL string built with f-strings, .format(), % formatting, or + concatenation including tainted values.
  - Examples to forbid:
    - f"SELECT * FROM users WHERE id = {user_id}"
    - "SELECT * FROM users WHERE id = %s" % user_id
    - "SELECT * FROM users WHERE name = '" + name + "'"
- Passing tainted values directly into functions that execute text SQL without parameters (e.g., cursor.execute(sql_string_with_interpolation))
- Using user input directly in table/column names without whitelisting

## Mandatory safe patterns and examples (Python)

- DB-API parameterized query (psycopg2, mysqlclient, sqlite3):
```python
# Safe: parameterized query (psycopg2, mysqlclient, sqlite3)
def get_user_by_id(conn, user_id):
    cur = conn.cursor()
    cur.execute("SELECT id, username FROM users WHERE id = %s", (user_id,))
    return cur.fetchone()
```

- Using SQLAlchemy ORM or the SQLAlchemy Core parameter binding:
```python
# SQLAlchemy ORM - safe
def get_user_by_username(session, username):
    return session.query(User).filter(User.username == username).one_or_none()

# SQLAlchemy Core - safe
from sqlalchemy import text
def get_user_by_email(conn, email):
    stmt = text("SELECT id, email FROM users WHERE email = :email")
    return conn.execute(stmt, {"email": email}).fetchone()
```

- Handling dynamic identifiers with a whitelist:
```python
# Safe handling of dynamic column with whitelist
ALLOWED_SORT_COLUMNS = {"username": "username", "created": "created_at"}

def list_users(conn, sort_key):
    column = ALLOWED_SORT_COLUMNS.get(sort_key)
    if not column:
        raise ValueError("invalid sort key")
    query = f"SELECT id, username FROM users ORDER BY {column} LIMIT %s"
    return conn.execute(query, (100,)).fetchall()
```
(Note: Only the known-safe column values are embedded; user input is never embedded directly.)

## Input validation guidance
- Prefer whitelists/enums for categorical values.
- For numeric IDs, coerce and assert type (e.g., int(user_id)).
- Enforce maximum lengths on string inputs; reject or truncate otherwise.
- Reject inputs containing SQL metacharacters when they are not expected (but do not rely on escaping instead of parameterization).

## Logging and secrets
- Never log full SQL statements containing raw parameters. Log parameter names (not values) or masked values.
- Use parameter binding values only for data-layer logging with masking/sanitization.

## Assistant generation checks (post-generation)
Every generated code snippet or patch must pass these automated checks before being returned or committed:
1. Static pattern scan (regex) to detect disallowed string interpolation into SQL:
   - Patterns to flag (examples):
     - f"SELECT .*{.*}.*"
     - r"\.format\(|%s.*%" when used to build SQL strings
     - r'["\']\s*\+\s*\w+' in SQL context
2. Ensure all cursor/connection execute calls pass parameters separately (tuple/dict) rather than inlined strings.
3. Ensure any dynamic identifier uses an explicit whitelist mapping.
4. Verify that any tainted source used in a query is either:
   - passed as a parameter to a parameterized query, or
   - validated/whitelisted with a defensible check.

Provide these regex examples (implementers may adapt to their tooling):
```text
# Flag risky SQL concatenation/interpolation patterns
(?i)(f"|f')(.*select|insert|update|delete).*{.*}   # f-strings containing SQL
(?i)\.format\([^)]*\)                              # .format used to build SQL
(?i)%\s*\(?.*\)?\s*%                              # % formatting used in SQL
(?i)["']\s*\+\s*\w+                               # concatenation of SQL + variable
```

## CI / SAST integration (required)
Add checks into CI to prevent merge of insecure code:
- Run bandit (Python) and fail on SQL injection-related findings.
- Run a custom script that:
  - Scans changed files for forbidden patterns listed above.
  - Verifies that DB execute calls use parameterization.
- Example GitHub Actions step:
```yaml
# .github/workflows/security.yaml (snippet)
- name: Install dependencies
  run: pip install bandit
- name: Run bandit
  run: bandit -r .
- name: Run custom SQLi scan
  run: python scripts/check_sqli_patterns.py
```
The scripts/check_sqli_patterns.py should implement the regex checks and require explicit approval/exception comments in code reviews if any flagged pattern is intentionally safe (rare).

## Testing requirements
- Unit tests must cover query-building functions. Tests should assert that queries executed use parameterization rather than string concatenation (e.g., by mocking cursor.execute and asserting parameterized call signature).
- Add integration tests that exercise API endpoints with malicious payloads (e.g., "1; DROP TABLE users") and assert no destructive behavior or SQL errors are exposed.

## Review and exception handling
- Any exception to these rules must be explicitly documented in a code comment linking to an approved design decision and security review ticket.
- The AI assistant must not generate exception comments; exceptions are only added by human reviewers after a security review.

## Developer guidance for code review
- Look for any code that constructs SQL by concatenating strings — reject and request rewrite using parameterization or ORM.
- Confirm that dynamic SQL identifiers use whitelists.
- Confirm tests exist that would catch SQL injection attempts.

## References and justification
- Vulnerability: python/Sqli (CWE-89)
- Recommended mitigations: parameterized queries, input validation, whitelisting, static scanning and CI enforcement.

## Minimal examples — Unsafe vs Safe (for quick reference)
Unsafe:
```python
# DO NOT GENERATE: vulnerable to SQL Injection
def find_user(conn, name):
    sql = "SELECT id FROM users WHERE name = '%s'" % name
    return conn.execute(sql).fetchone()
```

Safe:
```python
# Acceptable: parameterized
def find_user(conn, name):
    return conn.execute("SELECT id FROM users WHERE name = %s", (name,)).fetchone()
```

## Implementation checklist for integrating this file into an AI Code Assistant
- Integrate these rules into the assistant's generation policy and post-generation scanning pipeline.
- Add the forbidden-pattern regex checks to the assistant's validator.
- Configure CI to run bandit and the custom checks on every PR.
- Update the assistant's training/templating layers to prefer parameterized examples and ORM usage.

By following these rules, examples, and automated checks, the assistant will avoid generating code that introduces SQL Injection (python/Sqli, CWE-89) vulnerabilities.