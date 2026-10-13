# AI Code Assistant — Secure Coding Instructions (SQL Injection Mitigation)

- High-level revision plan:
  - Enforce policy: disallow SQL string concatenation with untrusted inputs; require parameterized queries, ORMs, or safe query builders.
  - Provide canonical, minimal-safe code patterns for common Python DB libraries (psycopg2, sqlite3, SQLAlchemy, Django).
  - Add input-handling rules: validation, whitelisting, and canonical sanitization guidance for tainted sources (HTTP params, headers, cookies, server env).
  - Integrate automated checks: semgrep/Bandit/linters and CI gate that fail on SQLi patterns; include sample semgrep rules.
  - Add PR reviewer checklist and automated tests to prevent regressions.

## Purpose and scope
This instruction file governs how the AI Code Assistant generates database-access code for this project. Its explicit goal is to eliminate SQL injection vulnerabilities by preventing generation of insecure patterns, providing safe templates, and enforcing tool-level and CI-level checks.

These rules apply to any code the AI generates or modifies that interacts with databases, raw SQL, or executes queries constructed from external input (HTTP params, query strings, form data, headers, cookies, environment variables).

## Mandatory policies for SQL/DB code generation
- NEVER generate SQL by concatenating or interpolating raw, untrusted input into query strings.
  - Disallow use of f-strings, %-formatting, str.format(), or "+" concatenation to build SQL when including variable content from request or environment sources.
- ALWAYS use one of:
  - Parameterized queries / prepared statements with the DB API parameter binding.
  - An ORM query builder (e.g., SQLAlchemy Core/ORM, Django ORM) with parameters bound through the ORM APIs.
  - A safe query builder library that provides parameter binding and prevents injection.
- If the user explicitly requests raw or dynamic SQL, require an explicit justification and follow-up questions from the assistant; offer safe alternatives first.
- Treat all incoming data from external/untrusted sources as tainted (HTTP params, headers, cookies, request body, websockets, query strings, path parameters, environment variables, server request context). Must be validated/whitelisted/escaped or passed as parameters.

## Prohibited patterns (examples)
Do not generate code like these:
```python
# Prohibited: vulnerable to SQL injection
query = "SELECT * FROM users WHERE name = '%s'" % username
cursor.execute(query)

# Prohibited: vulnerable
query = f"UPDATE users SET role='{role}' WHERE id = {user_id}"
cursor.execute(query)

# Prohibited: string concatenation
query = "DELETE FROM items WHERE id=" + item_id
cursor.execute(query)
```

## Required secure patterns and examples
- Use DB-API parameterized queries (psycopg2, sqlite3, MySQLdb, pymysql):
```python
# psycopg2 example (Postgres)
query = "SELECT id, name FROM users WHERE email = %s"
cursor.execute(query, (email,))

# sqlite3 example
query = "INSERT INTO events (user_id, note) VALUES (?, ?)"
cursor.execute(query, (user_id, note))
```

- Use SQLAlchemy Core or ORM:
```python
# SQLAlchemy Core (recommended for dynamic queries)
from sqlalchemy import text
stmt = text("SELECT * FROM users WHERE created_at >= :since")
result = connection.execute(stmt, {"since": since_datetime})

# SQLAlchemy ORM
user = session.query(User).filter(User.email == email).one_or_none()
```

- Use Django ORM (do not .raw() with interpolated strings):
```python
# Django ORM (recommended)
users = User.objects.filter(email=email)
# If raw SQL is unavoidable, use params:
qs = User.objects.raw("SELECT * FROM auth_user WHERE email = %s", [email])
```

- Async DB drivers (asyncpg, aiomysql): use their parameter binding API:
```python
# asyncpg example
row = await conn.fetchrow("SELECT * FROM users WHERE id = $1", user_id)
```

- Helper function pattern (centralize safe execution):
```python
def execute_query(cursor, query, params):
    # Always pass params as a separate argument
    cursor.execute(query, params)
```

## Input handling and validation
- Validate and/or whitelist expected values before binding:
  - For identifiers (table/column names) that must be dynamic, only accept values from a predefined whitelist and never interpolate raw values into SQL. Construct SQL using safe mappings:
```python
ALLOWED_SORT_COLUMNS = {"name": "name", "created": "created_at"}
sort_col = ALLOWED_SORT_COLUMNS.get(requested_sort, "created_at")
# Use parameterized queries for values; identifiers are chosen from whitelist
stmt = text(f"SELECT * FROM items ORDER BY {sort_col} LIMIT :limit")
connection.execute(stmt, {"limit": limit})
```
- For numerical inputs: coerce and validate types (int(), decimal) and check bounds.
- For enumerated inputs: validate against explicit enum/whitelist.
- For free text: treat as data; pass through bound parameters. Do not attempt to sanitize by escaping SQL manually as a general solution.

## Logging and error handling
- Do not log raw SQL with bound parameter values in production logs. Use placeholders or mask sensitive content.
- On DB errors, do not return raw DB error messages to clients. Return a safe, generic error and log details securely.

## Tool behavior / prompt constraints
- The assistant must refuse or warn when the user explicitly requests unsafe patterns. Preferred response: offer safe, parameterized alternatives and ask clarifying questions if dynamic SQL is required.
- When generating code, the assistant must:
  - Mark sources of taint in generated code comments (e.g., "# tainted: request.GET['id']").
  - Use safe templates only (see Required secure patterns).
  - If it cannot produce a safe alternative, it must explicitly flag risk and require human approval.

## CI and automated checks
- CI must run static analysis rules that block SQLi-prone patterns. Recommended tooling and baseline rules:
  - semgrep: include rules that detect SQL string concatenation, f-strings/formatting used with SQL, and direct inclusion of HTTP params into execute() calls.
  - Bandit: run default Python checks.
  - SAST/DAST where applicable.
- Example semgrep rule (place in .semgrep/rules/sql_injection.yml):
```yaml
rules:
  - id: python-sql-concat
    patterns:
      - pattern: |
          $CUR.execute($Q + ...)
      - pattern-either:
          - pattern: $CUR.execute(f"$Q{...}")
          - pattern: $CUR.execute($Q.format(...))
    message: "Avoid concatenating/interpolating user input into SQL. Use parameterized queries or ORM."
    languages: [python]
    severity: ERROR
```
- CI must fail on any semgrep/Bandit rule with severity ERROR related to SQL injection.

## Tests and review requirements
- Add unit tests that assert queries generated by helper functions use parameter binding and do not contain raw user input concatenated into SQL. Mock DB execution and assert execute() is called with query and params (not interpolated string).
- Add an automated PR checklist that requires:
  - A security reviewer sign-off for any pull request that adds raw SQL or changes DB-access patterns.
  - Evidence of passing semgrep/Bandit checks.
  - A short explanation in the PR description if raw SQL is added and why ORMs/parameterization could not be used.

## Semgrep/Bandit integration examples (CI snippets)
- Example GitHub Actions job (condensed):
```yaml
name: security-scan
on: [pull_request]
jobs:
  semgrep:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: returntocorp/semgrep-action@v1
        with:
          config: .semgrep
  bandit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Run bandit
        run: |
          pip install bandit
          bandit -r . -ll -iii B105,B106 || exit 0
```
- Configure CI to treat SQLi-related semgrep results as blocking (non-zero exit).

## PR reviewer checklist (short)
- Confirm no SQL is built via string concatenation or interpolation.
- Confirm parameter binding or ORM usage for all user-influenced values.
- Confirm input validation or whitelisting for dynamic identifiers.
- Confirm semgrep/Bandit passed; if they did not, a security rationale must be included and security team approval attached.

## Documentation and training
- Update the project README and internal style guide to include these rules and safe example snippets.
- Provide a short copy-paste safe-snippets file for developers and the assistant to use.

## Enforcement and escalation
- Any automated scanner finding tagged as SQL Injection (CWE-89) must block merging until resolved.
- If the AI Code Assistant cannot automatically convert a user request into a safe implementation, it must:
  - Refuse to generate unsafe code.
  - Provide a secure alternative.
  - Mark the PR for manual security review if the user insists on raw/dynamic SQL.

## Minimal safe helper templates (copyable)
- Central DB execution helper:
```python
def execute_safe(cursor, query, params=None):
    """
    Execute a parameterized query. Never interpolate parameters into `query`.
    `query` must be a constant string or constructed only using whitelisted identifiers.
    """
    if params is None:
        params = ()
    cursor.execute(query, params)
```

- Whitelisting identifiers:
```python
ALLOWED_COLUMNS = {"name", "email", "created_at"}
def safe_column(col):
    if col not in ALLOWED_COLUMNS:
        raise ValueError("Invalid column")
    return col
```

By following these instructions, the AI Code Assistant will avoid generating SQL injection vulnerabilities and will produce code that is safe-by-default for database interactions.