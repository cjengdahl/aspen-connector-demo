# AI Code Assistant: Secure Coding Instructions (focus: prevent SQL Injection)

- Checklist — high-level revision plan
  - Treat all external inputs (HTTP params, headers, server variables) as tainted and require explicit handling.
  - Mandate parameterized queries / prepared statements or ORM usage; forbid direct string concatenation/interpolation for SQL.
  - Provide clear safe/unsafe code examples for the common Python DB libraries and async drivers.
  - Enforce static analysis (semgrep/CodeQL/Bandit) and CI gates that fail PRs on SQLi patterns; include sample rules.
  - Require unit tests, code comments, and PR metadata demonstrating correct mitigation (parameterization + validation).
  - Add pre-commit and CI integrations to run scanners and tests automatically.

## Purpose & scope
These instructions direct the AI Code Assistant (and generated code) to never produce code vulnerable to SQL Injection (CWE-89). They apply to generated Python server code that handles external input (HTTP params, cookies, headers, path segments, request bodies) and constructs SQL queries.

## Threat model
- Sources: any client-controlled input (HTTP params, headers, cookies, path segments, file contents), and any data from other untrusted servers.
- Vulnerability: concatenation or interpolation of tainted input into SQL strings without parameter binding or safe query builders.
- Goal: ensure generated code rejects unsafe SQL construction and always uses safe binding/ORM patterns, plus input validation and least-privilege DB access.

## Mandatory generation rules (must be enforced by the AI tool)
1. Treat any value coming from request objects (e.g., Flask/Django/FastAPI request.*) or environment variables that originate from the network as tainted.
2. For every SQL operation generated:
   - Use parameterized queries / prepared statements OR a well-maintained ORM (e.g., SQLAlchemy ORM with bound parameters).
   - Never construct SQL via string concatenation, f-strings, %-formatting, or .format() using tainted values.
   - If dynamic SQL structure is required (table/column names), validate against a strict allowlist of permitted identifiers and never allow raw client input.
3. Always use parameter binding specific to the DB client API (placeholders and separate args). Example bindings required for code generation are provided below.
4. Use least-privilege database credentials and avoid SHOW/INFORMATION_SCHEMA exposures in public endpoints.
5. Sanitize/validate inputs where possible (type checks, allowlists, length limits). Validation is supplemental — parameterization is required even when inputs are validated.
6. Do not print or return raw DB error messages to clients. Log errors with care and avoid sensitive data leakage.
7. For generated code that accesses SQL, add a short inline security comment above the query indicating the mitigation used (e.g., "# SECURITY: parameterized query - prevents SQLi").

## Forbidden patterns (AI must never output)
- Any direct concatenation or interpolation of request-derived values into SQL strings:
  - Bad examples to never generate:
    - query = "SELECT * FROM users WHERE name = '%s'" % name
    - query = f"SELECT * FROM users WHERE id = {user_id}"
    - query = "SELECT * FROM " + table_name + " WHERE id = " + id
- Using string escape routines as the primary protection (escaping is error-prone and not sufficient). Use parameter binding instead.

## Safe patterns and code examples
- SQLite3 / DB-API paramstyle (qmark or named)
```python
# sqlite3 (qmark) - safe: parameters separate from SQL
import sqlite3

def get_user(conn, user_id):
    # SECURITY: parameterized query - prevents SQLi
    cur = conn.cursor()
    cur.execute("SELECT id, name FROM users WHERE id = ?", (user_id,))
    return cur.fetchone()
```

- psycopg2 (Postgres, %s placeholders)
```python
import psycopg2

def find_user(conn, username):
    # SECURITY: parameterized query - prevents SQLi
    with conn.cursor() as cur:
        cur.execute("SELECT id, email FROM users WHERE username = %s", (username,))
        return cur.fetchone()
```

- MySQLdb / PyMySQL (paramstyle %s)
```python
def find_orders(conn, customer_id):
    # SECURITY: parameterized query - prevents SQLi
    with conn.cursor() as cur:
        cur.execute("SELECT * FROM orders WHERE customer_id = %s", (customer_id,))
        return cur.fetchall()
```

- SQLAlchemy Core (use bind params) and ORM
```python
# SQLAlchemy Core
from sqlalchemy import text

def get_product(engine, sku):
    # SECURITY: parameterized query via SQLAlchemy text() binds
    with engine.connect() as conn:
        result = conn.execute(text("SELECT * FROM products WHERE sku = :sku"), {"sku": sku})
        return result.fetchall()

# SQLAlchemy ORM
def get_user_by_email(session, email):
    # SECURITY: ORM filters parameterize automatically
    return session.query(User).filter(User.email == email).one_or_none()
```

- asyncpg (async Postgres)
```python
import asyncpg

async def fetch_row(pool, user_id):
    # SECURITY: parameterized query - asyncpg uses $1, $2 placeholders
    async with pool.acquire() as conn:
        return await conn.fetchrow("SELECT * FROM users WHERE id = $1", user_id)
```

- Dynamic identifiers (table/column names): use allowlist
```python
ALLOWED_TABLES = {"users", "orders", "products"}

def query_table(conn, table_name, id):
    if table_name not in ALLOWED_TABLES:
        raise ValueError("invalid table")
    # construct SQL using validated identifier; still use params for values
    sql = f"SELECT * FROM {table_name} WHERE id = %s"
    cur = conn.cursor()
    cur.execute(sql, (id,))
    return cur.fetchall()
```

## Examples of required inline comments and PR metadata
- Above any query in generated code:
  - "# SECURITY: parameterized query - prevents SQLi"
- Generated PR must include:
  - "Security: SQL parameterization used for endpoints X, Y; validators: {fields}; CI scanners: semgrep/CodeQL configured"

## Static analysis and CI integration (enforce automatically)
- Required CI steps for all PRs that add/modify server code:
  1. Run static analyzers (semgrep, Bandit, CodeQL).
  2. Run repository semgrep rules that detect common SQLi anti-patterns (string concatenation, f-strings, .format() in SQL contexts).
  3. Run unit tests that include assertions that DB calls use parameters.
  4. Fail the PR if any SQLi rule is triggered.

- Example semgrep rule snippets (add to repo under .semgrep/*.yaml)
```yaml
rules:
  - id: python-sqli-string-concat
    patterns:
      - pattern: |
          $X = "$SQL" + $Y
      - pattern: |
          $X = "%s" % $Y
      - pattern: |
          $X = f"$SQL{...}"
    message: "Possible SQL injection: avoid building SQL via string concatenation/interpolation. Use parameterized queries or ORM."
    languages: [python]
    severity: ERROR

  - id: python-sqli-format-call
    pattern: |
      $X.format(...)
    message: "Possible SQL injection via .format(); do not format SQL strings with user input. Use parameterized queries instead."
    languages: [python]
    severity: ERROR
```

- Add these checks to CI (GitHub Actions / GitLab CI) and as pre-commit hooks:
```yaml
# .github/workflows/security.yml (snippet)
name: Security checks
on: [pull_request]
jobs:
  semgrep:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Run semgrep
        uses: returntocorp/semgrep-action@v1
        with:
          config: .semgrep/
```

## Unit tests and automated checks
- Generated code must include unit tests (pytest) that:
  - Mock DB drivers and assert execute() was called with parameter placeholders and parameter tuple/dict, not with fully composed SQL strings.
  - Example test pattern:
```python
def test_query_parameterized(monkeypatch):
    executed = {}
    class DummyCursor:
        def execute(self, query, params=None):
            executed['query'] = query
            executed['params'] = params
    class DummyConn:
        def cursor(self): return DummyCursor()
    conn = DummyConn()
    get_user(conn, 1)  # function under test
    assert executed['params'] is not None
    assert ("%" not in executed['query'] and "{" not in executed['query']) or executed['params'] != None
```
- CI must run tests; failing tests block merge.

## Developer guidance and review checklist for humans
For each change that touches SQL:
- Confirm all inputs used in SQL are either:
  - Bound parameters, or
  - Validated against a strict allowlist of identifiers (table/column names).
- Ensure DB credentials use least privilege for the required operations.
- Confirm no raw DB error strings are returned to clients.
- Ensure inline "# SECURITY: ..." comment exists and explains the mitigation.
- If an exception to patterns is needed, document in PR with a detailed security rationale and approval from a security reviewer.

## Tooling: how the AI Code Assistant must behave
When asked to generate or modify server-side code involving SQL:
1. Identify any input sources (e.g., request.args, request.json, headers, path params). Treat them as tainted.
2. Always output safe patterns (see Safe patterns) for the target DB library. If the project uses an ORM, default to ORM APIs.
3. If the user requests an example of dynamic SQL structure, require and implement allowlisting and show explicit validation code.
4. Annotate generated SQL calls with the required security comment and include a brief note in the generated PR/commit message describing the mitigation and tests added.
5. If the user insists on a raw SQL string built from input, refuse and explain why, then offer the secure alternative.

## Auditing and continuous improvement
- Add semgrep/CodeQL rules to the repository and maintain them as new patterns are discovered.
- Periodically run SAST on the main branch and audit PRs touching server/database code.
- Log and track any false negatives/positives from the static analyzer and refine rules accordingly.

## Minimal required repository changes (apply on first secure generation)
- Add .semgrep/ rules from above.
- Add a GitHub Action (or CI equivalent) to run semgrep and tests on PRs.
- Add a pre-commit hook to run semgrep locally.
- Document in CONTRIBUTING.md that all SQL-affecting code must follow these instructions and include tests and security comments.

By following these rules, the AI Code Assistant will prevent generation of SQL injection vulnerabilities in future code outputs.