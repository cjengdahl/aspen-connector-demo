# AI Code Assistant Tool — Secure Code Generation Instructions

- Quick checklist (high-level revision plan)
  - Enforce a strict “no string-concatenation” policy for SQL produced by the assistant; require parameterized queries/ORMs/prepared statements.
  - Define taint sources and require the assistant to treat those as untrusted, with mandatory sanitization/validation or parameter binding.
  - Provide concrete, minimal-safe Python examples (psycopg2, sqlite3, SQLAlchemy) and explicit banned examples.
  - Integrate static analysis and CI checks (Semgrep/Bandit) and require unit/security tests for PRs that add DB code.
  - Add generation rules for the assistant: detect when raw SQL asked for and force safe patterns plus an explicit warning/justification.

## Purpose
These instructions guide the AI Code Assistant to generate Python code that interacts with databases securely, specifically preventing SQL Injection (CWE-89). They apply whenever the assistant produces code that constructs SQL, executes queries, or handles untrusted input (HTTP params, CLI args, environment variables, etc.).

## Security policy (SQL Injection prevention)
- Always prefer high-level query builders or ORMs (SQLAlchemy ORM/Core, Django ORM, peewee) for building queries. When using raw SQL, use parameterized queries / prepared statements with bound parameters.
- Treat all external input as tainted/untrusted (HTTP parameters, request bodies, headers, cookies, query strings, WebSocket messages, CLI args, environment variables).
- Never construct SQL by concatenating strings or using formatting (%, format(), f-strings) with untrusted input.
- Input validation: apply strict whitelisting (allowed characters/values) when input must be used as identifiers (table/column names) and then use safe mapping to known identifiers rather than accepting arbitrary strings.
- Never log raw sensitive inputs (or bind parameters) in production logs.

## Taint sources (must be treated as untrusted)
- HTTP: query params, path params, POST body, headers, cookies, multipart fields.
- Environment/Config: OS env vars, process args, config files that may be user-controlled.
- CLI args and uploaded files.
- Any value reachable from the network (including inter-service requests).
For each generation request, the assistant must assume these sources are tainted unless the prompt explicitly establishes a trusted, pre-validated value and shows the validation code.

## Disallowed patterns (must never be generated)
- Building SQL by concatenating strings with untrusted variables:
  ```python
  # DISALLOWED
  query = "SELECT * FROM users WHERE username = '" + username + "';"
  cursor.execute(query)
  ```
- Using f-strings or format() to insert user input into SQL:
  ```python
  # DISALLOWED
  cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
  cursor.execute("SELECT * FROM users WHERE id = {}".format(user_id))
  ```
- Interpolating parameters into SQL identifiers without strict whitelisting:
  ```python
  # DISALLOWED
  query = f"SELECT * FROM {table_name} WHERE id = %s"
  cursor.execute(query, (id,))
  ```

## Allowed/safe patterns — Python examples

- Using psycopg2 (Postgres) with parameterized queries:
  ```python
  import psycopg2

  conn = psycopg2.connect(dsn)
  cur = conn.cursor()
  # SAFE: parameters are bound, no string formatting of values
  cur.execute("SELECT * FROM users WHERE username = %s", (username,))
  rows = cur.fetchall()
  ```

- Using sqlite3 parameter substitution:
  ```python
  import sqlite3

  conn = sqlite3.connect("db.sqlite")
  cur = conn.cursor()
  # SAFE: use ? placeholders
  cur.execute("SELECT * FROM products WHERE sku = ?", (sku,))
  ```

- Using SQLAlchemy Core with text and bound parameters:
  ```python
  from sqlalchemy import text, create_engine

  engine = create_engine(DB_URL)
  with engine.connect() as conn:
      # SAFE: bind params via execute/params
      stmt = text("SELECT * FROM users WHERE email = :email")
      result = conn.execute(stmt, {"email": email})
      rows = result.fetchall()
  ```

- Using SQLAlchemy ORM query builder (preferred for complex queries):
  ```python
  from sqlalchemy.orm import Session

  session = Session(engine)
  user = session.query(User).filter(User.username == username).first()
  ```

- Safe handling when identifiers (table/column names) need to be dynamic:
  - Do not accept arbitrary identifiers from the user.
  - Maintain an explicit whitelist mapping from user input to known safe identifiers:
  ```python
  ALLOWED_SORT_COLUMNS = {"date": "created_at", "name": "full_name"}
  sort_key = request.args.get("sort", "date")
  column = ALLOWED_SORT_COLUMNS.get(sort_key)
  if not column:
      raise ValueError("invalid sort key")
  # Use ORM or bind column via safe mapping (not string interpolation of user input)
  ```

## AI generation rules (for the assistant)
When asked to generate code that interacts with a database, follow these rules strictly:
1. Identify and mark taint sources in the prompt. If user input will reach DB queries, treat it as tainted.
2. Default to using ORM or parameterized APIs. Only generate raw SQL when explicitly requested and then:
   - Use parameter binding / prepared statements.
   - Validate/whitelist any identifiers.
   - Provide a one-line warning comment in the generated code explaining why parameterization is used and confirming no concatenation of user input.
3. Prohibit generating examples that use string concatenation, f-strings, or format() to construct SQL with untrusted inputs.
4. When asked to demonstrate SQL injection vulnerabilities (educational), generate those examples only in isolated test fixtures with clear, explicit disclaimers and never in production code; also include the safe remediation side-by-side.
5. If the assistant detects code that may be vulnerable (e.g., `.execute()` with f-strings), refuse and provide a secure rewrite.
6. Add input validation or whitelisting whenever user-input will affect SQL structure (columns/tables/order by).
7. For new DB code, automatically recommend and show how to add unit/integration tests that assert safe parameter binding.

## Static analysis, tests, and CI enforcement
- Required checks in CI for any PR that modifies DB-access code:
  - Run Semgrep with SQL-injection rules (example command):
    ```bash
    semgrep --config=p/ci --error
    ```
    Include a ruleset that flags .execute usage with string-formatting and f-strings.
  - Run Bandit for general security issues:
    ```bash
    bandit -r src/ -lll
    ```
  - Run repository unit tests (pytest).
- Example Semgrep rule (detect common Python string interpolation into .execute):
  ```yaml
  rules:
    - id: python-sql-exec-interpolation
      patterns:
        - pattern: $C.execute($SQ)
      message: "Possible SQL injection: avoid interpolated SQL strings; use parameterized queries"
      languages: [python]
      severity: ERROR
  ```
- Required test types:
  - Unit tests ensuring queries use parameters (e.g., mock cursor and assert execute called with parameter list/tuple/dict).
  - Integration tests for endpoints that hit DB should use test fixtures and assert that no SQL is constructed via string interpolation and known taint inputs are safe.

## PR and code review requirements
- Every PR that introduces or modifies DB code must:
  - Include unit tests demonstrating safe parameter usage or whitelist validation.
  - Pass Semgrep and Bandit CI gates.
  - Include an explicit "security consequences" section in the PR description describing taint sources and why the chosen approach is safe.
- Reviewer checklist (must be completed in PR template):
  - Does the code use parameterized queries or an ORM query builder? (Yes/No)
  - Are all user inputs validated or whitelisted before they affect SQL structure? (Yes/No)
  - Are there any uses of string concatenation/f-strings/format() with database queries? (Yes/No) — if yes, block merge.
  - Do tests cover malicious/edge inputs and CI scanning? (Yes/No)

## Remediation guidance (for maintainers)
- If an existing vulnerability is found (SQLi):
  - Immediately replace any concatenated SQL with parameterized statements or ORM usage.
  - Add unit tests that would have detected the injection (mocking execute and asserting parameter binding).
  - Run a full security scan (Semgrep/Bandit) and add the fix to the same PR.
  - For incidents in production, rotate database credentials and follow the incident response plan.

## Logging and data handling
- Do not log raw untrusted input or SQL statements containing unredacted parameters in production logs.
- If logging is necessary for debugging, redact or hash parameter values.

## Continuous improvement
- Periodically (quarterly) update the assistant’s generation rules with new patterns from current SAST findings.
- Keep the Semgrep/Bandit rulesets in the repository and update them as new risky patterns are discovered.

## Minimal examples (safe vs unsafe)

- Unsafe (do not generate):
  ```python
  # DO NOT GENERATE
  cursor.execute("SELECT * FROM users WHERE name = '%s'" % name)
  cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
  ```

- Safe (generate by default):
  ```python
  # SAFE - psycopg2
  cursor.execute("SELECT * FROM users WHERE name = %s", (name,))
  ```

  ```python
  # SAFE - SQLAlchemy text()
  stmt = text("SELECT * FROM items WHERE owner_id = :owner_id")
  conn.execute(stmt, {"owner_id": owner_id})
  ```

By following these concise, enforceable rules, the AI Code Assistant will avoid generating code that can lead to SQL Injection (CWE-89) and will provide maintainable, testable, and auditable database access code.