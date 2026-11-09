# AI Code Assistant Security Instructions — SQL Injection Mitigations

## Revision checklist
- Require parameterized queries / prepared statements for all generated SQL code; forbid string concatenation/f-strings with untrusted input.
- Treat all external input (HTTP params, headers, cookies, ENV, CLI args) as tainted/untrusted; always bind, validate, or escape before use.
- Provide safe examples (Python DB-API, psycopg2, sqlite3, SQLAlchemy, Django ORM) and forbid unsafe patterns.
- Integrate static analyzers and automated tests in CI (semgrep, bandit, unit tests) and block merges on SQLi findings.
- Force the AI Assistant to annotate generated DB code with security rationale and to run/require scanner output before accepting code that interacts with SQL.

## Policy: General rules for SQL / DB code generation
- Never construct SQL queries by concatenating strings or using f-strings / + with any untrusted input.
- Always use parameterized APIs or ORM binding mechanisms. Binding parameters must be passed separately to the DB driver/API (never injected into the SQL string).
- Prefer ORMs or query builders that perform automatic binding. When using raw SQL, require explicit parameter binding.
- Validate and whitelist inputs where feasible (e.g., allowlisted column names, enum values) — but validation is not a substitute for parameterization.
- All generated code that interacts with SQL must:
  - Mark taint sources in comments (e.g., "# TAINT: request.args['id']").
  - Use parameterized queries or ORM methods.
  - Include a short security note in the same PR describing how injection risk is mitigated.
- Treat SQL injection findings as "error" severity: fix before merge.

## Taint sources (always untrusted)
Treat the following as tainted/untrusted until explicitly sanitized/validated:
- HTTP inputs: request.args, request.form, request.values, request.json, request.get_data(), headers, cookies
- Query parameters and path parameters from web frameworks (Flask, FastAPI, Django requests)
- Environment variables, CLI arguments, third-party responses, file contents, and any user-supplied input

AI-generated code must annotate these sources whenever they are used to produce SQL. Example: 
```python
# TAINT: user_input = request.args.get("q")
```

## Safe coding patterns — Python examples

Unsafe pattern (forbidden):
```python
# UNSAFE: vulnerable to SQL injection — DO NOT GENERATE
user_id = request.args.get("id")                     # TAINT: external
sql = f"SELECT * FROM users WHERE id = {user_id}"    # unsafe interpolation
cursor.execute(sql)
```

Safe patterns (must be used):

- Python DB-API (sqlite3, psycopg2, MySQLdb):
```python
# SAFE: use parameterized execute with separate params
user_id = request.args.get("id")                     # TAINT
sql = "SELECT * FROM users WHERE id = %s"            # psycopg2 uses %s placeholders
cursor.execute(sql, (user_id,))
```

- sqlite3 (use ? placeholders):
```python
sql = "SELECT * FROM users WHERE id = ?"
cursor.execute(sql, (user_id,))
```

- SQLAlchemy Core (bound parameters):
```python
from sqlalchemy import text
sql = text("SELECT * FROM users WHERE id = :id")
result = connection.execute(sql, {"id": user_id})
```

- SQLAlchemy ORM (preferred for CRUD):
```python
# SAFE: ORM filter binds parameters automatically
user = session.query(User).filter(User.id == user_id).one_or_none()
```

- Django ORM (preferred):
```python
# SAFE: Django ORM binds parameters and escapes as needed
user = User.objects.filter(id=user_id).first()
```

- Raw SQL with SQLAlchemy ORM (if unavoidable):
```python
from sqlalchemy import text
sql = text("SELECT * FROM users WHERE id = :id")
# ensure params passed in separately
session.execute(sql, {"id": user_id})
```

Notes:
- When building dynamic SQL identifiers (table or column names) require strict allowlists; never bind identifiers via parameters. Example safe approach:
```python
ALLOWED_COLUMNS = {"name", "email", "created_at"}
col = request.args.get("sort")  # TAINT
if col not in ALLOWED_COLUMNS:
    raise ValueError("invalid column")
query = f"SELECT {col} FROM users WHERE id = :id"  # only safe because col was allowlisted
```
- Prefer returning and validating a concrete column name selected from a server-side list; keep the binding for values.

## Framework-specific guidance
- Flask / FastAPI / Starlette:
  - Use parameterized calls to DB drivers or SQLAlchemy; treat all request.* values as tainted.
- Django:
  - Prefer Django ORM; if using raw SQL via raw() or connection.cursor(), use params argument and never format strings with user input.
- SQLAlchemy:
  - Use bound parameters (text() with dict bindings) or ORM query methods. When using text(), prefer named binds.
- Avoid generating code that uses string interpolation to build queries for pagination, sorting, or filters — these require allowlisting or explicit mapping.

## CI: Static analysis and automated tests (example GitHub Actions)
- Add a CI job that runs semgrep and bandit (or other chosen scanners). Fail PRs where SQLi rules trigger.

.github/workflows/security.yml
```yaml
name: security-scan
on: [push, pull_request]
jobs:
  static:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: "3.10"
      - name: Install tools
        run: |
          pip install semgrep bandit
      - name: Run semgrep (rules for SQLi)
        run: semgrep --config .semgrep-rules.yml
      - name: Run bandit
        run: bandit -r .
```

Example .semgrep-rules.yml (minimal rule to catch concatenation into execute):
```yaml
rules:
  - id: python-sqli-unsafe-execute
    patterns:
      - pattern: |
          $CUR.execute($SQL)
      - pattern-not: |
          $CUR.execute($SQL, $ARGS)
      - metavariables:
          SQL:
            pattern: $X + $Y
    message: "Possible SQL injection: raw SQL concatenation passed to execute. Use parameterized queries."
    languages: [python]
    severity: ERROR
```
- Customize and expand semgrep rules to cover f-strings, + concatenation, string formatting, and raw query construction from tainted sources.
- Add unit tests that include malicious payloads (e.g., "' OR '1'='1") to assert queries remain safe (i.e., no change in schema, only parameterized filtering).

## Code review and merge policy
- PRs that add or modify code that interacts with SQL must:
  - Include security rationale comment inline indicating how user input is handled (bound, validated, allowlisted).
  - Pass the CI security-scan job (semgrep + bandit).
  - Include unit tests demonstrating correct handling of malicious input where practical.
- Any SQLi finding from static analysis is blocking and must be remediated before merge.

## AI Assistant behavior rules (must be enforced in the tool)
- When prompted to generate code that accesses a DB, the assistant must:
  - Default to ORM-based solutions or parameterized DB-API calls.
  - Never produce code that constructs SQL via concatenation or f-strings using untrusted input.
  - Annotate taint sources and the mitigation used with inline comments (e.g., "# TAINT: ...", "# MITIGATION: parameterized query").
  - Provide a one-line security rationale with the generated snippet explaining why the pattern is safe (e.g., "Uses parameterized execute to avoid SQL injection").
  - If the user insists on a raw SQL query that uses dynamic identifiers, require an explicit allowlist and show the allowlisting code.
  - Run or simulate a static-scan checklist and point out any remaining risks; refuse to produce unsafe code.
- If the assistant detects potential SQLi in existing code, it must:
  - Flag the issue explicitly and provide a corrected, parameterized replacement.
  - Provide concrete migration steps and tests to validate the fix.

## Secrets, credentials, and least privilege
- Generated code must not embed plaintext DB credentials. Use environment variables and secrets managers.
- Use least privilege DB roles: only grant the minimum permissions required for the operation (SELECT, INSERT, etc. on scoped tables).
- Include examples:
```python
# GOOD: get DB URL from environment / secret manager
db_url = os.environ["DATABASE_URL"]
```

## Tests and validation (developer responsibilities)
- Add unit/integration tests that pass malicious payloads and validate the query behavior is safe and returns expected data without executing injected commands.
- Add regression tests for any changes touching SQL construction.
- Periodically run dynamic scans (e.g., sqlmap in a safe test environment) as part of security assessments.

## Enforcement and continuous improvement
- Treat SQL Injection (CWE-89) as a critical error: update and maintain CI semgrep/bandit rules to catch newly observed patterns.
- Periodically review and expand the AI Assistant's security instruction set based on scanner output and real-world findings.
- Keep this file concise and up to date; any new rules or language-specific patterns should be added in companion snippets under the "Safe coding patterns" section.