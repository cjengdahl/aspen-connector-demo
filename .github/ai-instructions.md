# AI Code Assistant — Secure Coding Instructions (Preventing SQL Injection)

## Revision checklist
- Enforce generation of parameterized queries or ORM-based queries for all SQL use.
- Forbid string concatenation or formatting with untrusted input in SQL contexts; require whitelisting for identifiers.
- Add prompt/response constraints so the assistant explains and documents security measures in generated code.
- Integrate static analysis (bandit/semgrep) and unit tests into CI to catch regressions.
- Provide examples, “allowed”/“disallowed” patterns, and reviewer checklist to ensure compliance.

## Purpose and scope
These instructions define mandatory rules and examples the AI Code Assistant must follow when generating or modifying code that interacts with SQL databases. They are focused on preventing SQL Injection (CWE-89) by ensuring generated code treats all external input as untrusted and only uses safe patterns.

## Mandatory secure-code rules for generated code
1. Always treat external input (HTTP params, request bodies, headers, environment variables, files, etc.) as tainted.
2. Never interpolate or concatenate tainted values into SQL strings. Disallow f-strings, % formatting, str.format, or + concatenation that inserts untrusted input into SQL.
3. Use parameterized queries (DB-API parameter binding, prepared statements), ORM query builders, or safe SQL libraries for all value bindings.
4. If runtime SQL identifiers (table/column names) are required, map them against a strict whitelist (no direct string use of user input).
5. For multi-value clauses (IN lists), build placeholders and pass values as parameters rather than joining values into a string.
6. Add explicit input validation and whitelisting for any non-value SQL tokens (identifiers, ORDER BY columns, directions).
7. Generated code must include a short comment explaining what mitigation is used (e.g., "uses parameterized query", "whitelists table names").
8. If the assistant cannot produce a secure solution (e.g., ambiguous external input location), it must refuse and request clarification rather than generating insecure code.

## Required behavior for the AI Code Assistant
- Before returning code that touches a database, the assistant must:
  - Identify all external inputs used in the SQL context.
  - Ensure each is either parameterized, validated, or whitelisted.
  - Include a one-line comment in the code explaining the mitigation.
- The assistant should prefer ORM or query-builder patterns over raw SQL.
- If a single SQL statement cannot be safely parameterized (e.g., dynamic column names), the assistant must:
  - Use a server-side whitelist for the allowed names.
  - Show the whitelist and validation code inline.
- The assistant must produce unit test suggestions that exercise attempted SQL injection inputs for any changed/added DB code.

## Disallowed patterns (explicit)
- Any SQL constructed with user input via:
  - f-strings: cursor.execute(f"SELECT ... {user_input}")
  - % formatting: cursor.execute("SELECT ... %s" % user_input)
  - str.format(): cursor.execute("SELECT ... {}".format(user_input))
  - String concatenation: "SELECT ..." + user_input
- Direct insertion of raw HTTP parameters into SQL without binding or validation.
- Using user-provided identifiers without a whitelist.

## Allowed patterns and examples (Python)

Bad (disallowed) — DO NOT GENERATE:
```python
# DISALLOWED: interpolation of user input -> SQL injection risk
user_id = request.args.get("id")
query = "SELECT * FROM users WHERE id = %s" % user_id
cursor.execute(query)
```

Good (parameterized DB-API) — REQUIRED for value binding:
```python
# SAFE: parameterized query (sqlite3 uses ? placeholders)
user_id = request.args.get("id")
cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
# Comment: uses parameterized binding to avoid SQL injection
```

Good (psycopg2 example) — REQUIRED for PostgreSQL:
```python
# SAFE: psycopg2 uses %s placeholders but parameters are passed separately
user_id = request.args.get("id")
cur.execute("SELECT * FROM users WHERE id = %s", (user_id,))
# Comment: uses parameterized binding to avoid SQL injection
```

Good (SQLAlchemy ORM) — PREFERRED if available:
```python
# SAFE: ORM query avoids manual SQL and binds parameters automatically
user_id = request.args.get("id")
user = session.query(User).filter(User.id == user_id).one_or_none()
# Comment: uses ORM filtering which parameterizes values
```

Good (SQLAlchemy text with bind params):
```python
from sqlalchemy import text
sql = text("SELECT * FROM users WHERE id = :id")
session.execute(sql, {"id": user_id})
# Comment: uses text() with named bind parameters
```

Handling identifiers (whitelisting) — when table/column must be dynamic:
```python
# SAFE: whitelist dynamic table name; allowed_tables maps public input to safe identifiers
allowed_tables = {"users": "users", "orders": "orders"}
table_key = request.args.get("table")
if table_key not in allowed_tables:
    raise ValueError("Invalid table")
sql = f"SELECT * FROM {allowed_tables[table_key]} WHERE id = ?"
cursor.execute(sql, (user_id,))
# Comment: table name validated against whitelist; only values are parameterized
```

Handling IN-lists safely:
```python
# SAFE: expand placeholders for IN() and bind values as parameters
ids = request.args.getlist("ids")  # e.g., ["1", "2", "3"]
placeholders = ",".join(["?"] * len(ids))
cursor.execute(f"SELECT * FROM users WHERE id IN ({placeholders})", ids)
# Comment: constructs placeholders then binds values to avoid injection
```

## Input validation and sanitization recommendations
- Prefer type validation (int(), uuid parsing) for identifiers and numeric values.
- For strings validated against patterns, use strict regex anchored patterns and length limits.
- For enumerations or direction keywords (e.g., ORDER BY ASC/DESC), use explicit map/whitelist:
  - Example: sort_dir = "ASC" if req_dir == "asc" else "DESC" — only after checking allowed set.
- Never attempt to sanitize by escaping alone; escaping is brittle—parameterization is required for values.

## AI prompt/response constraints (how to instruct the assistant)
- When asked to generate code that touches a DB, the prompt must include:
  - The source of any external inputs (e.g., request.args["id"]) and their expected types.
  - Whether an ORM is available; preferred DB library.
- The assistant must always output:
  - The final code using parameterized queries/ORM.
  - A short (1-2 line) comment explaining the security measure(s).
  - If any identifier is dynamic, the assistant must include a whitelist and show the mapping code.
- If the prompt lacks information to safely bind/validate inputs, the assistant must ask clarifying questions instead of guessing.

## CI / Static analysis and automated checks
- Add these checks to CI (example GitHub Actions snippet):
```yaml
name: security-scan
on: [pull_request]
jobs:
  static-analysis:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.10'
      - name: Install tooling
        run: |
          python -m pip install --upgrade pip
          pip install bandit semgrep
      - name: Run bandit (security checks)
        run: bandit -r .
      - name: Run semgrep (custom SQLi rules)
        run: semgrep --config path/to/sql_injection_rules.yml .
```
- Required scanners:
  - Bandit (Python) with policies to detect use of string formatting in SQL contexts.
  - Semgrep with a rule set that flags concatenation/f-strings/formatting when SQL keywords are present.
- Block merging for PRs with static-analysis failure or new SQL-related findings.

## Example semgrep rule snippet (detect string interpolation combined with SQL keywords)
```yaml
rules:
  - id: risky-sql-string-format
    patterns:
      - pattern-inside: |
          $DB.execute($STR)
      - pattern-either:
          - pattern: "$STR = f\"$SQL\""
          - pattern: "$STR = \"%\" % $X"
          - pattern: "$STR = $SQL.format($X)"
    message: "Avoid building SQL with string interpolation/formatting; use parameterized queries or ORM."
    severity: ERROR
    languages: [python]
```

## Unit tests & fuzz tests
- Add unit tests asserting that functions accepting external input perform parameterized queries.
- Add simple injection tests that pass typical payloads (e.g., "' OR '1'='1") and verify they do not alter query semantics or leak data.
- Example test concept (pytest):
```python
def test_user_query_parameterized(db_cursor, client):
    resp = client.get("/users?id=1' OR '1'='1")
    # Assert application did not return all users or crash
    assert resp.status_code == 200
    assert "unexpected results" not in resp.text
```

## Code review checklist (for human reviewers)
- Confirm no SQL strings are constructed with user input via concatenation or formatting.
- Confirm parameters are passed to execute() or ORM filters are used.
- Verify any dynamic table/column names are validated against a server-side whitelist.
- Confirm clear security comment exists in the generated code explaining the mitigation.
- Run static analysis locally (bandit/semgrep) and ensure no new SQLi findings.

## Enforcement policy for the AI Code Assistant
- If an AI-generated change introduces disallowed patterns (detected by CI or reviewer), the assistant must:
  - Provide a secure rewrite with parameterized queries/ORM and include explanation and tests.
  - Annotate the PR with which rule(s) were violated and how the fix addresses them.
- Refuse to output insecure SQL construction and surface a remediation path instead.

## References
- CWE-89: SQL Injection — https://cwe.mitre.org/data/definitions/89.html
- DB-API parameterization: https://www.python.org/dev/peps/pep-0249/
- SQLAlchemy parameterization and text(): https://docs.sqlalchemy.org/

--- 
Follow the rules above in all future code generation. Any SQL-capable code returned by the assistant must be demonstrably safe against SQL injection by adhering to these policies.