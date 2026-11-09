# AI Code Assistant Security & SQL Injection Mitigation Instructions

- Review and apply parameterized queries by default; forbid string interpolation of SQL with untrusted input.
- Treat all external inputs (HTTP params, headers, cookies, server vars) as tainted; require validation or safe binding.
- Provide concrete safe/unsafe code examples and mandatory patterns (DB-API, psycopg2.sql, SQLAlchemy).
- Enforce static/dynamic checks in CI (semgrep + vulnerability scanner) and fail PRs on python/Sqli (CWE-89).
- Require PR checklist items: tests for DB inputs, security-review approval when using raw SQL, and reference to resolved scan issues.

## Purpose
These instructions direct the AI Code Assistant to avoid generating code that introduces SQL injection vulnerabilities (python/Sqli, CWE-89) and to produce secure SQL usage patterns, guardrails, and CI checks so the same vulnerabilities are not reintroduced.

## Scope
Applies to all code generation and edits by the AI Code Assistant for this repository when producing Python code interacting with SQL/databases (raw DB-API, psycopg2, sqlite3, SQLAlchemy, Django ORM, etc.), and when consuming any external input (HTTP params, headers, cookies, request bodies, server environment variables).

## High-level Policy
- Default: always use parameterized queries or ORM-provided binding. Never concatenate or format SQL strings with untrusted input.
- External input is tainted: always validate/whitelist/cast, or bind as a parameter.
- Raw SQL is discouraged; when necessary, require explicit security justification, a code comment, a focused unit test, and manual security review.
- CI must run static analysis and fail the build for python/Sqli detections.

## AI Generation Rules (rules the assistant must follow)
- NEVER produce code that constructs SQL by concatenating strings or using f-strings/.format/% with values coming from HTTP parameters, environment, or any external source.
- Prefer ORM APIs (SQLAlchemy ORM, Django ORM) or DB-API parameter substitution. When using raw SQL with DB-API, always use parameter placeholders and pass parameters as a separate argument (not interpolated).
- For identifier or table/column names (which cannot be bound as parameters), use a strict whitelist or safe helper libraries (e.g., psycopg2.sql.Identifier) — never allow arbitrary user input to be inserted into identifiers.
- If an input must constrain SQL structure (e.g., column name), require an explicit whitelist mapping inside code, with a code comment explaining allowed values.
- Add automated unit tests covering boundary/edge cases for DB input handling and include examples of attack payloads to assert behavior is safe.
- When asked to generate example code that demonstrates "bad practice" for educational reasons, clearly mark it as unsafe and always include the secure alternative immediately after.

## Safe Coding Requirements and Examples

- Use DB-API parameterization:
  - psycopg2 (Postgres): use %s placeholders and pass a tuple/list.
  - sqlite3: use ? placeholders and pass a tuple.
  - Avoid building SQL via string formatting.

Unsafe (do not generate):
```python
# UNSAFE — vulnerable to SQL injection
def get_user(conn, username):
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cur = conn.cursor()
    cur.execute(query)  # DO NOT DO THIS
    return cur.fetchone()
```

Safe DB-API examples:

psycopg2:
```python
# SAFE — parameterized query
def get_user(conn, username):
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE username = %s", (username,))
    return cur.fetchone()
```

sqlite3:
```python
# SAFE — parameterized query
def get_user(conn, username):
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE username = ?", (username,))
    return cur.fetchone()
```

- Use SQLAlchemy safely (Core or ORM):

SQLAlchemy ORM:
```python
# SAFE — use ORM with parameter binding
def get_user(session, username):
    return session.query(User).filter(User.username == username).one_or_none()
```

SQLAlchemy Core (text/params):
```python
from sqlalchemy import text

def get_user(engine, username):
    with engine.connect() as conn:
        result = conn.execute(text("SELECT * FROM users WHERE username = :username"), {"username": username})
        return result.fetchone()
```

- When constructing SQL identifier names use library helpers or whitelist:

psycopg2.sql usage:
```python
from psycopg2 import sql

def select_from_table(conn, table_name, id_value):
    # whitelist allowed tables
    ALLOWED_TABLES = {"users", "orders"}
    if table_name not in ALLOWED_TABLES:
        raise ValueError("Invalid table")
    query = sql.SQL("SELECT * FROM {} WHERE id = %s").format(sql.Identifier(table_name))
    cur = conn.cursor()
    cur.execute(query, (id_value,))
    return cur.fetchone()
```

Never attempt to parameterize table/column names with normal placeholders. Use strict whitelist/Identifier helpers.

## Input Validation and Sanitization Guidelines
- Treat all external inputs as tainted (HTTP params, headers, cookies, path segments, query strings, request bodies, server vars).
- Apply the following in order:
  1. Whitelist acceptable values where possible (enumerations).
  2. Validate types and bounds: cast to int/float and fail on conversion error rather than embedding raw string input.
  3. Reject or normalize suspicious inputs early and log occurrences.
  4. For free-form user data (e.g., comments), always bind as parameter for storage; do not plug into SQL structure.

Examples:
```python
# Safe numeric handling
def get_by_id(conn, id_str):
    try:
        id_val = int(id_str)
    except ValueError:
        raise BadRequest("invalid id")
    cur = conn.cursor()
    cur.execute("SELECT * FROM items WHERE id = %s", (id_val,))
    return cur.fetchone()
```

## Forbidden Patterns (AI must not generate)
- cursor.execute("...%s..." % var) or cursor.execute(f"...{var}...")
- cursor.execute(query % vars) or query.format(vars)
- building SQL via string concatenation with + when any operand is from an external source
- passing raw user-controlled input into identifiers (table/column names) without whitelist + safe builder
- using naive escaping utilities as the only defense

## When Raw SQL Is Allowed (exception process)
If the AI is instructed to generate raw SQL (e.g., complex queries not supported by ORM):
- Require an explicit code comment explaining reason and a security justification.
- Use parameter binding for values.
- Restrict insertion of identifiers via whitelist or safe identifier constructors.
- Add a focused unit test demonstrating that typical injection payloads do not succeed.
- Mark the PR for mandatory manual security review (assign reviewer from security team).

Example header for a raw SQL block:
```python
# SECURITY REVIEW REQUIRED: Using raw SQL due to X reason.
# - Values are parameterized
# - Identifier values are whitelisted: ALLOWED = {...}
# - Unit tests cover injection attempts
```

## CI and Tooling Requirements
- Add a semgrep rule set (or equivalent static analysis) to detect string-formatted SQL used in execute/execute_call; fail CI on matches for python/Sqli. Example rule (place in repo under security/semgrep/rules/sqli.yml):

```yaml
rules:
  - id: python-sqli-basic
    patterns:
      - pattern: $C.execute($QUERY)
      - metavariable-regex:
          name: QUERY
          regex: "f|\\.|%|format"
    message: "Possible SQL injection: avoid formatted SQL. Use parameterized queries or ORM binding."
    languages: [python]
    severity: ERROR
```

- Run the repository's vulnerability scanner and semgrep during CI; configure job to fail the build on any detection of python/Sqli (scanner output must be non-empty).
- Add pre-commit hooks to run basic linters/static checks (flake8) and the security scan.
- Optional: run dynamic tests that attempt common SQL injection payloads against test DB to assert protections.

CI step pseudocode:
```yaml
jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Install dependencies
        run: pip install -r requirements-dev.txt
      - name: Run semgrep
        run: semgrep --config security/semgrep/rules --quiet
      - name: Run vulnerability scanner
        run: python ci/run_vuln_scan.py
```
Fail the job if semgrep or vuln scanner reports python/Sqli.

## Code Review and PR Requirements
- Any PR touching database code must:
  - Include unit tests for DB input handling.
  - Show semgrep and vulnerability scan passing (or include remediation steps).
  - Add security justification for any raw SQL usage (see exception process).
  - Assign a security reviewer if semgrep/vuln scanner previously flagged python/Sqli.
  - Mention resolved vulnerability IDs (e.g., CWE-89) in PR description when applicable.

## Tests and QA
- Unit tests must cover:
  - Typical valid inputs.
  - Malicious inputs (attempted SQL injection payloads).
  - Identifier whitelist enforcement.
- Use ephemeral/test databases in CI for dynamic assertions where needed.

## Developer Guidance & Allowed Libraries
- Preferred: SQLAlchemy ORM/Core, Django ORM (use their binding APIs).
- For PostgreSQL: psycopg2 with psycopg2.sql.Identifier for identifiers.
- For SQLite: built-in sqlite3 with ? placeholders.
- Avoid crafting SQL via concatenation libraries or home-grown escaping. Vet third-party libraries for secure parameterization.

## Prompts / Instruction Templates for AI Generation (to embed in assistant model)
- When asked to generate DB code, prepend internal rule: "Treat all inputs as tainted. Use parameterized queries or ORM binding. Do not format SQL strings with user input."
- If user asks for dynamic SQL building, require the assistant to:
  1. Ask whether any input comes from external sources; if yes, require whitelist/security justification.
  2. Output both the secure implementation and unit tests demonstrating safety.

## Appendix: Example Semgrep Rule (detailed)
Place under security/semgrep/rules/sqli-detect.yml:

```yaml
rules:
  - id: python-sqli-execute-formatted
    languages: [python]
    message: "Possible SQL injection: avoid formatted SQL in execute() calls. Use parameterization or ORM binding."
    severity: ERROR
    patterns:
      - pattern: $C.execute($Q)
      - pattern-inside:
          - pattern-either:
              - pattern: f"$STR"
              - pattern: "$STR % $X"
              - pattern: "$STR.format($X)"
    metadata:
      cwe: "CWE-89"
      confidence: HIGH
```

Notes: adjust semgrep rule patterns to match your codebase style. The CI job must run semgrep with this rule set and fail on any matches.

## Enforcement & Remediation Workflow
- Any CI failure reporting python/Sqli must block merge. The PR must be updated to remove insecure patterns or justify and secure them per the "When Raw SQL Is Allowed" section.
- Maintain an issue tracker label (security/sqli) and require remediation PRs to reference the scanner finding id.

## Change Log & Ownership
- Security owner: add team or individual responsible for reviews in repository docs.
- Keep this file updated when new patterns, libraries, or scanners are adopted.

By following these instructions, the AI Code Assistant will avoid generating code that causes python/Sqli (CWE-89) and will produce secure, reviewable database access patterns suitable for this repository.