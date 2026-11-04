# AI Code Assistant: Secure-Code Generation Instructions (SQL Injection Mitigations)

- Review generated code for any database access: treat all external inputs (HTTP params, headers, cookies, path segments) as tainted by default and never interpolate them into SQL.
- Enforce parameterized queries / prepared statements or ORM APIs for all DB operations; ban string interpolation, f-strings, % formatting, and concatenation for SQL composition.
- Add semgrep/static-analysis rules and CI checks to catch dangerous patterns and fail PRs that introduce them.
- Require generated code to include short Security-Notes comments that explain how inputs are validated/escaped and why the pattern is safe.
- Provide safe examples (sqlite3, psycopg2, SQLAlchemy) and explicitly list prohibited patterns and remediation steps.

## Purpose
These instructions update the AI Code Assistant to prevent generation of code vulnerable to SQL injection (CWE-89). They are concise, actionable rules and examples the assistant must follow when producing or modifying Python code that interacts with databases.

## High-level generation policies (must-follow)
- Treat any data originating from network, HTTP request objects (e.g., request.args, request.form, request.values, request.headers, request.get_json()), environment, CLI args, or other external sources as tainted/untrusted.
- Never build SQL statements by concatenating strings, using f-strings, using %-formatting, or using .format() with untrusted values.
- Always use:
  - Parameterized queries / bound parameters as supported by the DB driver.
  - ORMs (SQLAlchemy, Django ORM, etc.) using parameter binding, query builders, or model APIs.
  - Prepared statements / stored procedures with bound parameters when applicable.
- If a literal query must be used, bind all user values through the driver’s parameter mechanism (do not substitute into the string).
- When validation is required, use strict whitelisting (allowed patterns, types, length) rather than blacklisting. Convert values to safe types (e.g., integer conversion for IDs) before use.
- If input controls allow only a restricted set of values (enum-like), validate against the exact set server-side.
- Include short inline "Security-Notes" comments in generated DB-access code explaining how inputs are sanitized/validated and showing the bound parameters.

## Prohibited patterns (do not generate)
Do not generate code that uses any of the following when constructing SQL queries with external input:
- f-strings with variables in SQL, e.g. f"SELECT * FROM users WHERE id = {user_id}"
- String concatenation, e.g. "SELECT ..." + user_input
- %-formatting, e.g. "SELECT ... %s" % user_input
- str.format(), e.g. "SELECT ... {}".format(user_input)
- Directly executing user-provided SQL statements without validation and binding
- Passing tainted input to APIs that accept raw SQL without binding (e.g., .execute(sql_string) where sql_string contains unbound user input)

## Required safe patterns and examples

- sqlite3 (Python builtin): use ? placeholders
```python
# Safe: parameterized query with sqlite3
# Security-Notes: user_id is treated as untrusted; passed as bound parameter to avoid SQL injection.
import sqlite3
conn = sqlite3.connect("app.db")
cur = conn.cursor()
user_id = int(request.args.get("id"))  # whitelisted conversion to int
cur.execute("SELECT * FROM users WHERE id = ?", (user_id,))
rows = cur.fetchall()
```

- psycopg2 (Postgres): use %s placeholders (pass parameters as tuple)
```python
# Safe: psycopg2 parameterized query
# Security-Notes: request.params['q'] validated/escaped via parameter binding; no string interpolation.
import psycopg2
conn = psycopg2.connect(dsn)
cur = conn.cursor()
search = request.args.get("q", "")
cur.execute("SELECT * FROM products WHERE name ILIKE %s", (f"%{search}%",))
results = cur.fetchall()
```

- SQLAlchemy Core / ORM: prefer ORM filters or text() with bindparams
```python
# Safe: SQLAlchemy ORM
# Security-Notes: user inputs are bound by the ORM; no manual string composition.
from sqlalchemy.orm import Session
session = Session(engine)
user_id = int(request.args.get("id"))
user = session.query(User).filter(User.id == user_id).one_or_none()
```

```python
# Safe: SQLAlchemy text() with parameters
from sqlalchemy import text
stmt = text("SELECT * FROM orders WHERE customer_id = :cid")
params = {"cid": int(request.args.get("customer_id"))}
result = session.execute(stmt, params).fetchall()
```

## Taint handling, validation, and transformation rules
- Always mark request-derived variables as tainted in model reasoning and require binding.
- Prefer server-side type coercion and whitelisting:
  - For numeric IDs: cast to int and handle exceptions.
  - For enums/choices: check against an explicit set (allowed_values).
  - For search/like patterns: escape wildcards or bind as parameter (driver handles escaping).
- If an input is used for SQL identifiers (table names, column names), do not accept arbitrary values. Use a server-side map of allowed identifiers and select the identifier by key (no string substitution).
- For SQL fragments that cannot be parameterized (rare), require:
  - Strong justification in the generated code comment.
  - Selection from a server-side whitelist of fragments.
  - A follow-up manual code review item flagged in the PR.

## AI assistant prompt/behavior constraints (how the tool should generate code)
- Before emitting DB-access code, the assistant must:
  - State (in a short comment in-code) which inputs are tainted and how they're validated or bound.
  - Emit only safe patterns (see examples above) or require migration to ORM/parameterization.
- If the code requested would naturally produce a raw SQL string containing user input, the assistant must:
  - Refuse to generate unsafe code.
  - Provide a secure alternative using parameterization or ORM.
- Always include a one-line "Security-Notes" comment adjacent to the DB call explaining why the chosen method prevents SQL injection.
- When suggesting third-party libraries or drivers, prefer well-maintained, current, and widely used libraries and recommend parameterized APIs over string-building utilities.

## CI / Static analysis / PR requirements
- Add/enable automated checks in CI that block PRs with SQL injection patterns:
  - Run semgrep with rules that detect f-strings, .format(), % formatting, or concatenation used with DB execute calls.
  - Run Bandit or a comparable security linter and fail on relevant findings.
- PRs that modify or add DB access must include:
  - A brief security rationale in the PR description describing how inputs are validated/escaped and which binding method is used.
  - Unit tests covering parameter-binding and inputs that could have triggered injection (e.g., strings with quotes, SQL fragments).
- Example semgrep rule (add to repo semgrep config):
```yaml
rules:
  - id: python-sqli-fstring
    patterns:
      - pattern: |
          $DB.execute(f"$SQL")
      - pattern-either:
          - pattern: |
              $DB.execute($SQL + $TAIL)
          - pattern: |
              $DB.execute($SQL % $ARGS)
    message: "Possible SQL injection: avoid f-strings, concatenation, or %-formatting for SQL. Use parameterized queries/ORM."
    severity: ERROR
    languages: [python]
```
- Additional semgrep rules should detect .format(), string concatenation passed into execute/execute_query functions, and direct use of request.* in SQL strings.

## Tests and verification
- Require unit tests for any new DB code to assert correctness and resistance to injection:
  - Include tests that pass dangerous payloads (e.g., quotes, SQL keywords) through inputs to ensure they are treated as data (not executed).
- Encourage property-based or fuzz testing for DB input handlers.
- Periodically run dependency and vulnerability scanners for DB drivers and related libs.

## Code review checklist for maintainers
- Verify all DB queries bind external inputs through driver/ORM mechanisms.
- Verify no raw SQL concatenation with request-derived values exists.
- Confirm that any identifier insertion uses a whitelist mapping and not direct substitution.
- Confirm inline "Security-Notes" are present and accurate for each DB access in the PR.

## Minimal examples of remediation patterns
- Unsafe (do not generate):
```python
# DO NOT GENERATE: vulnerable to SQL injection
q = "SELECT * FROM users WHERE name = '" + request.args.get("name") + "'"
cur.execute(q)
```
- Remediation (generate instead):
```python
# Security-Notes: user 'name' treated as untrusted; passed as bound parameter
name = request.args.get("name", "")
cur.execute("SELECT * FROM users WHERE name = ?", (name,))
```

## Tooling recommendations
- Use semgrep rules in CI for pattern-based detection.
- Use Bandit or other SAST tools that detect common injection patterns.
- Prefer SQLAlchemy ORM or the database driver's parameterized APIs (psycopg2, mysql-connector-python, sqlite3) rather than manual string-building.

## Enforcement summary (what the assistant will do)
- Automatically treat inputs as tainted.
- Never generate string-interpolated SQL; always prefer parameterization/ORM.
- Insert Security-Notes in code output.
- Add CI and static analysis checks to block regressions.
- Provide safe code examples and refuse unsafe generation, instead returning secure alternatives.

Append these rules to the AI Code Assistant tool configuration and make them required steps in its code-generation pipeline.