# AI Code Assistant — Security & SQL Injection (CWE-89) Guidelines

## Revision Plan (high-level checklist)
- Require parameterized queries and prepared statements by default; ban string interpolation/concatenation for SQL.
- Treat all server/HTTP inputs as tainted sources and enforce validation/whitelisting before use.
- Prefer safe ORMs/query builders and show secure code patterns for common Python DB APIs.
- Add CI/SAST requirements (Semgrep/Bandit/SNYK rules) that fail builds on SQLi patterns.
- Enforce code-review and security-approval workflow for any dynamic/raw-SQL generation.
- Provide runnable examples and minimal Semgrep rule snippets to detect insecure patterns.

## Purpose and Scope
These instructions direct the AI Code Assistant tool to generate Python code that is robust against SQL Injection (CWE-89). They apply to generated code that interacts with databases and accepts any input from HTTP requests, servers, or other untrusted sources. Follow these rules for all languages and DB clients used by the project; examples below focus on Python DB-API and SQLAlchemy.

## High-level Security Policies (mandatory)
- Always use parameterized queries / prepared statements for any SQL that includes dynamic data.
- Never construct SQL by concatenating strings, using f-strings, or formatting with % / .format with untrusted input.
- Treat request inputs (query params, form data, headers), server environment variables, CLI args, and file contents as tainted until validated/whitelisted.
- Do not use user-supplied values directly as SQL identifiers (table/column names). If you must, require strict whitelisting and mapping.
- Prefer ORM methods or query builders that automatically parameterize values. If raw SQL is required, use bind parameters.
- Log only sanitized versions of inputs; never log raw SQL with user data.

## AI Generation Rules (what the assistant must do)
- Default: generate parameterized DB access code. If receiving a prompt that attempts to include user data into SQL via interpolation, rewrite and return a safe parameterized version.
- If asked to generate dynamic SQL (e.g., dynamic ORDER BY, column selection), require or generate a whitelist mapping in code and reject direct use of user values as identifiers.
- If the prompt lacks details about how inputs are validated/typed, ask a clarifying question before generating code that uses those inputs in SQL.
- If asked to generate example/test data including vulnerable patterns, annotate clearly and provide a secure alternative implementation first.

## Secure Coding Patterns and Examples

### Python DB-API (sqlite3 / psycopg2 / MySQLdb)
Insecure (do not generate):
```python
# INSECURE: vulnerable to SQL injection
username = request.args.get("username")
query = "SELECT * FROM users WHERE username = '%s'" % username
cursor.execute(query)
```

Secure (generate this pattern):
```python
# Secure with parameterized query (DB-API)
username = request.args.get("username")
# Always use parameterized execution; placeholders differ by driver:
# psycopg2 / MySQLdb: %s
# sqlite3: ?
cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
# sqlite3 example:
# cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
```

### psycopg2 with named parameters
```python
from psycopg2 import sql

# Using DB-API parameterization with psycopg2
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
```

### SQLAlchemy ORM (preferred)
```python
# Preferred: ORM query generation automatically parameterizes values
user = session.query(User).filter(User.username == username).one_or_none()
```

### SQLAlchemy Core with bindparams
```python
from sqlalchemy import text

stmt = text("SELECT * FROM users WHERE username = :username")
result = connection.execute(stmt, {"username": username})
```

### Safe dynamic identifier pattern (whitelist mapping)
Do not interpolate arbitrary column names. Instead map user inputs to allowed identifiers.
```python
# Allowed sort columns mapping
ALLOWED_SORT = {
    "name": "name",
    "created": "created_at",
    "email": "email"
}

requested = request.args.get("sort", "name")
sort_column = ALLOWED_SORT.get(requested)
if not sort_column:
    raise ValueError("Invalid sort parameter")

# Use parameterized query for values; safe mapping for identifier
query = f"SELECT id, name, email FROM users ORDER BY {sort_column} LIMIT %s"
cursor.execute(query, (limit,))
```
Note: The identifier is taken from a safe, static mapping only.

## Input Validation and Whitelisting
- Validate types and lengths server-side (e.g., ints for IDs; enforce min/max and length limits for strings).
- Use strict allowlists for any dynamic SQL identifiers, SQL fragments, or clauses.
- Reject inputs that contain SQL meta-characters when these are not allowable (e.g., semicolons, comment markers).
- Prefer stricter validation (type checks, regex) rather than attempting to "escape" everything.

## Patterns to Avoid (AI must not generate these)
- String concatenation / interpolation to build SQL:
  - "SELECT ... " + user_input
  - f"SELECT ... {user_input}"
  - "SELECT ... %s" % user_input
- Using Python .format() or template engines to inject untrusted values into SQL.
- Passing preformatted SQL strings that include user data to execute() without parameters.
- Directly using request.args/request.form values as table/column names without mapping.

## CI / Static Analysis Requirements (enforced in repo)
- Add Semgrep, Bandit (or equivalent SAST) checks to CI. Fail the build on high-severity SQLi rules.
  - Example commands:
    - bandit -r .
    - semgrep --config path/to/sql-injection-rules.yml
- Include/enable rules that detect:
  - execute(...) calls with string concatenation or f-strings
  - use of .format or % to prepare SQL passed to execute
  - direct use of request.args / request.form inside SQL expressions
- Example minimal Semgrep rule (add to repo rules):
```yaml
rules:
  - id: python-sqli-basic
    patterns:
      - pattern: $CUR.execute($SQL)
    message: "Possible SQL injection: avoid passing formatted SQL strings to execute(); use parameterized queries or ORM methods."
    languages: [python]
    severity: ERROR
```
(Expand rules with patterns that match f-strings, + concatenation, % formatting, and .format.)

## Tests and Validation
- Add unit tests that assert queries use parameterization where applicable (e.g., mock cursor and assert execute called with parameters, not preformatted SQL).
- Add integration tests that exercise common tainted inputs to verify app behavior and that inputs are not interpreted as SQL.
- Add fuzz tests for inputs containing special SQL characters and ensure they are treated as data, not commands.

## Code Review & Approval Workflow
- Any PR that includes raw SQL, dynamic SQL generation, or bypasses ORM must:
  - Include a security rationale and justification in the PR description.
  - Include tests demonstrating safe behavior (parameterization and validation).
  - Be approved by a designated security reviewer before merging.
- The AI-generated code should include comments indicating why parameterization is used and noting any whitelisting mappings.

## Logging, Error Handling, and Secrets
- Never log full user-supplied SQL or raw request payloads. Log sanitized summaries only.
- Avoid embedding database credentials or secrets into generated code; use environment variables or secret management and follow project secret-handling practice.

## Tooling Behavior Requirements for the AI Code Assistant
- Prefer safe libraries/APIs in generated code: SQLAlchemy ORM/Core, DB-API parameterization, query builders.
- If asked to produce an unsafe example for illustration, always accompany it with a secure refactor and clearly mark the unsafe code as expressly for demonstration only.
- When generating migration or admin scripts that may run SQL from files, require explicit confirmation and generate safe loaders that parameterize values and validate inputs.
- Always include a brief note in generated code when the code depends on caller-side validation (and recommend server-side validation).

## References and Further Reading
- CWE-89: SQL Injection — https://cwe.mitre.org/data/definitions/89.html
- Python DB-API parameter styles and best practices
- SQLAlchemy documentation: ORM and text() bindparams
- Semgrep community rules for SQL injection detection

## Enforcement Summary (what will be blocked)
- CI will reject code that: constructs SQL via string interpolation/concatenation with untrusted input, omits parameter binding, or uses unvalidated user input as identifiers. PRs that bypass these protections require explicit security reviewer approval and justification.