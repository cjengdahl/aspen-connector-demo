# AI Code Assistant: Secure Coding & Generation Instructions (SQLi Mitigation)

- Quick revision plan:
  - Treat all server/http parameters and external inputs as tainted and never inline them into SQL.
  - Require and prefer parameterized queries, ORMs, or prepared statements in generated code.
  - Forbid generation of string-concatenated/f-string/.format SQL using user input; insert explicit comments and validators when inputs are required.
  - Add automated static checks and CI gate rules (semgrep, bandit) to detect unsafe SQL patterns before merge.
  - Produce minimal safe examples and unit-test templates with every DB access-generation task.

## Purpose and scope
These instructions direct the AI Code Assistant to prevent SQL Injection (CWE-89) vulnerabilities when generating or modifying code that interacts with databases. They apply to all code generation involving SQL, direct DB drivers, ORMs, stored procedures, query builders, migrations, or scripts that incorporate external inputs (HTTP params, headers, cookies, server variables, environment variables).

## Fundamental rules (must follow)
- Treat any server-side HTTP parameter (query/body/header/cookie/path param) and any external input as tainted by default.
- Never generate SQL by concatenating, interpolating, or formatting tainted values into query strings. This includes f-strings, str.format, "%" formatting, string concatenation, or `.join()` with tainted parts.
- Always use parameterized queries / bound parameters / prepared statements or an ORM's parameter binding for any variable content in a query.
- If raw SQL is necessary, bind values using the DB driver’s parameter placeholder mechanism and pass values separately.
- When the code must accept raw SQL text from user or config, require explicit, documented, and reviewed sanitization and permission checks; prefer disallowing this pattern altogether.
- When generating code that parses or casts input to a DB type, generate explicit validation/whitelisting and safe conversion (e.g., int() with try/except, regex/enum whitelist).

## Generation guidelines for Python (required)
- Preferred approaches (in order):
  1. ORM query methods (Django ORM, SQLAlchemy ORM) using filter/query methods.
  2. SQLAlchemy Core with text() and bind parameters.
  3. DB-API parameterized execution (psycopg2, sqlite3, MySQLdb) using positional or named placeholders and separate parameter tuples/dicts.
- Forbidden patterns (do not generate):
  - Any use of f-strings, .format(), or % to inject variables into SQL.
  - Concatenating strings with + to form SQL using user input.
  - Executing SQL strings that embed unsanitized/untainted values.

- Examples

  Insecure (do not generate):
  ```python
  # INSECURE - DO NOT GENERATE
  user_id = request.args.get("id")
  query = f"SELECT * FROM users WHERE id = {user_id}"
  cursor.execute(query)
  ```

  Secure with DB-API (psycopg2, sqlite3):
  ```python
  # SECURE - use parameterized queries
  user_id = request.args.get("id")
  try:
      user_id = int(user_id)
  except (TypeError, ValueError):
      # handle invalid input
      raise BadRequest("invalid id")

  query = "SELECT * FROM users WHERE id = %s"  # psycopg2 style
  cursor.execute(query, (user_id,))
  ```

  Secure with SQLAlchemy Core:
  ```python
  from sqlalchemy import text
  stmt = text("SELECT * FROM users WHERE id = :id")
  result = connection.execute(stmt, {"id": user_id})
  ```

  Secure with Django ORM:
  ```python
  user = User.objects.filter(id=user_id).first()
  ```

## Taint handling and prompting behavior
- When the assistant is asked to generate SQL or DB access code and the prompt includes user-controlled inputs, it must:
  - Mark the input variables as tainted in generated code comments.
  - Generate explicit validation/whitelisting for the input or require caller to provide a validated value.
  - If the prompt lacks context on input trust or expected types, ask a clarifying question before producing DB-access code. If the user does not provide additional info, default to generating parameterized code plus defensive validation.
- Example generated comment:
  ```python
  # NOTE: `user_input` is tainted (HTTP param). Do not remove validation/binding.
  ```

## Code patterns & templates the assistant must use
- Always separate SQL text from parameters:
  - DB-API: cursor.execute(sql, params)
  - SQLAlchemy text(): connection.execute(text(sql), params)
  - ORM: use filter()/where() methods with bound values.
- For dynamic identifiers (table/column names), never accept raw user input. If dynamic identifiers are required, require an explicit internal whitelist or mapping and generate code that maps user-provided keys to allowed identifiers.

  Safe dynamic identifier example:
  ```python
  allowed_cols = {"name": "name", "email": "email"}
  col = allowed_cols.get(request.args.get("col"))
  if not col:
      raise BadRequest("invalid column")
  query = text(f"SELECT {col} FROM users WHERE id = :id")  # col guaranteed from whitelist
  result = conn.execute(query, {"id": user_id})
  ```

## Testing, static analysis, and CI requirements (must be enforced)
- Generated code should include or be accompanied by tests verifying:
  - Parameter binding is used (unit test can assert that SQL strings contain placeholders and parameters are passed separately).
  - Validation logic for inputs (type/format/whitelist tests).
- Add the following automated checks to repository CI for PR gating (example GitHub Actions snippet is provided below). PRs must fail CI if semgrep or bandit flags SQL injection patterns.
  - semgrep with rules to detect SQL string concatenation, f-strings containing SQL, or cursor.execute(...) with a single string literal that concatenates variables.
  - bandit for Python issues.
- Example GitHub Actions job (include in .github/workflows/security.yml):
  ```yaml
  name: security-scan
  on: [pull_request]
  jobs:
    semgrep:
      runs-on: ubuntu-latest
      steps:
        - uses: actions/checkout@v3
        - name: Run semgrep
          uses: returntocorp/semgrep-action@v2
          with:
            config: "p/ci"   # or repo rule set + custom rules
    bandit:
      runs-on: ubuntu-latest
      steps:
        - uses: actions/checkout@v3
        - name: Run bandit
          run: |
            pip install bandit
            bandit -r .
  ```
- Provide at least one semgrep rule for SQL concatenation detection (add to repo ruleset):
  ```yaml
  rules:
    - id: python-sqli-string-concat
      language: python
      message: "Potential SQL injection: do not build SQL with string concatenation or f-strings; use parameterized queries."
      severity: ERROR
      patterns:
        - pattern: |
            $CURSOR.execute($SQL + $OTHER)
        - pattern: |
            $CURSOR.execute(f$TEMPLATE)
        - pattern: |
            $CURSOR.execute($SQL % $VAL)
  ```

## PR and reviewer guidance
- Every PR that adds or changes DB access must include:
  - A short security note describing why generated code is safe (parameterization, validation, whitelist).
  - Unit tests or CI evidence that static checks pass.
  - Explicit list of tainted sources used and how they were validated or bound.
- Reviewers must verify:
  - No string interpolation/concatenation of tainted data into SQL.
  - Proper use of parameter binding or ORM APIs.
  - Presence of input validation/whitelist logic or a documented reason why input is trusted.

## Allowed libraries and common idioms
- SQLAlchemy (Core/ORM) with bindparams or text()
- psycopg2, psycopg2-binary (use %s placeholders), sqlite3 (use ? placeholders), MySQL drivers with parameter binding
- Django ORM and querysets (do not use raw SQL unless necessary and then bind parameters)
- Prepared statements and stored procedures invoked with bound parameters

## Forbidden generation patterns (explicit)
- Do not generate:
  - query = f"...{user_input}..."
  - query = "..." + user_input
  - cursor.execute(query % user_input)
  - Any execution of SQL where user-provided values are inserted by string ops

## When raw SQL is required
- Require an explicit security justification comment in code.
- Require a developer-provided whitelist or mapping for dynamic identifiers.
- Use bind parameters for all values; never bind identifiers with placeholders (use whitelists instead).

## Example safe template to reuse when asked to generate DB code
```python
# Safe DB access template
# NOTE: treat `user_input` as tainted. Validate/convert before use.
user_input = request.args.get("id")
try:
    user_id = int(user_input)
except (TypeError, ValueError):
    raise BadRequest("invalid id")

sql = "SELECT id, name FROM users WHERE id = %s"
cursor.execute(sql, (user_id,))
rows = cursor.fetchall()
```

## Enforcement and monitoring
- Add a rule in the AI assistant’s generation pipeline:
  - Before returning code, run a lightweight pattern check for forbidden SQL patterns; if found, either refuse to generate or replace with a safe, parameterized alternative and include validation.
  - If the assistant cannot satisfy safety constraints due to missing context, it must prompt the user for clarifying info.
- Log any code-generation events that produce DB-access code and flag generation attempts that would have produced forbidden patterns for analyst review.

## Minimal developer checklist to include in PRs created by the assistant
- [ ] Did I validate/whitelist all external inputs used in queries?
- [ ] Did I use parameterized queries / ORM binding for all values?
- [ ] Did semgrep/bandit pass on my branch?
- [ ] Did I include tests covering input validation and query binding?
- [ ] Did I add a security note explaining why the generated DB code is safe?

By following these rules and templates, the assistant will prevent SQL Injection vulnerabilities in generated code and ensure repository-level checks catch regressions.