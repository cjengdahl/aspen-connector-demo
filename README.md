# aspen-connector-demo

A minimal Flask blog app used to demo [aspen-connector](https://github.com/SecurityJourney/aspen-connector) in CI.

`.github/workflows/aspen.yml` runs all three connector modes on every push/PR:

- **gate** — enforces the tenant's external access control policy for the committer
- **guardian** — scans with Bandit and rewrites `.github/ai-instructions.md` from the findings (Mode A)
- **adapt** — scans with Bandit and records the CWEs against the commit (Mode D)

Requires a `SECURITYJOURNEY_TOKEN` repo secret with an Aspen API token.

## Running locally

```bash
pip install -r requirements.txt
python app.py
```

This is the clean baseline branch. A follow-up branch introduces an example vulnerability to show the connector flagging it.
