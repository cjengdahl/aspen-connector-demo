# aspen-connector-demo

A minimal Flask blog app used to demo [aspen-connector](https://github.com/SecurityJourney/aspen-connector) in CI.

`.github/workflows/aspen.yml` runs Bandit and feeds the results into a single connector step on every push/PR:

- **gate** — enforces the tenant's external access control policy for the committer; runs first
- **guardian** — rewrites `.github/ai-instructions.md` from the Bandit findings (Mode A)
- **adapt** — records the same findings' CWEs against the commit, as part of Mode A

Requires a `SECURITYJOURNEY_TOKEN` repo secret with an Aspen API token.

## Running locally

```bash
pip install -r requirements.txt
python app.py
```

This is the clean baseline branch. A follow-up branch introduces an example vulnerability to show the connector flagging it.
