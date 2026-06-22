# Repository instructions

## Agent skills

### Issue tracker

Track work in this repository's GitHub Issues. External pull requests are also a triage request surface. See `docs/agents/issue-tracker.md`.

### Triage labels

Use the canonical `needs-triage`, `needs-info`, `ready-for-agent`, `ready-for-human`, and `wontfix` labels. See `docs/agents/triage-labels.md`.

### Domain docs

This is a single-context repository. Read `CONTEXT.md` and relevant decisions under `docs/adr/` before changing rule semantics, coverage profiles, or client artifacts. See `docs/agents/domain.md`.

## Generated files

Treat `dist/` and `upstream/` as generated data. Change source policy in `rules/`, `config/`, or `scripts/`, then rebuild and validate instead of editing generated outputs by hand.

## Required checks

Run these before committing rule or generator changes:

```bash
python scripts/build.py
python -m unittest discover -s tests -v
python scripts/validate.py
```
