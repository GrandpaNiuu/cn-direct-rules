# Contributing

## Domain changes

Edit one value per line in the appropriate file under `rules/`. Keep entries sorted, do not include rule types or `DIRECT`, and include evidence that the service is mainland-owned or should always route directly.

Do not add an entire globally open top-level domain. `config/forbidden-domain-suffixes.txt` records suffixes that must never be routed wholesale.

## Generated and upstream files

Do not hand-edit `dist/` or `upstream/`. Run:

```bash
python scripts/update_sources.py
python scripts/build.py
python -m unittest discover -s tests -v
python scripts/validate.py
```

Every change must keep generation deterministic and must not introduce LAN or reserved networks.
