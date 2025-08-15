# IAM Certification Simulator 🔐

A simple Access Certification automation project that simulates reviewing **700+ entitlements**
and producing certification decisions (Approve/Revoke/Flag) with explanations. Built in Python, file-based, no external deps.

---

## Features
- Ingests CSV of users, entitlements, and access context (last used, criticality, manager, owner).
- Applies **policy rules** from `rules.yaml`:
  - Unused access (e.g., >90 days) → Revoke unless critical.
  - Orphaned accounts or terminated users → Revoke.
  - SoD conflicts (e.g., `PAYMENTS_APPROVER` & `PAYMENTS_REQUESTER`) → Flag.
  - Time-bound access expired → Revoke.
  - High-criticality entitlements require manager/owner approval → Flag.
- Outputs **CSV + JSON** decisions with rationale and metrics.
- Generates a **Markdown report** with summary KPIs and samples.
- Includes a **700+ row synthetic dataset** for demos.

## Quickstart
```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt   # (no external libs needed)
python src/certify.py data/entitlements.csv --rules rules.yaml --out out/
```

## Example
```
$ python src/certify.py data/entitlements.csv --rules rules.yaml --out out/
Processed 750 rows
Summary: 52.3% auto-decided (Approve/Revoke), 14.8% flagged for review
Files: out/decisions.csv, out/decisions.json, out/report.md
```

## Repo Structure
```
src/
  certify.py          # main CLI
rules.yaml           # policy rules
data/
  entitlements.csv   # synthetic dataset (700+ rows)
out/                 # created on run
README.md
```

## Notes
- This is a **simulation** (no SailPoint API). The inputs/logic mirror common certification workflows.
- Extend `rules.yaml` and re-run to see how automation rates change.
- All data is anonymized for portfolio use.
