#!/usr/bin/env python3
import argparse, csv, json, os, yaml
from collections import defaultdict
from datetime import datetime

def load_rules(path):
    with open(path, "r") as f:
        return yaml.safe_load(f)

def read_entitlements(path):
    with open(path, newline="") as f:
        return list(csv.DictReader(f))

def has_sod_conflict(entitlements, conflicts):
    ents = set(entitlements)
    for a,b in conflicts:
        if a in ents and b in ents:
            return True, f"SoD conflict: {a} & {b}"
    return False, ""

def decide(row, rules, user_entitlements):
    last_used = int(row["last_used_days"]) if row["last_used_days"] else 9999
    status = row["user_status"]
    crit = (row["criticality"] or "").upper()
    ent = row["entitlement"]
    tbd = row["timebound_days_left"]
    tbd = int(tbd) if tbd not in (None, "", "None") else None

    # Defaults
    decision = "APPROVE"
    reason = "In use / no policy violation"

    # Terminated / orphaned
    if status in ("TERMINATED","ORPHANED"):
        return "REVOKE", f"User status {status}"

    # Time-bound access expired
    if tbd is not None and tbd < -abs(rules.get("timebound_grace_days", 7)):
        return "REVOKE", f"Time-bound access expired {abs(tbd)} days ago"

    # Unused access
    if last_used > rules.get("unused_days_threshold", 90):
        if crit in rules.get("criticality_whitelist", []):
            return "FLAG", f"Unused {last_used}d but critical ({crit})"
        else:
            return "REVOKE", f"Unused {last_used}d"

    # SoD conflicts at the user level
    conflict, why = has_sod_conflict(user_entitlements, rules.get("sod_conflicts", []))
    if conflict:
        return "FLAG", why

    # High criticality require human review
    if crit == "CRITICAL":
        return "FLAG", "Critical entitlement requires owner/manager review"

    return decision, reason

def main():
    ap = argparse.ArgumentParser(description="IAM Certification Simulator")
    ap.add_argument("csv_path", help="Path to entitlements CSV")
    ap.add_argument("--rules", default="rules.yaml")
    ap.add_argument("--out", default="out/")
    args = ap.parse_args()

    rules = load_rules(args.rules)
    rows = read_entitlements(args.csv_path)

    # Build map of user -> list of entitlements for SoD checks
    user_to_ents = defaultdict(list)
    for r in rows:
        user_to_ents[r["user"]].append(r["entitlement"])

    os.makedirs(args.out, exist_ok=True)
    decisions = []
    auto_count = 0
    flag_count = 0

    for r in rows:
        decision, reason = decide(r, rules, user_to_ents[r["user"]])
        auto = decision in ("APPROVE","REVOKE")
        if auto:
            auto_count += 1
        if decision == "FLAG":
            flag_count += 1
        decisions.append({
            **r,
            "decision": decision,
            "reason": reason,
            "auto_decided": auto
        })

    # Write CSV
    out_csv = os.path.join(args.out, "decisions.csv")
    with open(out_csv, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(decisions[0].keys()))
        w.writeheader()
        w.writerows(decisions)

    # Write JSON
    out_json = os.path.join(args.out, "decisions.json")
    with open(out_json, "w") as f:
        json.dump(decisions, f, indent=2)

    # Report
    total = len(decisions)
    auto_rate = round(auto_count/total*100, 1)
    flag_rate = round(flag_count/total*100, 1)
    report = f"""# Certification Report
Generated: {datetime.utcnow().isoformat()}Z
Source: {os.path.basename(args.csv_path)}

- Total entitlements: **{total}**
- Auto-decided (Approve/Revoke): **{auto_count}** ({auto_rate}%)
- Flagged for review: **{flag_count}** ({flag_rate}%)

> Tip: Tweak `rules.yaml` to change automation rate and re-run.

"""
    out_md = os.path.join(args.out, "report.md")
    with open(out_md, "w") as f:
        f.write(report)

    print(f"Processed {total} rows")
    print(f"Summary: {auto_rate}% auto-decided, {flag_rate}% flagged")
    print(f"Files: {out_csv}, {out_json}, {out_md}")

if __name__ == "__main__":
    main()
