#!/usr/bin/env python3
"""
compare_semgrep.py

Compare two Semgrep invocation MODES over the same corpus and map findings onto
the 10 weakness categories from Fares et al., "Unpacking Security Scanners for
GitHub Actions Workflows":

  legacy = semgrep scan --config p/github-actions   (the paper's usage)
  full   = semgrep ci                                (Policy + Pro engine, full potential)

Beyond raw counts, it reports the dimensions where "full ci" actually differs
from legacy: rule breadth, severity/confidence tiering, autofixability, and
Pro-engine vs OSS-engine findings.

Usage:
    python3 compare_semgrep.py \
        --run legacy:legacy.json \
        --run full:full.json \
        --out-md  semgrep_compare_report.md \
        --out-csv semgrep_compare.csv

--run is repeatable (LABEL:PATH). The first run is the baseline for the
"surfaced only by ..." diff; the last is the richer config.
"""

import argparse
import csv
import json
import sys
from collections import defaultdict

# --- Weakness taxonomy (paper, Table III) ----------------------------------
WEAKNESSES = ["AIW", "CFW", "EPW", "GRCW", "HGW", "IW", "KVCW", "PTW", "SEW", "UDW"]
WEAKNESS_NAMES = {
    "AIW": "Artifact Integrity", "CFW": "Control Flow", "EPW": "Excessive Permission",
    "GRCW": "Runner Compatibility", "HGW": "Hardening Gap", "IW": "Injection",
    "KVCW": "Known Vulnerable Component", "PTW": "Privileged Trigger",
    "SEW": "Secrets Exposure", "UDW": "Unpinned Dependency",
}

# Substring -> weakness, first match wins (case-insensitive against check_id).
# After the first run, extend this using the "Unmapped rules" list the script prints.
RULE_MAP = [
    ("pull-request-target", "PTW"), ("pull_request_target", "PTW"), ("pwn-request", "PTW"),
    ("workflow-run", "PTW"),
    ("shell-injection", "IW"), ("template-injection", "IW"), ("expression-injection", "IW"),
    ("code-injection", "IW"), ("command-injection", "IW"), ("unsecure-commands", "IW"),
    ("set-env", "IW"), ("add-path", "IW"),
    ("unpinned", "UDW"), ("mutable-ref", "UDW"), ("mutable", "UDW"), ("pin-", "UDW"),
    ("-pin", "UDW"), ("pinning", "UDW"), ("third-party-action", "UDW"),
    ("oidc", "SEW"), ("secret", "SEW"), ("inherit", "SEW"), ("hardcoded", "SEW"),
    ("credential", "SEW"), ("token", "SEW"),
    ("permission", "EPW"), ("privileg", "EPW"), ("write-all", "EPW"),
    ("artifact", "AIW"), ("cache", "AIW"), ("integrity", "AIW"), ("checksum", "AIW"),
    ("cve-", "KVCW"), ("vulnerable", "KVCW"), ("known-vuln", "KVCW"),
    ("deprecated", "GRCW"), ("runner", "GRCW"),
    ("always-true", "CFW"), ("control-flow", "CFW"),
    ("sast", "HGW"), ("no-scanning", "HGW"),
]

# Paper Table V, semgrep row (same corpus). (findings, distinct workflows).
PAPER_SEMGREP = {w: (0, 0) for w in WEAKNESSES}
PAPER_SEMGREP["IW"] = (255, 128)
PAPER_SEMGREP["PTW"] = (15, 10)


def classify(check_id):
    cid = (check_id or "").lower()
    for needle, weak in RULE_MAP:
        if needle in cid:
            return weak
    return "UNMAPPED"


def short_id(check_id):
    parts = (check_id or "").split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else (check_id or "")


def load_run(path):
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except FileNotFoundError:
        print(f"[warn] {path} not found; empty run", file=sys.stderr)
        return [], 0
    except json.JSONDecodeError as exc:
        print(f"[warn] {path} invalid JSON ({exc}); empty run", file=sys.stderr)
        return [], 0
    return data.get("results", []), len(data.get("errors", []))


def aggregate(results):
    by_rule = defaultdict(lambda: {"findings": 0, "files": set()})
    by_weak = defaultdict(lambda: {"findings": 0, "files": set()})
    sev = defaultdict(int)        # ERROR / WARNING / INFO
    conf = defaultdict(int)       # HIGH / MEDIUM / LOW / UNKNOWN
    engine = defaultdict(int)     # PRO / OSS / UNKNOWN  (Pro-engine signal)
    files = set()
    fixable = 0
    for r in results:
        cid = r.get("check_id", "<no-id>")
        path = r.get("path", "<no-path>")
        extra = r.get("extra", {}) or {}
        md = extra.get("metadata", {}) or {}
        by_rule[cid]["findings"] += 1
        by_rule[cid]["files"].add(path)
        w = classify(cid)
        by_weak[w]["findings"] += 1
        by_weak[w]["files"].add(path)
        files.add(path)
        sev[(extra.get("severity") or "UNKNOWN").upper()] += 1
        conf[(md.get("confidence") or "UNKNOWN").upper()] += 1
        if extra.get("fix") is not None or extra.get("fixed_lines") is not None:
            fixable += 1
        ek = extra.get("engine_kind") or r.get("engine_kind") or md.get("engine_kind")
        engine[(ek or "UNKNOWN").upper()] += 1
    return {
        "by_rule": by_rule, "by_weak": by_weak, "files": files,
        "total": len(results), "sev": sev, "conf": conf,
        "engine": engine, "fixable": fixable,
    }


def fmt(cell):
    f, n = cell
    return f"{f} ({n})" if f else "-"


def build_markdown(runs, agg, errors, base_label, rich_label):
    labels = [l for l, _ in runs]
    out = ["# Semgrep: full `semgrep ci` vs legacy CLI on the GitHub Actions corpus\n"]

    # --- Capabilities / depth table ---------------------------------------
    out.append("## What each mode surfaced\n")
    out.append("| Metric | " + " | ".join(f"`{l}`" for l in labels) + " |")
    out.append("|---|" + "---:|" * len(labels))

    def row(name, fn):
        out.append(f"| {name} | " + " | ".join(str(fn(agg[l])) for l in labels) + " |")

    row("Total findings", lambda a: a["total"])
    row("Distinct rules fired", lambda a: len(a["by_rule"]))
    row("Files with ≥1 finding", lambda a: len(a["files"]))
    row("Weakness classes covered", lambda a: sum(1 for w in WEAKNESSES if a["by_weak"].get(w, {}).get("findings", 0)))
    row("ERROR severity", lambda a: a["sev"].get("ERROR", 0))
    row("WARNING severity", lambda a: a["sev"].get("WARNING", 0))
    row("INFO severity", lambda a: a["sev"].get("INFO", 0))
    row("HIGH confidence", lambda a: a["conf"].get("HIGH", 0))
    row("Autofixable findings", lambda a: a["fixable"])
    row("Pro-engine findings", lambda a: a["engine"].get("PRO", 0))
    out.append("| Scan errors | " + " | ".join(str(errors[l]) for l in labels) + " |")
    out.append("")
    out.append(
        "> Pro-engine findings show up only if your Policy enables Pro/cross-file "
        "and the language is supported (YAML is not an interfile language, so for "
        "pure workflow corpora this is usually 0 — the ci gains here are breadth, "
        "tiering, and autofix, not cross-file taint).\n"
    )

    # --- Per-weakness ------------------------------------------------------
    out.append("## Findings per weakness  *(findings, distinct files in parens)*\n")
    out.append("| Weakness | " + " | ".join(f"`{l}`" for l in labels) + " | Paper (semgrep) |")
    out.append("|---|" + "---:|" * (len(labels) + 1))
    active = [w for w in WEAKNESSES + ["UNMAPPED"]
              if any(agg[l]["by_weak"].get(w, {}).get("findings", 0) for l in labels)
              or PAPER_SEMGREP.get(w, (0, 0))[0]]
    for w in active:
        name = WEAKNESS_NAMES.get(w, "Unmapped (review)")
        cells = [fmt((agg[l]["by_weak"].get(w, {"findings": 0, "files": set()})["findings"],
                      len(agg[l]["by_weak"].get(w, {"findings": 0, "files": set()})["files"]))) for l in labels]
        ref = fmt(PAPER_SEMGREP.get(w, (0, 0))) if w != "UNMAPPED" else "n/a"
        out.append(f"| **{w}** {name} | " + " | ".join(cells) + f" | {ref} |")
    out.append("\n> Paper column = Table V semgrep row, same corpus. Your `legacy` "
               "column should land near it.\n")

    # --- Per-rule ----------------------------------------------------------
    out.append("## Findings per rule\n")
    all_rules = set().union(*[set(agg[l]["by_rule"]) for l in labels]) if labels else set()
    out.append("| Rule (check_id) | Weakness | " + " | ".join(f"`{l}`" for l in labels) + " |")
    out.append("|---|---|" + "---:|" * len(labels))
    for cid in sorted(all_rules, key=lambda c: (classify(c), c)):
        cells = [fmt((agg[l]["by_rule"].get(cid, {"findings": 0, "files": set()})["findings"],
                      len(agg[l]["by_rule"].get(cid, {"findings": 0, "files": set()})["files"]))) for l in labels]
        out.append(f"| `{short_id(cid)}` | {classify(cid)} | " + " | ".join(cells) + " |")
    out.append("")

    # --- What full ci adds -------------------------------------------------
    if base_label != rich_label:
        out.append(f"## Surfaced only by `{rich_label}` (not by `{base_label}`)\n")
        base = agg[base_label]["by_rule"]
        rich = agg[rich_label]["by_rule"]
        added = [(cid, base.get(cid, {"findings": 0})["findings"], d["findings"])
                 for cid, d in rich.items()
                 if d["findings"] - base.get(cid, {"findings": 0})["findings"] > 0]
        if added:
            out.append("| Rule | Weakness | base | rich | Δ |")
            out.append("|---|---|---:|---:|---:|")
            for cid, bf, rf in sorted(added, key=lambda x: -(x[2] - x[1])):
                out.append(f"| `{short_id(cid)}` | {classify(cid)} | {bf} | {rf} | +{rf - bf} |")
        else:
            out.append("_Nothing additional — full ci surfaced no rules beyond legacy._")
        out.append("")

    # --- Unmapped ----------------------------------------------------------
    unmapped = sorted({c for l in labels for c in agg[l]["by_rule"] if classify(c) == "UNMAPPED"})
    if unmapped:
        out.append("## Unmapped rules — add to RULE_MAP\n")
        out += [f"- `{c}`" for c in unmapped]
        out.append("")
    return "\n".join(out)


def write_csv(path, runs, agg):
    labels = [l for l, _ in runs]
    all_rules = set().union(*[set(agg[l]["by_rule"]) for l in labels]) if labels else set()
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        header = ["check_id", "weakness"]
        for l in labels:
            header += [f"{l}_findings", f"{l}_files"]
        w.writerow(header)
        for cid in sorted(all_rules):
            r = [cid, classify(cid)]
            for l in labels:
                d = agg[l]["by_rule"].get(cid, {"findings": 0, "files": set()})
                r += [d["findings"], len(d["files"])]
            w.writerow(r)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--run", action="append", default=[], metavar="LABEL:PATH",
                    help="Semgrep JSON, repeatable. First=baseline, last=rich.")
    ap.add_argument("--out-md", default="semgrep_compare_report.md")
    ap.add_argument("--out-csv", default="semgrep_compare.csv")
    args = ap.parse_args()
    if not args.run:
        args.run = ["legacy:legacy.json", "full:full.json"]

    runs = []
    for spec in args.run:
        if ":" not in spec:
            ap.error(f"--run must be LABEL:PATH, got {spec!r}")
        label, path = spec.split(":", 1)
        runs.append((label, path))

    agg, errors = {}, {}
    for label, path in runs:
        results, n_err = load_run(path)
        agg[label] = aggregate(results)
        errors[label] = n_err

    md = build_markdown(runs, agg, errors, runs[0][0], runs[-1][0])
    with open(args.out_md, "w", encoding="utf-8") as fh:
        fh.write(md)
    write_csv(args.out_csv, runs, agg)
    print(md)
    print(f"\n[ok] wrote {args.out_md} and {args.out_csv}", file=sys.stderr)


if __name__ == "__main__":
    main()
