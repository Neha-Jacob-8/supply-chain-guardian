"""Shared helpers for the role agents (schemas, risk-item grouping).

AttackAgent  (Red Team)  - investigates suspicious/non-CVE findings, read-only, builds attack-path hypotheses.
RiskAgent               - prioritises with the deterministic scores + investigations; explains, never re-scores.
DefenseAgent (Blue Team) - picks remediation candidates; cannot invent fixes or mark them successful.
"""
import json

from . import tools as T


def _s(t):
    return {"type": "string", "description": t}


def _arr(items, d=""):
    return {"type": "array", "items": items, "description": d}


def _obj(props):
    return {"type": "object", "properties": props, "required": list(props), "additionalProperties": False}


def risk_items(state):
    """Group findings into reviewable units: vulns per component, indicators per (rule, component/file)."""
    groups = {}
    for f in state.findings:
        if f["category"] == "vulnerability":
            key = ("VULN", f["component_id"])
        else:
            key = (f["rule_id"], f.get("component_id") or f["evidence"].get("path"))
        groups.setdefault(key, []).append(f)
    items = []
    for (rule, subj), fs in groups.items():
        scores = [state.risk[f["finding_id"]]["score"] for f in fs]
        top = max(fs, key=lambda f: state.risk[f["finding_id"]]["score"])
        title = (f"{T._short(subj)}: {len(fs)} advisories" if rule == "VULN" else top["title"])
        items.append({"rule": rule, "subject": T._short(subj) if rule == "VULN" else subj, "title": title,
                      "score": max(scores), "finding_ids": [f["finding_id"] for f in fs],
                      "top_finding": top["finding_id"]})
    items.sort(key=lambda i: -i["score"])
    return items
