"""Integrity Agent: investigates Merkle-tree chunk tampering (IT1) and hash-chained ledger tampering (IT2).

When an unauthorized code edit (e.g., a silently modified payment gateway line or rebased commit)
is caught by Merkle chunk verification or ledger verification, this agent inspects the tampered
lines, checks the ledger chain, and produces structured forensic investigations.
"""
import json

from . import tools as T
from .base import Agent
from .common import _arr, _obj, _s


class IntegrityAgent(Agent):
    name = "integrity_agent"
    tool_names = ["verify_merkle_baseline", "verify_audit_ledger", "get_finding", "read_file", "git_commit_info"]
    max_steps = 16
    system = (
        "You are the Supply Chain Guardian Cryptographic Integrity Agent. "
        "Your job is to investigate unauthorized code or audit-ledger tampering detected by the "
        "4096-byte Merkle-tree chunk verifier (rule IT1) and the HMAC hash-chained ledger (rule IT2). "
        "Call verify_merkle_baseline, verify_audit_ledger, and read_file on the tampered lines to determine "
        "what changed on disk without a developer signature (for example, an altered URL, injected backdoor, "
        "or edited ledger record). Every verified_fact must cite real finding_ids or evidence_ids from tool calls."
    )
    result_schema = _obj({"investigations": _arr(_obj({
        "finding_ids": _arr({"type": "string"}),
        "title": _s("short summary of the integrity breach"),
        "hypothesis": _s("what the unauthorized code/ledger edit attempts to do"),
        "attack_path": _arr({"type": "string"}, "ordered steps from unauthorized edit to runtime impact"),
        "verified_facts": _arr(_obj({"claim": _s("fact shown by Merkle/ledger/file tool"), "evidence_ids": _arr({"type": "string"})})),
        "inferences": _arr({"type": "string"}, "security impact analysis"),
        "verdict": {"type": "string", "enum": ["confirmed_risk", "likely_benign", "needs_human_review"]},
        "confidence": {"type": "number"}}))})

    def candidates(self, state):
        return [f for f in state.findings if f.get("rule_id") in ("IT1", "IT2")]

    def task(self, state):
        rows = [{"finding_id": f["finding_id"], "rule_id": f["rule_id"], "title": f["title"],
                 "path": (f.get("evidence") or {}).get("path"), "line": (f.get("evidence") or {}).get("line")}
                for f in self.candidates(state)]
        return ("Investigate these cryptographic integrity findings (Merkle-tree chunk tampering / hash-chained ledger breaks). "
                "Read the exact modified lines in the affected files and verify the baseline/ledger state.\n\n"
                f"Integrity Findings:\n{json.dumps(rows, indent=1)}")

    def fallback(self, state):
        out = []
        b_res, b_eid = T.call(state, "verify_merkle_baseline", {"rounds": 1})
        l_res, l_eid = T.call(state, "verify_audit_ledger", {})

        for f in self.candidates(state):
            ev = f.get("evidence") or {}
            path = ev.get("path") or ""
            line = ev.get("line") or 1
            facts = [{"claim": f"{f['title']} — {f.get('detail', '')}", "evidence_ids": [f["finding_id"]]}]
            if f["rule_id"] == "IT1" and b_eid:
                facts.append({"claim": f"Merkle baseline check reported {b_res.get('anomalies_count', 1)} unsigned chunk anomaly(s).",
                              "evidence_ids": [b_eid]})
                if path and not path.startswith(".guardian"):
                    f_out, f_eid = T.call(state, "read_file", {"path": path, "start_line": max(1, line - 3), "end_line": line + 5})
                    if f_eid and not f_out.get("error"):
                        facts.append({"claim": f"Tampered code excerpt in {path} (around line {line}): {f_out.get('text', '')[:180]}",
                                      "evidence_ids": [f_eid]})
            elif f["rule_id"] == "IT2" and l_eid:
                facts.append({"claim": f"Audit ledger verification status: {l_res.get('message')}", "evidence_ids": [l_eid]})

            out.append({
                "finding_ids": [f["finding_id"]],
                "title": f["title"],
                "hypothesis": "File or audit history was modified outside the developer-signed Merkle baseline (potential post-install tamper or unauthorized rebase).",
                "attack_path": [
                    f"1. Unauthorized modification made to {path or 'repository'} (chunk #{ev.get('chunk', 0)}, line {line})",
                    "2. Change bypassed developer signing key (.guardian/baseline.json HMAC / Merkle root mismatch)",
                    "3. Modified code executes altered logic at runtime if not blocked",
                ],
                "verified_facts": facts,
                "inferences": [
                    "Because the Merkle chunk hash does not match the signed baseline, this edit was not authorized by the signing key holder."
                ],
                "verdict": "confirmed_risk",
                "confidence": 0.95,
            })
        return {"investigations": out}
