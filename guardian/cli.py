"""Guardian CLI.

  scan    <repo>   Day 1: inventory, SBOM, matrix, vulnerabilities, indicators
  run     <repo>   full agentic pipeline; pauses for human approval unless --approve is given
  approve          record human approval decisions for proposed fixes
  resume  <repo>   continue after approval: independent validation + report
  serve            HTTP API for the dashboard
"""
import argparse, json
from collections import Counter
from pathlib import Path
from .pipeline import discover


def main():
    from .config import load_dotenv
    load_dotenv()
    ap = argparse.ArgumentParser(prog="guardian")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan"); s.add_argument("repo"); s.add_argument("--out", default="output")
    s.add_argument("--no-vulns", action="store_true", help="skip the OSV stage")
    s.add_argument("--offline", action="store_true", help="use cached OSV data only")
    s.add_argument("--history", type=int, default=20, help="lockfile commits to compare (0 = off)")
    r = sub.add_parser("run"); r.add_argument("repo"); r.add_argument("--out", default="output")
    r.add_argument("--offline", action="store_true"); r.add_argument("--history", type=int, default=20)
    r.add_argument("--llm", choices=["auto", "claude", "gemini", "none"], default="auto", help="auto = Claude if credentials exist")
    r.add_argument("--approve", default=None, help="'all', 'low', 'none' or comma-separated candidate ids")
    r.add_argument("--no-smoke", action="store_true", help="skip docker build/boot smoke test in validation")
    r.add_argument("--auto-merge", action="store_true", help="run LLM/fallback test generation in sandbox and auto-merge passing fixes")
    ap_ = sub.add_parser("approve"); ap_.add_argument("--out", default="output")
    ap_.add_argument("--ids", required=True, help="comma-separated candidate ids, or 'all' / 'low'")
    ap_.add_argument("--reject", action="store_true")
    rs = sub.add_parser("resume"); rs.add_argument("repo"); rs.add_argument("--out", default="output")
    rs.add_argument("--offline", action="store_true"); rs.add_argument("--history", type=int, default=20)
    rs.add_argument("--llm", choices=["auto", "claude", "gemini", "none"], default="auto")
    rs.add_argument("--no-smoke", action="store_true")
    bs = sub.add_parser("baseline", help="Create developer-signed 4096B Merkle-tree chunk baseline and log to ledger")
    bs.add_argument("repo"); bs.add_argument("--key", default=None, help="secret signing key/passphrase")
    bs.add_argument("--signer", default="developer", help="signer identity recorded in baseline and ledger")
    bs.add_argument("--venv", default=None, help="optional virtualenv path to include in baseline")
    wt = sub.add_parser("watch", help="Run keyed random-chunk Merkle spot-checks against signed baseline")
    wt.add_argument("repo"); wt.add_argument("--interval", type=int, default=2)
    wt.add_argument("--rounds", type=int, default=3); wt.add_argument("--key", default=None)
    vl = sub.add_parser("verify-ledger", help="Verify cryptographic hash chain and HMAC signatures in .guardian/ledger.jsonl")
    vl.add_argument("repo"); vl.add_argument("--key", default=None)
    sv = sub.add_parser("serve", help="HTTP API for the dashboard (needs the [api] extra)")
    sv.add_argument("--out", default="output"); sv.add_argument("--host", default="127.0.0.1")
    sv.add_argument("--port", type=int, default=8000)
    a = ap.parse_args()
    if a.cmd == "serve":
        from .api import serve
        return serve(a.out, a.host, a.port)
    if getattr(a, "repo", None):
        from .ingestion import resolve_target
        a.repo = str(resolve_target(a.repo))
    if a.cmd == "baseline":
        from .integrity import create_baseline
        doc = create_baseline(a.repo, venv_dir=a.venv, signing_key=a.key, signer=a.signer)
        print(f"Signed Merkle baseline for {len(doc['files'])} file(s) -> {a.repo}/.guardian/baseline.json (HMAC {doc['hmac'][:16]}...)")
        return
    if a.cmd == "watch":
        from .integrity import run_watch
        anomalies = run_watch(a.repo, interval=a.interval, rounds=a.rounds, signing_key=a.key)
        if not anomalies:
            print(f"Integrity OK: {a.rounds} round(s) of keyed random-chunk Merkle verification passed.")
        else:
            for item in anomalies:
                print(f"[TAMPER] round {item.get('round')}: {item.get('file')} ({item.get('status')}) chunk={item.get('chunk')} line={item.get('line')}")
        return
    if a.cmd == "verify-ledger":
        from .integrity import verify_ledger
        ok, msg, _ = verify_ledger(a.repo, signing_key=a.key)
        print(msg)
        return
    if a.cmd in ("run", "resume"):
        import sys
        from .agents.orchestrator import Orchestrator
        o = Orchestrator(a.repo, a.out, a.llm, a.offline, a.history, smoke=not a.no_smoke)
        if a.cmd == "resume":
            return o.resume()
        approve = a.approve if a.approve in (None, "all", "low", "none") else a.approve.split(",")
        return o.run(approve, interactive=approve is None and not a.auto_merge and sys.stdin.isatty(), auto_merge=a.auto_merge)
    if a.cmd == "approve":
        import time
        f = Path(a.out) / "run_state.json"
        st = json.loads(f.read_text())
        props = {p["candidate_id"]: p for p in st["proposals"]}
        ids = list(props) if a.ids == "all" else [i for i in props if props[i]["change_risk"] == "low"] if a.ids == "low" \
            else a.ids.split(",")
        for i in ids:
            if i not in props:
                print(f"unknown candidate {i}"); continue
            p = props[i]
            st["approvals"][i] = {
                "status": "rejected" if a.reject else "approved", "by": "human reviewer",
                "at": time.strftime("%Y-%m-%dT%H:%M:%S"), "repo_identity": st.get("identity"),
                "diff_sha256": p.get("diff_sha256"), "base_files_sha256": p.get("base_files_sha256", {}),
            }
            print(f"{st['approvals'][i]['status']}: {i}  {props[i]['summary']}")
        f.write_text(json.dumps(st, indent=2))
        return

    out = Path(a.out)
    inv, comps, findings, changes = discover(a.repo, out, a.offline, a.history, a.no_vulns)
    if not comps:
        print("No supported manifest or lockfile; see coverage_gaps.json"); return
    edges = [t for ts in inv["adjacency"].values() for t in ts]
    rel, scope = Counter(c.relationship for c in comps.values()), Counter(c.scope for c in comps.values())
    print(f"Repo: {inv['repo']}  projects: " + ", ".join(f"{p['manifest']} ({p['ecosystem']}, {p['components']})" for p in inv["projects"]))
    print(f"Components (unique name@version): {len(comps)}")
    print(f"  direct: {rel['direct']}  transitive: {rel['transitive']}")
    print(f"  prod: {scope['prod']}  dev: {scope['dev']}")
    print(f"  with install scripts: {sum(c.has_install_script for c in comps.values())}")
    print(f"  non-registry sources: {sum(1 for c in comps.values() if c.source_url and 'registry.npmjs.org' not in c.source_url)}")
    print(f"Edges: {len(edges)}  coverage gaps: {len(inv['gaps'])}")
    if any(f["category"] == "vulnerability" for f in findings):
        vuln = [c for c in comps.values() if c.risk_status == "vulnerable"]
        vr, vs = Counter(c.relationship for c in vuln), Counter(c.scope for c in vuln)
        sev = Counter(f["severity"] for f in findings)
        print(f"Vulnerable components: {len(vuln)}  (direct {vr['direct']}, transitive {vr['transitive']}; "
              f"prod {vs['prod']}, dev {vs['dev']})")
        vf = [f for f in findings if f["category"] == "vulnerability"]
        sev = Counter(f["severity"] for f in vf)
        print(f"Advisories (component x advisory): {len(vf)}  "
              + "  ".join(f"{k}:{sev[k]}" for k in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN") if sev[k]))
    ind = [f for f in findings if f["category"] != "vulnerability"]
    print(f"Supply-chain indicators: {len(ind)}  (lockfile commits compared: {len(changes)})")
    for (cat, rule), n in sorted(Counter((f["category"], f["rule_id"]) for f in ind).items()):
        top = next(f for f in ind if f["rule_id"] == rule and f["category"] == cat)
        print(f"  {rule:<4} {cat:<12} x{n:<3} e.g. {top['title']}")
    st = Counter(c.risk_status for c in comps.values())
    print("Component risk status: " + "  ".join(f"{k}:{v}" for k, v in st.most_common()))
    print(f"Wrote: {', '.join(sorted(p.name for p in out.iterdir()))} -> {out}/")


if __name__ == "__main__":
    main()
