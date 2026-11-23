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
    ap = argparse.ArgumentParser(prog="guardian")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan"); s.add_argument("repo"); s.add_argument("--out", default="output")
    s.add_argument("--no-vulns", action="store_true", help="skip the OSV stage")
    s.add_argument("--offline", action="store_true", help="use cached OSV data only")
    s.add_argument("--history", type=int, default=20, help="lockfile commits to compare (0 = off)")
    r = sub.add_parser("run"); r.add_argument("repo"); r.add_argument("--out", default="output")
    r.add_argument("--offline", action="store_true"); r.add_argument("--history", type=int, default=20)
    r.add_argument("--llm", choices=["auto", "claude", "none"], default="auto", help="auto = Claude if credentials exist")
    r.add_argument("--approve", default=None, help="'all', 'low', 'none' or comma-separated candidate ids")
    r.add_argument("--no-smoke", action="store_true", help="skip docker build/boot smoke test in validation")
    ap_ = sub.add_parser("approve"); ap_.add_argument("--out", default="output")
    ap_.add_argument("--ids", required=True, help="comma-separated candidate ids, or 'all' / 'low'")
    ap_.add_argument("--reject", action="store_true")
    rs = sub.add_parser("resume"); rs.add_argument("repo"); rs.add_argument("--out", default="output")
    rs.add_argument("--offline", action="store_true"); rs.add_argument("--history", type=int, default=20)
    rs.add_argument("--llm", choices=["auto", "claude", "none"], default="auto")
    rs.add_argument("--no-smoke", action="store_true")
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
    if a.cmd in ("run", "resume"):
        import sys
        from .agents.orchestrator import Orchestrator
        o = Orchestrator(a.repo, a.out, a.llm, a.offline, a.history, smoke=not a.no_smoke)
        if a.cmd == "resume":
            return o.resume()
        approve = a.approve if a.approve in (None, "all", "low", "none") else a.approve.split(",")
        return o.run(approve, interactive=approve is None and sys.stdin.isatty())
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
            st["approvals"][i] = {"status": "rejected" if a.reject else "approved", "by": "human reviewer",
                                  "at": time.strftime("%Y-%m-%dT%H:%M:%S")}
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
