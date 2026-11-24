"""Live simulation script for Supply Chain Guardian (`targets/<repo>`).

Usage:
  python3 scripts/simulate_attacks.py [targets/<repo>] <scenario>

Scenarios:
  1. shadow        Injects both a phantom dependency import AND a known malicious (`MAL-*`) shadow dependency import
  2. merkle-tamper Simulates a malicious script injecting an unauthorized HTTP exfiltration call into an existing source file
  3. dev-edit      Simulates a legitimate developer feature edit (ready to be signed in the Frontend UI)
  4. typosquat     Adds multi-ecosystem typosquatted packages (SC9)
  5. provenance    Adds an unpublished 404 internal package (SC10) and a brand-new release (<7d, SC11)
  6. all           Applies shadow + merkle-tamper + typosquat + provenance in one command
  7. reset         Restores the repository to its clean git HEAD state and re-signs the baseline
"""
from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


def _ensure_target(repo: Path):
    if not repo.exists():
        repo.mkdir(parents=True, exist_ok=True)
        (repo / "requirements.txt").write_text("flask==3.0.0\n", encoding="utf-8")
        (repo / "app.py").write_text(
            "import flask\n\n"
            "def process_order(order_id, amount):\n"
            "    gateway = 'https://api.stripe.com/v1/charges'\n"
            "    return {'order': order_id, 'gateway': gateway, 'amount': amount}\n",
            encoding="utf-8",
        )
        subprocess.run(["git", "-C", str(repo), "init", "-q"], check=False)
        subprocess.run(["git", "-C", str(repo), "add", "."], check=False)
        subprocess.run(["git", "-C", str(repo), "-c", "user.name=Dev", "-c", "user.email=dev@example.com",
                        "commit", "-qm", "initial clean commit"], check=False)
        from guardian.integrity import create_baseline
        create_baseline(repo, signer="initial-dev")
        print(f"Created and signed clean demo repository at {repo}")


def _pick_source_file(repo: Path) -> Path:
    for ext in ("*.py", "*.js", "*.ts"):
        files = [
            p for p in sorted(repo.rglob(ext))
            if not {".git", "node_modules", ".venv", "venv", "output", "test", "tests"} & set(p.relative_to(repo).parts)
        ]
        if files:
            return files[0]
    p = repo / "app.py"
    p.write_text("def main():\n    return 'ok'\n", encoding="utf-8")
    return p


def sim_shadow(repo: Path, out_dir: Path):
    """1. Inject one phantom/shadow dependency AND one malicious (MAL-*) shadow dependency."""
    src = _pick_source_file(repo)
    is_py = src.suffix == ".py"
    cache_osv = out_dir / "cache" / "osv"
    cache_reg = out_dir / "cache" / "registry"
    cache_osv.mkdir(parents=True, exist_ok=True)
    cache_reg.mkdir(parents=True, exist_ok=True)

    if is_py:
        if not (repo / "requirements.txt").exists():
            (repo / "requirements.txt").write_text("flask==3.0.0\n", encoding="utf-8")
        text = src.read_text(encoding="utf-8", errors="replace")
        addition = "\n# Simulated phantom + malicious shadow imports\nimport urllib3\nimport ctx_malicious_ telemetry\n".replace(" ", "")
        addition = "\n# Simulated phantom + malicious shadow imports\nimport urllib3\nimport evil_ drain_ sdk\n".replace(" ", "_")
        # Use valid Python identifier for malicious package: evil_drain_sdk -> evil-drain-sdk
        addition = "\n# Simulated phantom + malicious shadow imports\nimport urllib3\nimport evil_drain_sdk\n"
        if "evil_drain_sdk" not in text:
            src.write_text(text + addition, encoding="utf-8")
        # Seed registry + OSV cache so evil-drain-sdk resolves to 1.0.0 and triggers MAL-2026-9999 even offline
        (cache_reg / "pypi-evil-drain-sdk.json").write_text(json.dumps({"name": "evil-drain-sdk", "version": "1.0.0", "releases": {"1.0.0": [{"upload_time_iso_8601": "2026-11-23T00:00:00Z"}]}}))
        (cache_reg / "pypi-urllib3.json").write_text(json.dumps({"name": "urllib3", "version": "2.2.1", "releases": {"2.2.1": [{"upload_time_iso_8601": "2025-01-01T00:00:00Z"}]}}))
        mal_rec = {
            "id": "MAL-2026-9999",
            "summary": "Malicious credential & payment exfiltration package evil-drain-sdk",
            "aliases": [],
            "affected": [{"package": {"ecosystem": "PyPI", "name": "evil-drain-sdk"},
                          "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}]}],
        }
        (cache_osv / "MAL-2026-9999.json").write_text(json.dumps(mal_rec))
        import hashlib
        qkey = hashlib.sha256(b"pkg:pypi/evil-drain-sdk@1.0.0").hexdigest()[:16]
        (cache_osv / f"querybatch-{qkey}.json").write_text(json.dumps({"pkg:pypi/evil-drain-sdk@1.0.0": ["MAL-2026-9999"]}, indent=1))
        print(f"[shadow] Injected phantom import `urllib3` + malicious shadow import `evil_drain_sdk` into {src.relative_to(repo)}")
    else:
        text = src.read_text(encoding="utf-8", errors="replace")
        addition = "\n// Simulated phantom + malicious shadow imports\nconst _phantom = require('debug');\nconst _mal = require('evil-drain-sdk');\n"
        if "evil-drain-sdk" not in text:
            src.write_text(text + addition, encoding="utf-8")
        (cache_reg / "npm-pack-evil-drain-sdk.json").write_text(json.dumps({"name": "evil-drain-sdk", "latest": "1.0.0", "time": {"1.0.0": "2026-11-23T00:00:00Z"}}))
        print(f"[shadow] Injected phantom require('debug') + malicious require('evil-drain-sdk') into {src.relative_to(repo)}")


def sim_merkle_tamper(repo: Path):
    """2a. Ensure a signed baseline exists, then silently inject an unauthorized HTTP exfiltration call into source code."""
    from guardian.integrity import create_baseline
    if not (repo / ".guardian" / "baseline.json").exists():
        create_baseline(repo, signer="trusted-dev")
    src = _pick_source_file(repo)
    text = src.read_text(encoding="utf-8", errors="replace")
    if src.suffix == ".py":
        tamper = "\n# UNAUTHORIZED INJECTED HTTP EXFILTRATION\nimport urllib.request as _exfil_http\n_exfil_url = 'https://evil-payment-gateway.example.com/collect'\n"
    else:
        tamper = "\n// UNAUTHORIZED INJECTED HTTP EXFILTRATION\nconst _exfil_http = require('https');\nconst _exfil_url = 'https://evil-payment-gateway.example.com/collect';\n"
    src.write_text(text + tamper, encoding="utf-8")
    print(f"[merkle-tamper] Modified {src.relative_to(repo)} WITHOUT developer signature -> will trigger IT1 & IntegrityAgent!")


def sim_dev_edit(repo: Path):
    """2b. Simulate a legitimate developer edit that you can then bless in the Frontend UI by clicking 'Sign Merkle Baseline'."""
    src = _pick_source_file(repo)
    text = src.read_text(encoding="utf-8", errors="replace")
    if src.suffix == ".py":
        edit = "\n# Verified developer update: added healthcheck helper\ndef health_status():\n    return {'status': 'healthy', 'version': '1.0.1'}\n"
    else:
        edit = "\n// Verified developer update: added healthcheck helper\nfunction healthStatus() { return { status: 'healthy', version: '1.0.1' }; }\n"
    src.write_text(text + edit, encoding="utf-8")
    print(f"[dev-edit] Added legitimate developer function to {src.relative_to(repo)}.")
    print("  -> Now click 'Sign Merkle Baseline' in the Web UI (Overview -> Cryptographic Integrity) to sign this edit!")


def sim_typosquat(repo: Path):
    """4. Inject multi-ecosystem typosquatted packages (SC9)."""
    req = repo / "requirements.txt"
    if req.exists():
        txt = req.read_text(encoding="utf-8")
        if "reqeusts==" not in txt:
            req.write_text(txt.rstrip("\n") + "\nreqeusts==2.31.0\n", encoding="utf-8")
            print("[typosquat] Added `reqeusts==2.31.0` (typosquat of `requests`) to requirements.txt")
    pj = repo / "package.json"
    if pj.exists():
        data = json.loads(pj.read_text(encoding="utf-8"))
        deps = dict(data.get("dependencies") or {})
        deps["lodahs"] = "4.17.21"
        data["dependencies"] = deps
        pj.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
        print("[typosquat] Added `lodahs@4.17.21` (typosquat of `lodash`) to package.json")


def sim_provenance(repo: Path, out_dir: Path):
    """5. Inject a 404 unknown-provenance package (SC10) and a <7-day brand-new release (SC11)."""
    cache_reg = out_dir / "cache" / "registry"
    cache_reg.mkdir(parents=True, exist_ok=True)
    now_iso = datetime.now(timezone.utc).isoformat()

    req = repo / "requirements.txt"
    if not req.exists():
        req.write_text("flask==3.0.0\n", encoding="utf-8")
    txt = req.read_text(encoding="utf-8")
    additions = []
    if "internal-ghost-pkg==" not in txt:
        additions.append("internal-ghost-pkg==1.0.0")
        (cache_reg / "pypi-internal-ghost-pkg.json").write_text(json.dumps({"__404": True}))
    if "zero-day-fresh-pkg==" not in txt:
        additions.append("zero-day-fresh-pkg==0.1.0")
        (cache_reg / "pypi-zero-day-fresh-pkg.json").write_text(json.dumps({
            "name": "zero-day-fresh-pkg", "version": "0.1.0",
            "releases": {"0.1.0": [{"upload_time_iso_8601": now_iso}]}
        }))
    if additions:
        req.write_text(txt.rstrip("\n") + "\n" + "\n".join(additions) + "\n", encoding="utf-8")
        print(f"[provenance] Added 404 package `internal-ghost-pkg==1.0.0` (SC10) and <7d package `zero-day-fresh-pkg==0.1.0` (SC11)")


def sim_reset(repo: Path):
    subprocess.run(["git", "-C", str(repo), "checkout", "--", "."], check=False)
    subprocess.run(["git", "-C", str(repo), "clean", "-fd", "-e", ".guardian"], check=False)
    from guardian.integrity import create_baseline
    create_baseline(repo, signer="reset-clean")
    print(f"[reset] Restored {repo} to clean git state and re-signed Merkle baseline.")


def main():
    args = sys.argv[1:]
    if not args:
        print(__doc__)
        return
    if len(args) == 1:
        repo = Path("targets/live-demo")
        scenario = args[0]
    else:
        repo = Path(args[0])
        scenario = args[1]
    out_dir = Path("output")
    _ensure_target(repo)

    if scenario == "shadow":
        sim_shadow(repo, out_dir)
    elif scenario == "merkle-tamper":
        sim_merkle_tamper(repo)
    elif scenario == "dev-edit":
        sim_dev_edit(repo)
    elif scenario == "typosquat":
        sim_typosquat(repo)
    elif scenario == "provenance":
        sim_provenance(repo, out_dir)
    elif scenario == "all":
        sim_merkle_tamper(repo)
        sim_shadow(repo, out_dir)
        sim_typosquat(repo)
        sim_provenance(repo, out_dir)
    elif scenario == "reset":
        sim_reset(repo)
    else:
        print(f"Unknown scenario '{scenario}'. Choose: shadow | merkle-tamper | dev-edit | typosquat | provenance | all | reset")


if __name__ == "__main__":
    main()
