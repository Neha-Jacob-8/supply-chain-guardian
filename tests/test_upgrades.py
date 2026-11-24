import datetime
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from guardian.agents.gemini import gemini_keys
from guardian.agents.integrity_agent import IntegrityAgent
from guardian.agents.state import RunState
from guardian.discovery import build_inventory
from guardian.ingestion import parse_github_url
from guardian.integrity import (
    append_ledger_record, apply_waivers, check_repo_integrity, create_baseline,
    load_waivers, run_watch, unwaive_finding, verify_ledger, waive_finding,
)
from guardian.intel.crawler import crawl_shadow_dependencies, dynamic_py_import_map
from guardian.intel.osv import cvss4_score, scan_components
from guardian.intel.registry import verify_registries
from guardian.intel.risk import import_usage
from guardian.intel.typosquat import detect_typosquats
from guardian.models import Component
from guardian.remediation.candidates import build_candidates
from guardian.validation.auto_mitigate import auto_mitigate_candidate


class IngestionShorthandTest(unittest.TestCase):
    def test_shorthand_and_domain_urls(self):
        self.assertEqual(parse_github_url("https://github.com/axios/axios.git"), ("axios", "axios"))
        self.assertEqual(parse_github_url("github.com/OWASP/NodeGoat"), ("OWASP", "NodeGoat"))
        self.assertEqual(parse_github_url("axios/axios"), ("axios", "axios"))
        with self.assertRaises(ValueError):
            parse_github_url("https://gitlab.com/a/b")


class MavenDependencyTreeTest(unittest.TestCase):
    def test_mvn_dependency_tree_parses_transitive_edges(self):
        d = Path(tempfile.mkdtemp())
        (d / "pom.xml").write_text(
            "<project><groupId>com.example</groupId><artifactId>demo</artifactId><version>1.0.0</version>"
            "<dependencies><dependency><groupId>org.apache.logging.log4j</groupId>"
            "<artifactId>log4j-core</artifactId><version>2.14.1</version></dependency></dependencies></project>"
        )
        (d / "mvn-tree.txt").write_text(
            "[INFO] com.example:demo:jar:1.0.0\n"
            "[INFO] +- org.apache.logging.log4j:log4j-core:jar:2.14.1:compile\n"
            "[INFO] |  \\- org.apache.logging.log4j:log4j-api:jar:2.14.1:compile\n"
            "[INFO] \\- junit:junit:jar:4.13.2:test\n"
        )
        inv = build_inventory(d)
        comps = inv["components"]
        core_id = "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"
        api_id = "pkg:maven/org.apache.logging.log4j/log4j-api@2.14.1"
        junit_id = "pkg:maven/junit/junit@4.13.2"
        self.assertIn(core_id, comps)
        self.assertIn(api_id, comps)
        self.assertEqual(comps[core_id].relationship, "direct")
        self.assertEqual(comps[api_id].relationship, "transitive")
        self.assertIn(core_id, comps[api_id].parents)
        self.assertEqual(comps[junit_id].scope, "dev")


class OsvMaliciousAndCvss4Test(unittest.TestCase):
    def test_cvss4_calculator(self):
        s_crit = cvss4_score("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N")
        s_med = cvss4_score("CVSS:4.0/AV:L/AC:H/AT:P/PR:L/UI:P/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N")
        s_zero = cvss4_score("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N")
        self.assertEqual(s_crit, 9.3)
        self.assertTrue(2.0 <= s_med <= 6.9)
        self.assertEqual(s_zero, 0.0)
        self.assertIsNone(cvss4_score("invalid"))

    def test_mal_advisory_separated_as_malicious_critical(self):
        cache = Path(tempfile.mkdtemp())
        cid = "pkg:npm/evil-pkg@1.0.0"
        comps = {cid: Component(component_id=cid, name="evil-pkg", version="1.0.0", ecosystem="npm", relationship="direct")}
        mal_rec = {
            "id": "MAL-2026-1234",
            "summary": "Malicious code in evil-pkg",
            "aliases": [],
            "affected": [{"package": {"ecosystem": "npm", "name": "evil-pkg"}, "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}]}]}],
        }
        (cache / "MAL-2026-1234.json").write_text(json.dumps(mal_rec))
        with patch("guardian.intel.osv._query_ids", return_value={cid: ["MAL-2026-1234"]}):
            findings = scan_components(comps, cache, offline=True)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["category"], "malicious")
        self.assertEqual(findings[0]["rule_id"], "OSV-MAL")
        self.assertEqual(findings[0]["severity"], "CRITICAL")
        self.assertEqual(comps[cid].risk_status, "malicious")


class RegistryAndTyposquatTest(unittest.TestCase):
    def test_registry_404_and_release_age_detection(self):
        cache = Path(tempfile.mkdtemp())
        c_npm = Component(component_id="pkg:npm/priv-internal@1.0.0", name="priv-internal", version="1.0.0", ecosystem="npm", relationship="direct")
        c_pypi = Component(component_id="pkg:pypi/fresh-pkg@0.1.0", name="fresh-pkg", version="0.1.0", ecosystem="pypi", relationship="direct")
        c_mvn = Component(component_id="pkg:maven/com.ghost/missing@1.0", name="com.ghost:missing", version="1.0", ecosystem="maven", relationship="direct")

        now = datetime.datetime(2026, 11, 24, 12, 0, tzinfo=datetime.timezone.utc)
        (cache / "npm-pack-priv-internal.json").write_text(json.dumps({"__404": True}))
        (cache / "pypi-fresh-pkg.json").write_text(json.dumps({
            "name": "fresh-pkg", "version": "0.1.0",
            "releases": {"0.1.0": [{"upload_time_iso_8601": "2026-11-22T10:00:00Z"}]}
        }))
        (cache / "maven-com.ghost_missing.json").write_text(json.dumps({"response": {"numFound": 0}}))

        findings = verify_registries(
            {c_npm.component_id: c_npm, c_pypi.component_id: c_pypi, c_mvn.component_id: c_mvn},
            cache, offline=True, now=now
        )
        rules = {f["component_id"]: f["rule_id"] for f in findings}
        self.assertEqual(rules["pkg:npm/priv-internal@1.0.0"], "SC10")
        self.assertEqual(rules["pkg:pypi/fresh-pkg@0.1.0"], "SC11")
        self.assertEqual(rules["pkg:maven/com.ghost/missing@1.0"], "SC10")

    def test_typosquat_across_ecosystems(self):
        cache = Path(tempfile.mkdtemp())
        comps = {
            "pkg:npm/lodahs@4.17.21": Component(component_id="pkg:npm/lodahs@4.17.21", name="lodahs", version="4.17.21", ecosystem="npm"),
            "pkg:pypi/reqeusts@2.31.0": Component(component_id="pkg:pypi/reqeusts@2.31.0", name="reqeusts", version="2.31.0", ecosystem="pypi"),
            "pkg:cargo/sered@1.0.0": Component(component_id="pkg:cargo/sered@1.0.0", name="sered", version="1.0.0", ecosystem="cargo"),
        }
        findings = detect_typosquats(comps, cache, offline=True)
        self.assertEqual(len(findings), 3)
        self.assertTrue(all(f["rule_id"] == "SC9" for f in findings))


class ShadowCrawlerAndDynamicImportTest(unittest.TestCase):
    def test_dynamic_top_level_txt_and_shadow_dependency_candidate(self):
        repo = Path(tempfile.mkdtemp())
        # Create fake .venv dist-info mapping import "custom_pay" -> distribution "acme-payments"
        di = repo / ".venv" / "lib" / "python3.11" / "site-packages" / "acme_payments-2.4.0.dist-info"
        di.mkdir(parents=True)
        (di / "METADATA").write_text("Name: acme-payments\nVersion: 2.4.0\n")
        (di / "top_level.txt").write_text("custom_pay\n")

        (repo / "requirements.txt").write_text("flask==3.0.0\n")
        (repo / "app.py").write_text("import flask\nimport custom_pay\n")

        imp_map = dynamic_py_import_map(repo)
        self.assertIn("acme-payments", imp_map.get("custom_pay", set()))

        # Reachability check using dynamic top_level.txt
        hits = import_usage(repo, ["acme-payments"], "pypi")
        self.assertEqual(len(hits["acme-payments"]), 1)

        inv = build_inventory(repo)
        comps = inv["components"]
        findings = crawl_shadow_dependencies(repo, inv, comps, cache_dir=repo / "cache", offline=True)
        sc8 = [f for f in findings if f["rule_id"] == "SC8"]
        self.assertEqual(len(sc8), 1)
        self.assertEqual(sc8[0]["evidence"]["package"], "acme-payments")
        self.assertEqual(sc8[0]["evidence"]["resolved_version"], "2.4.0")

        # Verify remediation candidate is built to pin acme-payments==2.4.0 in requirements.txt
        cands = build_candidates(repo, comps, findings, repo / "cache", offline=True)
        shdw = [c for c in cands if c["candidate_id"].startswith("FIX-SHDW-")]
        self.assertEqual(len(shdw), 1)
        self.assertIn("acme-payments==2.4.0", shdw[0]["diff"])

    def test_crawler_detects_rust_java_go_and_ruby_shadow_dependencies(self):
        repo = Path(tempfile.mkdtemp())
        # Rust
        (repo / "Cargo.toml").write_text('[package]\nname = "demo"\nversion = "0.1.0"\n[dependencies]\nserde = "1.0"\n')
        (repo / "Cargo.lock").write_text(
            '[[package]]\nname = "demo"\nversion = "0.1.0"\ndependencies = ["serde"]\n\n'
            '[[package]]\nname = "serde"\nversion = "1.0.0"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\n'
        )
        (repo / "src").mkdir()
        (repo / "src" / "main.rs").write_text("use serde::Serialize;\nuse tokio::net::TcpListener;\n")

        # Java
        (repo / "pom.xml").write_text(
            "<project><groupId>com.example</groupId><artifactId>app</artifactId><version>1.0</version>"
            "<dependencies><dependency><groupId>org.slf4j</groupId><artifactId>slf4j-api</artifactId><version>2.0.0</version></dependency></dependencies></project>"
        )
        (repo / "src" / "App.java").write_text("package com.example;\nimport org.slf4j.Logger;\nimport com.google.common.collect.ImmutableList;\n")

        # Go
        (repo / "go.mod").write_text("module example.com/demo\n\ngo 1.22\n\nrequire github.com/gin-gonic/gin v1.9.1\n")
        (repo / "main.go").write_text('package main\nimport (\n\t"fmt"\n\t"github.com/gin-gonic/gin"\n\t"github.com/spf13/cobra"\n)\n')

        inv = build_inventory(repo)
        comps = inv["components"]
        findings = crawl_shadow_dependencies(repo, inv, comps, cache_dir=repo / "cache", offline=True)
        sc8_pkgs = {f["evidence"]["ecosystem"]: f["evidence"]["package"] for f in findings if f["rule_id"] == "SC8"}
        self.assertEqual(sc8_pkgs.get("cargo"), "tokio")
        self.assertIn("com.google.common", sc8_pkgs.get("maven", ""))
        self.assertEqual(sc8_pkgs.get("golang"), "github.com/spf13/cobra")

        cands = build_candidates(repo, comps, findings, repo / "cache", offline=True)
        shdw_summaries = " | ".join(c["summary"] for c in cands if c["candidate_id"].startswith("FIX-SHDW-"))
        self.assertIn("Cargo.toml", shdw_summaries)
        self.assertIn("pom.xml", shdw_summaries)
        self.assertIn("go.mod", shdw_summaries)

    def test_crawler_ignores_internal_dotted_package_imports(self):
        repo = Path(tempfile.mkdtemp())
        (repo / "requirements.txt").write_text("pyyaml==6.0.1\n")
        # Create internal package tree: guardian/agents/gemini.py and guardian/agents/llm.py
        (repo / "guardian" / "agents").mkdir(parents=True)
        (repo / "guardian" / "__init__.py").write_text("")
        (repo / "guardian" / "agents" / "__init__.py").write_text("")
        (repo / "guardian" / "agents" / "gemini.py").write_text("class GeminiLLM:\n    pass\n")
        (repo / "guardian" / "agents" / "llm.py").write_text("class LLMUnavailable(Exception):\n    pass\n")
        # File importing internal dotted modules + 1 real external shadow dependency (requests)
        (repo / "tests").mkdir()
        (repo / "tests" / "test_internal.py").write_text(
            "from guardian.agents.gemini import GeminiLLM\n"
            "from guardian.agents.llm import LLMUnavailable\n"
            "from . import something_relative\n"
            "import requests\n"
        )
        inv = build_inventory(repo)
        comps = inv["components"]
        findings = crawl_shadow_dependencies(repo, inv, comps, cache_dir=repo / "cache", offline=True)
        flagged_pkgs = [f["evidence"]["package"] for f in findings if f["rule_id"] == "SC8"]
        self.assertNotIn("guardian", flagged_pkgs)
        self.assertEqual(flagged_pkgs, ["requests"])


class MerkleIntegrityAndLedgerTest(unittest.TestCase):
    def test_merkle_chunk_tamper_and_integrity_agent(self):
        repo = Path(tempfile.mkdtemp())
        out = Path(tempfile.mkdtemp())
        (repo / "payment.py").write_text(
            "def process_payment(amount):\n"
            "    gateway = 'https://api.stripe.com/v1/charges'\n"
            "    return (gateway, amount)\n"
        )
        # 1. Developer signs baseline with secret key
        create_baseline(repo, signing_key="super-secret-dev-key", signer="alice@dev")
        ok, msg, _ = verify_ledger(repo, signing_key="super-secret-dev-key")
        self.assertTrue(ok)
        self.assertEqual(run_watch(repo, rounds=2, signing_key="super-secret-dev-key"), [])

        # 2. Malicious package / unauthorized edit changes line 2 without re-signing
        (repo / "payment.py").write_text(
            "def process_payment(amount):\n"
            "    gateway = 'https://evil-attacker.example.com/steal'\n"
            "    return (gateway, amount)\n"
        )
        anomalies = run_watch(repo, rounds=1, signing_key="super-secret-dev-key")
        self.assertEqual(len(anomalies), 1)
        self.assertEqual(anomalies[0]["file"], "payment.py")
        self.assertEqual(anomalies[0]["line"], 2)
        self.assertIn("evil-attacker", anomalies[0]["excerpt"])

        # 3. Integrity detector + IntegrityAgent investigation
        findings = check_repo_integrity(repo, signing_key="super-secret-dev-key")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["rule_id"], "IT1")

        state = RunState(repo, out)
        state.set_findings(findings)
        res = IntegrityAgent().run(state, llm=None)
        self.assertEqual(len(res["investigations"]), 1)
        self.assertEqual(res["investigations"][0]["verdict"], "confirmed_risk")

        # 4. Tamper with the ledger directly and verify IT2 catches the exact record
        ledger_p = repo / ".guardian" / "ledger.jsonl"
        lines = ledger_p.read_text().splitlines()
        rec0 = json.loads(lines[0])
        rec0["data"]["signer"] = "forged-attacker"
        ledger_p.write_text(json.dumps(rec0) + "\n")
        ok2, msg2, _ = verify_ledger(repo, signing_key="super-secret-dev-key")
        self.assertFalse(ok2)
        self.assertIn("CHAIN BREAK at record #0", msg2)


class AutoMitigateAndMergeTest(unittest.TestCase):
    def test_auto_mitigate_generates_smoke_test_and_auto_merges(self):
        repo = Path(tempfile.mkdtemp())
        out = Path(tempfile.mkdtemp())
        (repo / "requirements.txt").write_text("flask==3.0.0\n")
        (repo / "app.py").write_text("def hello():\n    return 'ok'\n")

        state = RunState(repo, out)
        cand = {
            "candidate_id": "FIX-SHDW-123456",
            "action": "pin",
            "summary": "Declare shadow dependency requests==2.31.0 in requirements.txt",
            "component_id": "pkg:pypi/requests@2.31.0",
            "closes": ["SC8-1"],
            "change_risk": "low",
            "files": {"requirements.txt": ("flask==3.0.0\n", "flask==3.0.0\nrequests==2.31.0\n")},
        }
        res = auto_mitigate_candidate(state, cand, llm=None, auto_merge=True)
        self.assertEqual(res["verdict"], "verified")
        self.assertTrue(res["merged"])
        self.assertEqual(res["test_info"]["kind"], "generated")
        self.assertTrue(any(s["name"] == "create_test_env" for s in res["steps"]))
        self.assertIn("requests==2.31.0", (repo / "requirements.txt").read_text())

    def test_gemini_api_for_testing_env_key_priority(self):
        import os
        with patch.dict(os.environ, {"GEMINI_API_KEYS": "main_key_1", "GEMINI_API_FOR_TESTING": "test_key_99", "GEMINI_FOR_SANDBOX": "sbx_key_77"}, clear=False):
            self.assertEqual(gemini_keys(for_testing=True)[0], "test_key_99")
            self.assertEqual(gemini_keys(for_sandbox=True)[0], "sbx_key_77")
            self.assertEqual(gemini_keys(for_testing=False, for_sandbox=False)[0], "main_key_1")

    def test_sandbox_dockerfile_generation_when_missing(self):
        from guardian.validation.auto_mitigate import _generate_sandbox_dockerfile
        td = Path(tempfile.mkdtemp())
        (td / "requirements.txt").write_text("flask==3.0.0\n")
        (td / "app.py").write_text("import flask\n")
        df_path, step = _generate_sandbox_dockerfile(td, "pypi", llm=None)
        self.assertTrue(df_path.is_file())
        self.assertEqual(step["name"], "generate_dockerfile")
        self.assertIn("FROM python:", df_path.read_text())


class MaliciousAndPhantomShadowTest(unittest.TestCase):
    def test_malicious_shadow_and_phantom_shadow_dependencies(self):
        repo = Path(tempfile.mkdtemp())
        cache = repo / "cache"
        (cache / "osv").mkdir(parents=True)
        (cache / "registry").mkdir(parents=True)

        # requirements.txt declares flask (direct) and urllib3 (transitive via flask)
        (repo / "requirements.txt").write_text("flask==3.0.0\n    # via -r requirements.in\nurllib3==2.2.1\n    # via flask\n")
        # app.py imports urllib3 (phantom transitive) and evil_drain_sdk (undeclared malicious shadow)
        (repo / "app.py").write_text("import flask\nimport urllib3\nimport evil_drain_sdk\n")

        (cache / "registry" / "pypi-evil-drain-sdk.json").write_text(json.dumps({
            "name": "evil-drain-sdk", "version": "1.0.0",
            "releases": {"1.0.0": [{"upload_time_iso_8601": "2026-11-23T00:00:00Z"}]}
        }))
        mal_rec = {
            "id": "MAL-2026-9999",
            "summary": "Malicious exfiltration package evil-drain-sdk",
            "aliases": [],
            "affected": [{"package": {"ecosystem": "PyPI", "name": "evil-drain-sdk"},
                          "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}]}],
        }
        (cache / "osv" / "MAL-2026-9999.json").write_text(json.dumps(mal_rec))

        inv = build_inventory(repo)
        comps = inv["components"]
        with patch("guardian.intel.osv._query_ids", return_value={"pkg:pypi/evil-drain-sdk@1.0.0": ["MAL-2026-9999"]}):
            findings = crawl_shadow_dependencies(repo, inv, comps, cache_dir=cache, offline=True)

        sc8_by_pkg = {f["evidence"]["package"]: f for f in findings if f["rule_id"] == "SC8"}
        # 1. Phantom dependency (transitive urllib3 imported directly)
        self.assertIn("urllib3", sc8_by_pkg)
        self.assertEqual(sc8_by_pkg["urllib3"]["evidence"]["shadow_kind"], "phantom (transitive-only)")
        self.assertEqual(sc8_by_pkg["urllib3"]["severity"], "MEDIUM")

        # 2. Malicious shadow dependency (undeclared evil-drain-sdk with MAL-2026-9999)
        self.assertIn("evil-drain-sdk", sc8_by_pkg)
        self.assertEqual(sc8_by_pkg["evil-drain-sdk"]["category"], "malicious")
        self.assertEqual(sc8_by_pkg["evil-drain-sdk"]["severity"], "CRITICAL")


class HumanWarningBypassTest(unittest.TestCase):
    def test_human_can_waive_and_unwaive_finding_with_ledger_audit(self):
        repo = Path(tempfile.mkdtemp())
        (repo / "app.py").write_text("print('ok')\n")
        findings = [{
            "finding_id": "SC11-abcdef1234",
            "rule_id": "SC11",
            "category": "suspicious",
            "severity": "MEDIUM",
            "title": "PyPI release fresh-pkg==0.1.0 uploaded 1d ago (< 7d)",
            "component_id": "pkg:pypi/fresh-pkg@0.1.0",
        }]
        w = waive_finding(repo, "SC11-abcdef1234", reason="Verified internal release by maintainer", by="alice", signing_key="k1")
        self.assertEqual(w["status"], "waived")
        self.assertIn("SC11-abcdef1234", load_waivers(repo))

        apply_waivers(repo, findings)
        self.assertTrue(findings[0].get("waived"))
        self.assertEqual(findings[0]["waiver"]["reason"], "Verified internal release by maintainer")

        # Ledger chain remains valid and records the human bypass
        ok, msg, _ = verify_ledger(repo, signing_key="k1")
        self.assertTrue(ok)

        # Unwaive restores the warning
        self.assertTrue(unwaive_finding(repo, "SC11-abcdef1234", by="alice", signing_key="k1"))
        self.assertNotIn("SC11-abcdef1234", load_waivers(repo))


class ReportPdfAndGitHubAppPRTest(unittest.TestCase):
    def test_executive_report_and_pdf_export(self):
        from guardian.reporting import write_report
        repo = Path(tempfile.mkdtemp())
        out = Path(tempfile.mkdtemp())
        (repo / "requirements.txt").write_text("pillow==13.0.0\n")
        st = RunState(repo, out)
        st.comps = {"pkg:pypi/pillow@11.0.0": Component(
            component_id="pkg:pypi/pillow@11.0.0", name="pillow", version="11.0.0", ecosystem="pypi", relationship="direct"
        )}
        st.set_findings([{
            "finding_id": "CVE-2025-1:pkg:pypi/pillow@11.0.0",
            "rule_id": "OSV", "category": "vulnerability", "severity": "HIGH",
            "title": "Buffer overflow in pillow", "component_id": "pkg:pypi/pillow@11.0.0",
            "advisory_id": "CVE-2025-1", "aliases": [], "evidence": {"source": "OSV"},
        }])
        st.risk = {"CVE-2025-1:pkg:pypi/pillow@11.0.0": {"score": 72, "severity": "HIGH", "factors": {}}}
        st.proposals = [{
            "candidate_id": "FIX-VULN-1", "finding_ids": ["CVE-2025-1:pkg:pypi/pillow@11.0.0"],
            "summary": "Upgrade pillow 11.0.0 -> 13.0.0 (requirements.txt)",
            "change_risk": "high", "rationale": "Closes buffer overflow CVE-2025-1",
            "expected_risk_reduction": "Eliminates remote image parsing RCE risk.",
        }]
        st.approvals = {"FIX-VULN-1": {"status": "approved"}}
        st.validations = [{
            "candidate_id": "FIX-VULN-1", "summary": "Upgrade pillow 11.0.0 -> 13.0.0",
            "verdict": "verified", "merged": True, "merged_files": ["requirements.txt"],
            "steps": [{"name": "run_tests", "rc": 0, "detail": "smoke test passed"}],
            "test_info": {"kind": "generated"},
        }]
        paths = write_report(st, llm=None)
        self.assertIn("report.pdf", paths)
        pdf_bytes = (out / "report.pdf").read_bytes()
        self.assertTrue(pdf_bytes.startswith(b"%PDF-1.4"))
        md_text = (out / "report.md").read_text()
        self.assertIn("## Executive Remediation Summary", md_text)
        self.assertIn("Upgrade pillow", md_text)
        rj = json.loads((out / "report.json").read_text())
        self.assertIn("executive_narrative", rj)
        self.assertEqual(len(rj["executive_narrative"]["actions"]), 1)

    def test_github_app_jwt_and_pr_creation(self):
        import subprocess
        from guardian.remediation.github_pr import create_app_jwt, create_remediation_pr

        td = Path(tempfile.mkdtemp())
        pem = td / "test-app.pem"
        # Generate a real ephemeral 2048-bit RSA key for testing RS256 JWT signing
        subprocess.run(["openssl", "genrsa", "-out", str(pem), "2048"], check=True, capture_output=True)
        jwt_tok = create_app_jwt("123456", pem)
        self.assertEqual(len(jwt_tok.split(".")), 3)

        repo = td / "repo"
        out = td / "out"
        repo.mkdir(); out.mkdir()
        (repo / "requirements.txt").write_text("flask==3.0.0\n")
        subprocess.run(["git", "-C", str(repo), "init", "-q"], check=True)
        subprocess.run(["git", "-C", str(repo), "remote", "add", "origin", "https://github.com/octocat/Hello-World.git"], check=True)
        subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
        subprocess.run(["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "init"], check=True)
        (repo / "requirements.txt").write_text("flask==3.1.0\n")
        (out / "report.json").write_text(json.dumps({
            "executive_narrative": {
                "markdown": "Upgraded flask to 3.1.0",
                "actions": [{"candidate_id": "FIX-VULN-1", "action": "Upgrade flask 3.0.0 -> 3.1.0", "verdict": "verified", "outcome": "Auto-Merged"}],
            }
        }))

        def fake_gh(method, path, token, body=None):
            if path == "/repos/octocat/Hello-World":
                return 200, {"default_branch": "main"}
            if path == "/repos/octocat/Hello-World/forks":
                return 202, {"full_name": "guardian-bot/Hello-World", "owner": {"login": "guardian-bot"}}
            if path == "/repos/octocat/Hello-World/pulls":
                return 201, {"html_url": "https://github.com/octocat/Hello-World/pull/42", "number": 42}
            return 200, {}

        orig_git = __import__("guardian.remediation.github_pr", fromlist=["_git"])._git
        def git_side_effect(r, *a, **kw):
            if a and a[0] == "push":
                return 0, "pushed"
            return orig_git(r, *a, **kw)

        with patch("guardian.remediation.github_pr.get_installation_token", return_value=("ghs_fake_tok", "999")), \
                patch("guardian.remediation.github_pr._gh_request", side_effect=fake_gh), \
                patch("guardian.remediation.github_pr.time.sleep"), \
                patch("guardian.remediation.github_pr._git", side_effect=git_side_effect):
            res = create_remediation_pr(repo, out, app_id="123456", pem_path=str(pem))

        self.assertTrue(res["ok"])
        self.assertEqual(res["pr_number"], 42)
        self.assertEqual(res["pr_url"], "https://github.com/octocat/Hello-World/pull/42")
        self.assertTrue(res["branch"].startswith("guardian/deps/"))
        self.assertEqual(res["fork"], "guardian-bot/Hello-World")


if __name__ == "__main__":
    unittest.main()
