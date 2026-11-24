import datetime
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from guardian.agents.integrity_agent import IntegrityAgent
from guardian.agents.state import RunState
from guardian.discovery import build_inventory
from guardian.ingestion import parse_github_url
from guardian.integrity import append_ledger_record, check_repo_integrity, create_baseline, run_watch, verify_ledger
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
        self.assertIn("requests==2.31.0", (repo / "requirements.txt").read_text())


if __name__ == "__main__":
    unittest.main()
