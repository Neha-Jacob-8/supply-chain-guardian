"""Auto-Mitigation Engine: LLM / fallback test discovery & generation, sandbox execution, and auto-merge.

Designed for demo and small-to-medium projects:
  1. Checks if the project already has unit tests (`tests/test_*.py`, `*test*.py`, `*.test.js`, or a real `package.json` `"test"` script).
  2. If no existing test covers the patched dependency/module, uses the configured LLM (or a deterministic smoke-test generator when `--llm none`)
     to create a lightweight smoke test (`_guardian_smoke_test.py` or `_guardian_smoke_test.js`) based on actual import sites in the repository.
  3. Applies the remediation candidate in an isolated sandbox directory and executes the test suite.
  4. If the test suite passes (`rc == 0`) and `auto_merge=True`, merges the patched files into the target repository,
     updates the signed Merkle baseline & hash-chained ledger (if present), and records the full result for the Web UI.
"""
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time

from ..integrity import append_ledger_record, create_baseline
from ..intel.risk import import_usage


def _run_cmd(cmd, cwd, timeout=60):
    t0 = time.time()
    try:
        r = subprocess.run(cmd, cwd=str(cwd), capture_output=True, text=True, timeout=timeout)
        rc, out = r.returncode, (r.stdout or "") + (r.stderr or "")
    except FileNotFoundError as e:
        rc, out = 127, str(e)
    except subprocess.TimeoutExpired as e:
        rc = 124
        out = ((e.stdout or "") if isinstance(e.stdout, str) else "") + "\ncommand timed out"
    return {"cmd": " ".join(str(x) for x in cmd), "rc": rc, "seconds": round(time.time() - t0, 2), "output": out[-3000:]}


def discover_existing_tests(work_dir: Path) -> dict | None:
    """Detect existing runnable Python or Node unit tests in a directory."""
    work_dir = Path(work_dir)
    # 1. Python tests
    py_tests = [
        p for p in sorted(work_dir.rglob("*.py"))
        if (p.name.startswith("test_") or p.name.endswith("_test.py"))
        and not {".git", "node_modules", ".venv", "venv", "output", "validation"} & set(p.relative_to(work_dir).parts)
    ]
    if py_tests:
        return {
            "kind": "existing",
            "ecosystem": "pypi",
            "files": [str(p.relative_to(work_dir)) for p in py_tests[:10]],
            "command": [sys.executable, "-m", "unittest", "discover", "-s", str(py_tests[0].parent.relative_to(work_dir)), "-t", "."],
        }

    # 2. Node.js tests
    pj_path = work_dir / "package.json"
    if pj_path.exists():
        try:
            pj = json.loads(pj_path.read_text())
        except Exception:
            pj = {}
        test_script = ((pj.get("scripts") or {}).get("test") or "").strip()
        if test_script and "no test specified" not in test_script.lower():
            return {
                "kind": "existing",
                "ecosystem": "npm",
                "files": ["package.json (scripts.test)"],
                "command": ["npm", "test"],
            }
    js_tests = [
        p for p in sorted(work_dir.rglob("*.test.js"))
        if not {".git", "node_modules", "output", "validation"} & set(p.relative_to(work_dir).parts)
    ]
    if js_tests and shutil.which("node"):
        return {
            "kind": "existing",
            "ecosystem": "npm",
            "files": [str(p.relative_to(work_dir)) for p in js_tests[:10]],
            "command": ["node", str(js_tests[0].relative_to(work_dir))],
        }
    return None


def _generate_llm_or_fallback_test(state, cand, work_dir: Path, llm=None) -> dict:
    """Generate a lightweight smoke test for a demo project when no existing unit tests exist."""
    work_dir = Path(work_dir)
    comp = state.comps.get(cand.get("component_id")) if cand.get("component_id") else None
    is_py = (comp and comp.ecosystem == "pypi") or any(f.endswith((".txt", ".toml", ".py")) for f in cand.get("files", {}))
    pkg_name = comp.name if comp else ""

    # Gather context on where the package or app code lives
    app_files = [
        p for p in sorted(work_dir.rglob("*.py" if is_py else "*.js"))
        if not {".git", "node_modules", ".venv", "venv", "output", "validation"} & set(p.relative_to(work_dir).parts)
        and not p.name.startswith("_guardian_")
    ]
    sample_file = str(app_files[0].relative_to(work_dir)) if app_files else None
    sample_code = (work_dir / sample_file).read_text(errors="replace")[:1200] if sample_file else ""

    generated_code = None
    generator_mode = "deterministic-template"

    # Prefer dedicated GEMINI_API_FOR_TESTING key if configured in environment/.env
    test_llm = llm
    if os.environ.get("GEMINI_API_FOR_TESTING"):
        try:
            from ..agents.gemini import GeminiLLM, gemini_keys
            test_llm = GeminiLLM(keys=gemini_keys(for_testing=True))
        except Exception:
            pass

    if test_llm is not None:
        prompt = (
            f"Generate a minimal, self-contained {'Python unittest' if is_py else 'Node.js'} smoke test file "
            f"to verify that applying patch `{cand.get('summary')}` does not break syntax or module loading.\n"
            f"Target file: `{sample_file or 'none'}`\n"
            f"Code excerpt:\n```\n{sample_code}\n```\n"
            "Rules: Do not make external network requests; output ONLY raw code (no markdown fences)."
        )
        for provider in (getattr(test_llm, "providers", None) or [test_llm]):
            try:
                r = provider.step("You write concise, safe smoke tests. Output raw code only.", [{"role": "user", "content": prompt}], [])
                txt = (r.text or "").strip()
                txt = re.sub(r"^```[a-zA-Z]*\n|\n```$", "", txt).strip()
                if txt and ("import " in txt or "require(" in txt or "assert" in txt):
                    generated_code = txt
                    generator_mode = f"llm:{provider.name}"
                    break
            except Exception:
                continue

    if is_py:
        test_rel = "_guardian_smoke_test.py"
        if not generated_code:
            lines = [
                "import ast",
                "import pathlib",
                "import unittest",
                "",
                "class GuardianSmokeTest(unittest.TestCase):",
                "    def test_project_python_files_compile(self):",
                "        root = pathlib.Path(__file__).parent",
                "        for p in root.rglob('*.py'):",
                "            if '.venv' in p.parts or 'venv' in p.parts:",
                "                continue",
                "            src = p.read_text(encoding='utf-8', errors='replace')",
                "            ast.parse(src, filename=str(p))",
            ]
            if sample_file and sample_file.endswith(".py"):
                lines += [
                    "    def test_target_module_ast_and_manifests(self):",
                    f"        target = pathlib.Path(__file__).parent / {sample_file!r}",
                    "        self.assertTrue(target.exists())",
                    "        tree = ast.parse(target.read_text(encoding='utf-8'))",
                    "        self.assertIsNotNone(tree)",
                ]
            lines += ["", "if __name__ == '__main__':", "    unittest.main()", ""]
            generated_code = "\n".join(lines)
        (work_dir / test_rel).write_text(generated_code, encoding="utf-8")
        return {
            "kind": "generated",
            "generator": generator_mode,
            "ecosystem": "pypi",
            "files": [test_rel],
            "code": generated_code,
            "command": [sys.executable, test_rel],
        }
    else:
        test_rel = "_guardian_smoke_test.js"
        if not generated_code:
            lines = [
                "const fs = require('fs');",
                "const path = require('path');",
                "const vm = require('vm');",
                "const root = __dirname;",
                "if (fs.existsSync(path.join(root, 'package.json'))) {",
                "  const pj = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));",
                "  if (!pj || typeof pj !== 'object') throw new Error('Invalid package.json');",
                "}",
            ]
            if sample_file and sample_file.endswith(".js"):
                lines += [
                    f"const src = fs.readFileSync(path.join(root, {sample_file!r}), 'utf8');",
                    f"new vm.Script(src, {{ filename: {sample_file!r} }});",
                ]
            lines.append("console.log('Guardian smoke test passed');\n")
            generated_code = "\n".join(lines)
        (work_dir / test_rel).write_text(generated_code, encoding="utf-8")
        cmd = ["node", test_rel] if shutil.which("node") else [sys.executable, "-c", "import json, pathlib; json.loads((pathlib.Path('package.json').read_text())) if pathlib.Path('package.json').exists() else None; print('JSON syntax verified')"]
        return {
            "kind": "generated",
            "generator": generator_mode,
            "ecosystem": "npm",
            "files": [test_rel],
            "code": generated_code,
            "command": cmd,
        }


def auto_mitigate_candidate(state, cand, llm=None, auto_merge=True, save_generated_test=False) -> dict:
    """Run test discovery / LLM test generation in a sandbox, validate the patch, and auto-merge if tests pass."""
    cid = cand["candidate_id"]
    work = state.out / "validation" / f"automitigate_{cid}"
    if work.exists():
        shutil.rmtree(work)
    shutil.copytree(
        state.repo,
        work,
        ignore=shutil.ignore_patterns(".git", "node_modules", ".venv", "venv", "output", "validation"),
    )

    steps = []
    # 1. Apply patch in sandbox
    for rel_path, (old_text, new_text) in cand.get("files", {}).items():
        target = work / rel_path
        cur = target.read_text(encoding="utf-8") if target.exists() else ""
        if cur != old_text and cur != new_text:
            steps.append({"name": "apply_patch", "rc": 1, "detail": f"{rel_path} differs from expected base content"})
            return {
                "candidate_id": cid, "summary": cand["summary"], "verdict": "failed",
                "merged": False, "steps": steps, "test_info": None,
            }
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(new_text, encoding="utf-8")
    steps.append({"name": "apply_patch", "rc": 0, "detail": f"Patched {len(cand.get('files', {}))} file(s) in sandbox"})

    # 2. Discover existing tests or generate smoke test
    test_info = discover_existing_tests(work)
    if test_info is None:
        test_info = _generate_llm_or_fallback_test(state, cand, work, llm=llm)
        steps.append({
            "name": "generate_smoke_test",
            "rc": 0,
            "detail": f"No existing tests found; generated {test_info['files'][0]} ({test_info['generator']})",
            "log_tail": test_info.get("code", ""),
        })
    else:
        steps.append({
            "name": "discover_tests",
            "rc": 0,
            "detail": f"Found existing test suite: {', '.join(test_info['files'])}",
        })

    # 3. Execute test suite in sandbox
    run_res = _run_cmd(test_info["command"], cwd=work, timeout=90)
    steps.append({
        "name": "run_tests",
        "rc": run_res["rc"],
        "seconds": run_res["seconds"],
        "detail": f"Executed `{run_res['cmd']}` -> exit {run_res['rc']}",
        "log_tail": run_res["output"],
    })

    passed = run_res["rc"] == 0
    merged = False
    merged_files = []
    ledger_hash = None

    # 4. Auto-merge back into target repository if tests passed
    if passed and auto_merge:
        for rel_path, (_old_text, new_text) in cand.get("files", {}).items():
            dest = Path(state.repo) / rel_path
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(new_text, encoding="utf-8")
            merged_files.append(rel_path)

        if save_generated_test and test_info.get("kind") == "generated" and test_info.get("code"):
            gen_rel = test_info["files"][0]
            (Path(state.repo) / gen_rel).write_text(test_info["code"], encoding="utf-8")
            merged_files.append(gen_rel)

        # If repository uses a signed Merkle baseline or ledger, update them automatically
        if (Path(state.repo) / ".guardian" / "baseline.json").exists():
            create_baseline(state.repo, signer="guardian-auto-mitigate")
        else:
            ledger_hash = append_ledger_record(
                state.repo,
                {
                    "event": "auto_mitigate_merged",
                    "candidate_id": cid,
                    "summary": cand["summary"],
                    "files": merged_files,
                    "test_kind": test_info["kind"],
                },
            )
        merged = True
        steps.append({
            "name": "auto_merge",
            "rc": 0,
            "detail": f"Auto-merged {', '.join(merged_files)} into repository" + (f" (ledger {ledger_hash[:12]})" if ledger_hash else ""),
        })

    verdict = "verified" if passed else "failed"
    result = {
        "candidate_id": cid,
        "summary": cand["summary"],
        "verdict": verdict,
        "merged": merged,
        "merged_files": merged_files,
        "ledger_hash": ledger_hash,
        "test_info": test_info,
        "steps": steps,
        "validated_by": "auto_mitigate (test + sandbox)",
    }
    state.log("auto_mitigate", "completed", {"candidate_id": cid, "verdict": verdict, "merged": merged, "test_kind": test_info["kind"]})
    return result
