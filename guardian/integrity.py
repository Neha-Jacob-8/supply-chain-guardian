"""Merkle-tree chunk baseline, secret-key developer signing, line-level tamper localization,
and tamper-evident hash-chained audit ledger (Rules IT1, IT2).

Workflow:
  1. Developer signs legitimate changes: `guardian baseline <repo> [--key <secret>]`
     - Splits tracked/monitored files into 4096-byte chunks
     - Computes per-file SHA-256 Merkle trees and line hashes (for text files)
     - Signs `.guardian/baseline.json` with HMAC-SHA256 derived from the secret signing key
     - Appends a signed block to `.guardian/ledger.jsonl`
  2. Scanner / Watcher verifies integrity: `guardian watch <repo>` or during `guardian scan`/`run`
     - Performs HMAC-keyed random chunk sampling (plus full check rounds)
     - Pinpoints the exact modified file, chunk index, byte offset, and modified line numbers (IT1)
     - Verifies the hash chain (`prev_hash` -> `record_hash`) and `head_sig` in `.guardian/ledger.jsonl` (IT2)
"""
from datetime import datetime, timezone
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import time

SKIP_DIRS = frozenset({
    ".git", ".guardian", ".truststack", ".truststack_cache", "node_modules",
    ".venv", "venv", "__pycache__", "out", "output", "dist", "build", "target", "validation",
})

TEXT_EXTS = frozenset({
    ".py", ".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs", ".json", ".yaml", ".yml",
    ".toml", ".lock", ".txt", ".md", ".go", ".rs", ".rb", ".java", ".xml", ".sh",
})


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _merkle_root(hashes: list[str]) -> str:
    if not hashes:
        return _sha256(b"")
    layer = list(hashes)
    while len(layer) > 1:
        if len(layer) % 2 == 1:
            layer.append(layer[-1])
        layer = [_sha256((layer[i] + layer[i + 1]).encode()) for i in range(0, len(layer), 2)]
    return layer[0]


def _guardian_dir(repo: str | Path) -> Path:
    d = Path(repo) / ".guardian"
    d.mkdir(parents=True, exist_ok=True)
    return d


def resolve_signing_key(repo: str | Path, explicit_key: str | bytes | None = None, create: bool = True) -> bytes | None:
    """Resolve the developer signing key from:
      1. `explicit_key` argument (--key)
      2. `GUARDIAN_SIGNING_KEY` environment variable
      3. `~/.guardian/signing.key` or `<repo>/.guardian/baseline.key`
    """
    if explicit_key:
        raw = explicit_key.encode() if isinstance(explicit_key, str) else explicit_key
        return hashlib.sha256(raw).digest()
    env_key = os.environ.get("GUARDIAN_SIGNING_KEY")
    if env_key:
        return hashlib.sha256(env_key.encode()).digest()

    gdir = _guardian_dir(repo)
    key_path = gdir / "baseline.key"
    legacy_path = Path(repo) / ".truststack" / "baseline.key"
    if key_path.exists():
        return key_path.read_bytes()
    if legacy_path.exists():
        return legacy_path.read_bytes()
    if not create:
        return None
    key = secrets.token_bytes(32)
    key_path.write_bytes(key)
    try:
        os.chmod(key_path, 0o600)
    except OSError:
        pass
    return key


def _collect_files(repo: str | Path, venv_dir: str | None = None, max_files: int = 50000) -> list[tuple[str, Path]]:
    repo_p = Path(repo)
    targets = []
    for root, dirs, files in os.walk(repo_p):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
        for fname in sorted(files):
            full = Path(root) / fname
            rel = str(full.relative_to(repo_p)).replace("\\", "/")
            targets.append((rel, full))
            if len(targets) >= max_files:
                return targets
    if venv_dir and os.path.exists(venv_dir):
        v_p = Path(venv_dir)
        for root, dirs, files in os.walk(v_p):
            dirs[:] = sorted(d for d in dirs if d != "__pycache__")
            for fname in sorted(files):
                full = Path(root) / fname
                rel = "@venv/" + str(full.relative_to(v_p)).replace("\\", "/")
                targets.append((rel, full))
                if len(targets) >= max_files:
                    return targets
    return targets


def _line_hashes(data: bytes, rel: str) -> list[str] | None:
    if Path(rel).suffix.lower() not in TEXT_EXTS or len(data) > 512_000:
        return None
    try:
        lines = data.decode("utf-8").splitlines()
    except UnicodeDecodeError:
        return None
    return [_sha256(ln.encode("utf-8"))[:16] for ln in lines]


def create_baseline(
    repo: str | Path,
    venv_dir: str | None = None,
    chunk_size: int = 4096,
    signing_key: str | bytes | None = None,
    signer: str = "developer",
) -> dict:
    """Split monitored files into 4096B chunks, build Merkle trees, sign with HMAC, and log to ledger."""
    repo_p = Path(repo)
    gdir = _guardian_dir(repo_p)
    key = resolve_signing_key(repo_p, signing_key, create=True)

    files_meta = {}
    for rel, full in _collect_files(repo_p, venv_dir):
        try:
            data = full.read_bytes()
        except OSError:
            continue
        chunks = [
            _sha256(data[i : i + chunk_size])
            for i in range(0, max(1, len(data)), chunk_size)
        ]
        meta = {
            "size": len(data),
            "whole_sha256": _sha256(data),
            "chunks": chunks,
            "merkle_root": _merkle_root(chunks),
        }
        lh = _line_hashes(data, rel)
        if lh is not None:
            meta["line_hashes"] = lh
        files_meta[rel] = meta

    payload = {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "signer": signer,
        "chunk_size": chunk_size,
        "venv_dir": venv_dir,
        "files": files_meta,
    }
    canon = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    sig = hmac.new(key, canon, hashlib.sha256).hexdigest()
    doc = {**payload, "hmac": sig}
    (gdir / "baseline.json").write_text(json.dumps(doc, indent=2), encoding="utf-8")

    # Record baseline sign-off in the hash-chained ledger
    append_ledger_record(
        repo_p,
        {
            "event": "baseline_signed",
            "signer": signer,
            "files_count": len(files_meta),
            "baseline_hmac": sig,
            "timestamp": payload["created_at"],
        },
        signing_key=signing_key,
    )
    return doc


def _pick_chunk_indices(key: bytes, nonce: str, rel: str, num_chunks: int, n: int) -> list[int]:
    if num_chunks <= n:
        return list(range(num_chunks))
    picked = set()
    counter = 0
    while len(picked) < n:
        digest = hmac.new(key, f"{nonce}:{rel}:{counter}".encode(), hashlib.sha256).digest()
        idx = int.from_bytes(digest[:8], "big") % num_chunks
        picked.add(idx)
        counter += 1
    return sorted(picked)


def _diff_modified_lines(data: bytes, expected_line_hashes: list[str] | None, chunk_idx: int, chunk_size: int) -> dict:
    """Identify exact modified line numbers and excerpt inside a tampered file/chunk."""
    try:
        lines = data.decode("utf-8", errors="replace").splitlines()
    except Exception:
        lines = []
    if expected_line_hashes and lines:
        changed_lines = []
        for i, ln in enumerate(lines, 1):
            h = _sha256(ln.encode("utf-8"))[:16]
            if i > len(expected_line_hashes) or h != expected_line_hashes[i - 1]:
                changed_lines.append((i, ln.strip()[:160]))
        if changed_lines:
            first_ln = changed_lines[0][0]
            return {
                "line": first_ln,
                "modified_lines": [ln for ln, _ in changed_lines[:15]],
                "excerpt": "\n".join(f"L{ln}: {txt}" for ln, txt in changed_lines[:8]),
            }
    # Fallback: map byte offset chunk_idx * chunk_size to line numbers
    start_byte = chunk_idx * chunk_size
    prefix = data[:start_byte].decode("utf-8", errors="replace")
    start_line = prefix.count("\n") + 1
    chunk_text = data[start_byte : start_byte + chunk_size].decode("utf-8", errors="replace")
    end_line = start_line + chunk_text.count("\n")
    excerpt = "\n".join(f"L{i}: {lines[i - 1][:160]}" for i in range(start_line, min(len(lines) + 1, end_line + 1))[:8])
    return {
        "line": start_line,
        "modified_lines": list(range(start_line, end_line + 1))[:15],
        "excerpt": excerpt or chunk_text[:200],
    }


def run_watch(
    repo: str | Path,
    interval: int = 0,
    rounds: int = 1,
    sample_n: int = 8,
    full_check_every: int = 1,
    signing_key: str | bytes | None = None,
) -> list[dict]:
    """Run keyed random-chunk spot-checks and Merkle verification against the signed baseline."""
    repo_p = Path(repo)
    base_path = repo_p / ".guardian" / "baseline.json"
    if not base_path.exists():
        legacy = repo_p / ".truststack" / "baseline.json"
        if legacy.exists():
            base_path = legacy
        else:
            raise FileNotFoundError(f"No baseline found at {base_path}. Run `guardian baseline <repo>` first.")

    key = resolve_signing_key(repo_p, signing_key, create=False)
    if not key:
        return [{"round": 0, "status": "missing_key", "file": str(base_path.relative_to(repo_p))}]

    try:
        doc = json.loads(base_path.read_text(encoding="utf-8"))
    except Exception:
        return [{"round": 0, "status": "corrupt_baseline", "file": str(base_path.relative_to(repo_p))}]

    stored_sig = doc.get("hmac", "")
    payload = {k: v for k, v in doc.items() if k != "hmac"}
    canon = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    if not hmac.compare_digest(stored_sig, hmac.new(key, canon, hashlib.sha256).hexdigest()):
        return [{"round": 0, "status": "tampered_baseline", "file": str(base_path.relative_to(repo_p))}]

    chunk_size = int(doc.get("chunk_size", 4096))
    files_meta = doc.get("files", {})
    findings = []
    seen_files = set()

    for r in range(1, rounds + 1):
        nonce = secrets.token_hex(12)
        is_full = (full_check_every <= 1) or (r % full_check_every == 0)
        for rel, meta in files_meta.items():
            if rel in seen_files:
                continue
            full = (Path(doc["venv_dir"]) / rel[6:]) if (rel.startswith("@venv/") and doc.get("venv_dir")) else (repo_p / rel)
            if not full.exists():
                seen_files.add(rel)
                findings.append({"round": r, "status": "missing", "file": rel})
                continue
            try:
                data = full.read_bytes()
            except OSError:
                continue
            exp_chunks = meta.get("chunks", [])
            n = sample_n * 2 if rel.endswith(("package-lock.json", "package.json", "requirements.txt", "pom.xml")) else sample_n
            indices = (
                list(range(len(exp_chunks)))
                if is_full
                else _pick_chunk_indices(key, nonce, rel, len(exp_chunks), n)
            )
            tampered_chunk = None
            for idx in indices:
                start = idx * chunk_size
                actual = _sha256(data[start : start + chunk_size])
                if idx >= len(exp_chunks) or actual != exp_chunks[idx]:
                    tampered_chunk = (idx, start, exp_chunks[idx] if idx < len(exp_chunks) else None, actual)
                    break

            if tampered_chunk is not None:
                seen_files.add(rel)
                idx, start, exp_h, act_h = tampered_chunk
                line_info = _diff_modified_lines(data, meta.get("line_hashes"), idx, chunk_size)
                findings.append({
                    "round": r,
                    "status": "chunk_modified",
                    "file": rel,
                    "chunk": idx,
                    "offset": start,
                    "expected": exp_h,
                    "actual": act_h,
                    "expected_merkle_root": meta.get("merkle_root"),
                    "actual_merkle_root": _merkle_root([_sha256(data[i : i + chunk_size]) for i in range(0, max(1, len(data)), chunk_size)]),
                    **line_info,
                })
            elif len(data) != meta.get("size"):
                seen_files.add(rel)
                line_info = _diff_modified_lines(data, meta.get("line_hashes"), 0, chunk_size)
                findings.append({
                    "round": r,
                    "status": "size_changed",
                    "file": rel,
                    "expected_size": meta.get("size"),
                    "actual_size": len(data),
                    **line_info,
                })
        if r < rounds and interval > 0:
            time.sleep(interval)
    return findings


# ---------- Tamper-Evident Hash-Chained Audit Ledger ----------

def _ledger_path(repo: str | Path) -> Path:
    repo_p = Path(repo)
    g_ledger = repo_p / ".guardian" / "ledger.jsonl"
    ts_ledger = repo_p / ".truststack" / "ledger.jsonl"
    if not g_ledger.exists() and ts_ledger.exists():
        return ts_ledger
    return _guardian_dir(repo_p) / "ledger.jsonl"


def _hash_entry(index: int, prev_hash: str, data: dict) -> str:
    canon = json.dumps(
        {"index": index, "prev_hash": prev_hash, "data": data},
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return hashlib.sha256(canon).hexdigest()


def append_ledger_record(repo: str | Path, record: dict, signing_key: str | bytes | None = None) -> str:
    """Append a hash-chained, HMAC-signed record to `.guardian/ledger.jsonl`."""
    repo_p = Path(repo)
    ledger_file = _ledger_path(repo_p)
    key = resolve_signing_key(repo_p, signing_key, create=True)

    prev_hash = "0" * 64
    index = 0
    if ledger_file.exists():
        lines = [ln.strip() for ln in ledger_file.read_text(encoding="utf-8").splitlines() if ln.strip()]
        if lines:
            last = json.loads(lines[-1])
            prev_hash = last["record_hash"]
            index = int(last["index"]) + 1

    rec_hash = _hash_entry(index, prev_hash, record)
    sig = hmac.new(key, rec_hash.encode(), hashlib.sha256).hexdigest()
    entry = {
        "index": index,
        "prev_hash": prev_hash,
        "data": record,
        "record_hash": rec_hash,
        "head_sig": sig,
    }
    with open(ledger_file, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry, sort_keys=True) + "\n")
    return rec_hash


def verify_ledger(repo: str | Path, signing_key: str | bytes | None = None) -> tuple[bool, str, dict | None]:
    """Verify every hash link and HMAC signature in `.guardian/ledger.jsonl`."""
    repo_p = Path(repo)
    ledger_file = _ledger_path(repo_p)
    if not ledger_file.exists():
        return True, "Ledger is empty (no records yet).", None

    key = resolve_signing_key(repo_p, signing_key, create=False)
    if not key:
        return False, "Ledger signing key missing.", {"index": 0, "reason": "missing_key", "path": str(ledger_file.relative_to(repo_p))}

    lines = [ln.strip() for ln in ledger_file.read_text(encoding="utf-8").splitlines() if ln.strip()]
    expected_prev = "0" * 64
    rel_path = str(ledger_file.relative_to(repo_p))

    for expected_idx, raw in enumerate(lines):
        try:
            entry = json.loads(raw)
        except json.JSONDecodeError:
            msg = f"CHAIN BREAK at line {expected_idx + 1}: invalid JSON."
            return False, msg, {"index": expected_idx, "line": expected_idx + 1, "reason": msg, "path": rel_path}

        if entry.get("index") != expected_idx:
            msg = f"CHAIN BREAK at line {expected_idx + 1}: index mismatch (expected {expected_idx}, got {entry.get('index')})."
            return False, msg, {"index": expected_idx, "line": expected_idx + 1, "reason": msg, "path": rel_path}

        if entry.get("prev_hash") != expected_prev:
            msg = f"CHAIN BREAK at record #{expected_idx}: prev_hash mismatch (history edited!)."
            return False, msg, {"index": expected_idx, "line": expected_idx + 1, "reason": msg, "path": rel_path}

        recomputed = _hash_entry(expected_idx, expected_prev, entry.get("data", {}))
        if entry.get("record_hash") != recomputed:
            msg = f"CHAIN BREAK at record #{expected_idx}: record_hash mismatch (record tampered!)."
            return False, msg, {"index": expected_idx, "line": expected_idx + 1, "reason": msg, "path": rel_path}

        expected_sig = hmac.new(key, recomputed.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(entry.get("head_sig", ""), expected_sig):
            msg = f"CHAIN BREAK at record #{expected_idx}: invalid HMAC signature (unsigned edit!)."
            return False, msg, {"index": expected_idx, "line": expected_idx + 1, "reason": msg, "path": rel_path}

        expected_prev = recomputed

    return True, f"Ledger OK: {len(lines)} hash-chained record(s) verified.", {"records": len(lines), "head_hash": expected_prev, "path": rel_path}


def check_repo_integrity(repo: str | Path, signing_key: str | bytes | None = None, auto_init: bool = False) -> list[dict]:
    """Run Merkle-tree baseline verification and hash-chained ledger verification during a scan.
    If `auto_init=True` and no baseline exists yet, automatically creates and signs the initial
    4096-byte Merkle baseline + ledger record so future scans automatically detect any tampered lines."""
    repo_p = Path(repo)
    findings = []

    base_exists = (repo_p / ".guardian" / "baseline.json").exists() or (repo_p / ".truststack" / "baseline.json").exists()
    if not base_exists and auto_init:
        try:
            create_baseline(repo_p, signing_key=signing_key, signer="guardian-auto-init")
            base_exists = True
        except Exception:
            pass
    if base_exists:
        try:
            anomalies = run_watch(repo_p, interval=0, rounds=1, full_check_every=1, signing_key=signing_key)
        except Exception as e:
            anomalies = [{"status": "error", "file": ".guardian/baseline.json", "detail": str(e)}]
        for a in anomalies:
            f_rel = a.get("file", ".guardian/baseline.json")
            status = a.get("status", "modified")
            ln = a.get("line")
            anchor = f"IT1|{f_rel}|{status}|{a.get('chunk')}|{ln}"
            if status in ("tampered_baseline", "missing_key", "corrupt_baseline"):
                title = f"Merkle baseline signature invalid ({status}) in {f_rel}"
                detail = "The baseline manifest or its HMAC signature failed verification with the developer signing key."
            elif status == "missing":
                title = f"Monitored file '{f_rel}' was deleted without a signed baseline update"
                detail = f"File '{f_rel}' is recorded in the signed Merkle baseline but is missing from disk."
            else:
                lines_str = f" (lines {', '.join(map(str, a.get('modified_lines', [])[:6]))})" if a.get("modified_lines") else ""
                title = f"Unauthorized code modification in '{f_rel}' chunk #{a.get('chunk', 0)}{lines_str}"
                detail = (f"Merkle tree chunk #{a.get('chunk', 0)} (byte offset {a.get('offset', 0)}) of '{f_rel}'{lines_str} "
                          f"does not match the developer-signed baseline hash ({str(a.get('expected', ''))[:12]} != {str(a.get('actual', ''))[:12]}).")
            findings.append({
                "finding_id": f"IT1-{_sha256(anchor.encode())[:10]}",
                "rule_id": "IT1",
                "category": "suspicious",
                "severity": "CRITICAL",
                "title": title,
                "detail": detail,
                "component_id": None,
                "evidence_class": "verified",
                "evidence": {
                    "source": "merkle-baseline",
                    "path": f_rel,
                    "line": ln,
                    "sha256": a.get("actual") or "",
                    "excerpt": a.get("excerpt") or json.dumps(a),
                    "chunk": a.get("chunk"),
                    "offset": a.get("offset"),
                    "modified_lines": a.get("modified_lines", []),
                    "status": status,
                },
                "recommendation": "Inspect the unauthorized code modification immediately. If legitimate, re-sign with `guardian baseline <repo> --key <secret>`.",
            })

    ledger_exists = (repo_p / ".guardian" / "ledger.jsonl").exists() or (repo_p / ".truststack" / "ledger.jsonl").exists()
    if ledger_exists:
        ok, msg, info = verify_ledger(repo_p, signing_key=signing_key)
        if not ok:
            f_rel = (info or {}).get("path", ".guardian/ledger.jsonl")
            ln = (info or {}).get("line", 1)
            anchor = f"IT2|{f_rel}|{ln}|{msg}"
            findings.append({
                "finding_id": f"IT2-{_sha256(anchor.encode())[:10]}",
                "rule_id": "IT2",
                "category": "suspicious",
                "severity": "CRITICAL",
                "title": f"Tamper-evident audit ledger broken: {msg}",
                "detail": f"Cryptographic hash chain / HMAC verification failed on {f_rel} at record #{(info or {}).get('index', 0)}.",
                "component_id": None,
                "evidence_class": "verified",
                "evidence": {
                    "source": "audit-ledger",
                    "path": f_rel,
                    "line": ln,
                    "sha256": _sha256(msg.encode()),
                    "excerpt": msg,
                },
                "recommendation": "Audit git history and restore `.guardian/ledger.jsonl` from trusted backup.",
            })

    return findings
