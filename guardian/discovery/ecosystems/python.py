"""Python: poetry.lock, uv.lock, Pipfile.lock (full or flat graphs), requirements*.txt (pins + pip-compile `# via`)."""
import json
import re
import tomllib

from ..purl import normalize_name
from .base import ProjectGraph, assemble

DEV_HINT = re.compile(r"(dev|test|lint|doc|ci|type)", re.I)


def _n(name):
    return normalize_name("pypi", name)


def _pyproject_direct(path):
    """{normalized name: scope} from pyproject.toml (PEP 621, Poetry, uv dependency groups)."""
    out = {}
    try:
        d = tomllib.loads(path.read_text())
    except (OSError, tomllib.TOMLDecodeError):
        return out
    req = lambda s: _n(re.split(r"[\s<>=!~;\[(]", s.strip(), 1)[0])
    for s in d.get("project", {}).get("dependencies", []):
        out[req(s)] = "prod"
    for grp in d.get("project", {}).get("optional-dependencies", {}).values():
        for s in grp:
            out.setdefault(req(s), "prod")
    for grp in d.get("dependency-groups", {}).values():
        for s in grp:
            if isinstance(s, str):
                out.setdefault(req(s), "dev")
    poetry = d.get("tool", {}).get("poetry", {})
    for n in poetry.get("dependencies", {}):
        if n.lower() != "python":
            out[_n(n)] = "prod"
    for n in poetry.get("dev-dependencies", {}):
        out.setdefault(_n(n), "dev")
    for g in poetry.get("group", {}).values():
        for n in g.get("dependencies", {}):
            out.setdefault(_n(n), "dev")
    return out


def _toml_lock(repo, rel, kind):
    path = repo / rel
    data = tomllib.loads(path.read_text())
    pg = ProjectGraph(rel, "pypi", path.parent.name)
    ids, deps = {}, {}
    for p in data.get("package", []):
        src = p.get("source", {})
        if kind == "uv" and isinstance(src, dict) and ("editable" in src or "virtual" in src):
            pg.name, pg.version = p["name"], p.get("version", "")
            for d in p.get("dependencies", []):
                deps.setdefault("__root__", []).append((d["name"], "prod"))
            for grp in (p.get("dev-dependencies") or {}).values():
                for d in grp:
                    deps.setdefault("__root__", []).append((d["name"], "dev"))
            continue
        url = src.get("url") or src.get("registry") or src.get("git") if isinstance(src, dict) else None
        cid = pg.add(p["name"], p.get("version", ""), source_url=url,
                     integrity=(p.get("sdist") or {}).get("hash") if kind == "uv" else None)
        ids[_n(p["name"])] = cid
        dl = p.get("dependencies", {})
        names = [d["name"] for d in dl] if isinstance(dl, list) else list(dl)
        deps[cid] = names
        if kind == "poetry" and p.get("category") == "dev":
            pg.hints[cid] = {"scope": "dev"}
    for parent, names in deps.items():
        if parent == "__root__":
            continue
        for n in names:
            if _n(n) in ids:
                pg.edges.append((parent, ids[_n(n)]))
    direct = {}
    for n, scope in deps.get("__root__", []):
        direct[_n(n)] = scope
    if not direct and (path.parent / "pyproject.toml").exists():
        direct = _pyproject_direct(path.parent / "pyproject.toml")
    for n, scope in direct.items():
        if n in ids:
            pg.direct[ids[n]] = scope
    if not pg.direct:
        pg.gap("unresolved_dependency", "could not tell which locked packages are direct (no pyproject.toml found); "
                                        "all are treated as reachable from the project")
        pg.direct = {cid: "prod" for cid in ids.values()}
    return assemble(pg)


def parse_poetry_lock(repo, rel):
    return _toml_lock(repo, rel, "poetry")


def parse_uv_lock(repo, rel):
    return _toml_lock(repo, rel, "uv")


def parse_pipfile_lock(repo, rel):
    data = json.loads((repo / rel).read_text())
    pg = ProjectGraph(rel, "pypi", (repo / rel).parent.name)
    for section, scope in (("default", "prod"), ("develop", "dev")):
        for name, meta in (data.get(section) or {}).items():
            ver = (meta.get("version") or "").lstrip("=")
            cid = pg.add(name, ver, source_url=meta.get("git"), integrity=(meta.get("hashes") or [None])[0])
            pg.direct.setdefault(cid, scope)
    pg.gap("unresolved_dependency", "Pipfile.lock is flat: parent/child edges between packages are not recorded",
           rel) if pg.packages else None
    return assemble(pg)


REQ = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(\[[^\]]*\])?\s*(==|===|~=|>=|<=|!=|>|<)?\s*([^;\s#,]*)")


def parse_requirements(repo, rel):
    path = repo / rel
    scope = "dev" if DEV_HINT.search(path.name) or DEV_HINT.search(path.parent.name) else "prod"
    pg = ProjectGraph(rel, "pypi", path.parent.name if path.parent != repo else repo.name)
    via, last, unpinned = {}, None, 0
    lines = path.read_text(errors="replace").splitlines()
    for i, raw in enumerate(lines):
        line = raw.strip()
        if line.startswith("#"):
            v = line.lstrip("#").strip()
            if last and v.startswith("via"):
                rest = v[3:].strip()
                if rest:
                    via.setdefault(last, []).append(rest)
                else:
                    via.setdefault(last, [])
            elif last and last in via and v and not v.startswith("via"):
                via[last].append(v)
            continue
        if not line or line.startswith(("-r", "-c", "--", "-i", "-f")):
            continue
        if line.startswith(("-e ", "git+", "http")) or "@ git+" in line or " @ " in line:
            name = line.split("#egg=")[-1] if "#egg=" in line else line.split("@")[0].replace("-e", "").strip()
            cid = pg.add(name or line, "", resolution="declared-only", source_url=line.split("@", 1)[-1].strip(), line=i + 1)
            pg.direct[cid] = scope
            last = cid
            continue
        m = REQ.match(line)
        if not m:
            continue
        name, op, ver = m.group(1), m.group(3), m.group(4)
        pinned = op in ("==", "===") and ver and "*" not in ver
        unpinned += 0 if pinned else 1
        cid = pg.add(name, ver if pinned else "", resolution="locked" if pinned else "declared-only",
                     spec=(op or "") + (ver or ""), line=i + 1)
        last = cid
    names = {_n(p["name"]): cid for cid, p in pg.packages.items()}
    for cid in pg.packages:
        parents = via.get(cid)
        real = [names[_n(p)] for p in (parents or []) if _n(p) in names]
        if real:
            for p in real:
                pg.edges.append((p, cid))
        if parents is None or not real or any(p.startswith("-r") for p in parents or []):
            pg.direct.setdefault(cid, scope)
    if not via:
        pg.gap("unresolved_dependency", "requirements file lists packages without parents (not pip-compile output): "
                                        "transitive dependencies are unknown", rel)
    if unpinned:
        pg.gap("unresolved_dependency", f"{unpinned} requirement(s) are not pinned to an exact version", rel)
    return assemble(pg)


def parse_pyproject(repo, rel):
    """pyproject.toml without a lockfile: declared dependencies only (PEP 621, Poetry, dependency groups)."""
    path = repo / rel
    try:
        d = tomllib.loads(path.read_text())
    except (OSError, tomllib.TOMLDecodeError):
        return None
    pg = ProjectGraph(rel, "pypi", d.get("project", {}).get("name") or d.get("tool", {}).get("poetry", {}).get("name")
                      or path.parent.name, d.get("project", {}).get("version", ""))
    for name, scope in _pyproject_direct(path).items():
        pg.direct[pg.add(name, "", resolution="declared-only")] = scope
    if pg.packages:
        pg.gap("no_lockfile", f"{len(pg.packages)} dependencies declared in pyproject.toml without a lockfile: versions "
                              "are ranges and transitive dependencies are unknown")
    return assemble(pg)
