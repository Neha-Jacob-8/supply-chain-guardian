"""Go (go.mod), Rust (Cargo.lock), Ruby (Gemfile.lock), PHP (composer.lock/json), Java (pom.xml),
ROS (package.xml), vcstool (.repos) and git submodules."""
import json
import re
import tomllib
import xml.etree.ElementTree as ET

from .base import ProjectGraph, assemble


def parse_go_mod(repo, rel):
    text = (repo / rel).read_text(errors="replace")
    mod = re.search(r"^module\s+(\S+)", text, re.M)
    pg = ProjectGraph(rel, "golang", mod.group(1) if mod else (repo / rel).parent.name)
    in_block, indirect = False, 0
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("require ("):
            in_block = True; continue
        if in_block and s == ")":
            in_block = False; continue
        m = re.match(r"(?:require\s+)?(\S+)\s+(v\S+)(\s*//\s*indirect)?", s) if (in_block or s.startswith("require ")) else None
        if m and not s.startswith("//"):
            cid = pg.add(m.group(1), m.group(2))
            if m.group(3):
                indirect += 1
                pg.hints[cid] = {"relationship": "transitive", "scope": "prod"}
            else:
                pg.direct[cid] = "prod"
        r = re.match(r"replace\s+(\S+).*=>\s*(\S+)(?:\s+(\S+))?", s)
        if r:
            pg.gap("unresolved_dependency", f"replace directive: {r.group(1)} => {r.group(2)} {r.group(3) or ''}".strip())
    if indirect:
        pg.gap("unresolved_dependency", f"{indirect} indirect Go modules have no recorded parent (go.mod lists them "
                                        "flat; `go mod graph` would be needed)")
    return assemble(pg)


def parse_cargo_lock(repo, rel):
    data = tomllib.loads((repo / rel).read_text())
    pg = ProjectGraph(rel, "cargo", (repo / rel).parent.name)
    pkgs = data.get("package", [])
    by_name = {}
    for p in pkgs:
        by_name.setdefault(p["name"], []).append(p)
    members = [p for p in pkgs if "source" not in p]       # workspace members have no source
    ids = {}
    for p in pkgs:
        if "source" in p:
            ids[(p["name"], p["version"])] = pg.add(p["name"], p["version"], source_url=p["source"],
                                                    integrity=p.get("checksum"))

    def resolve(spec):
        parts = spec.split()
        name = parts[0]
        cands = by_name.get(name, [])
        if len(parts) > 1:
            cands = [c for c in cands if c["version"] == parts[1]]
        c = cands[0] if cands else None
        return ids.get((c["name"], c["version"])) if c and "source" in c else None

    dev_names = set()
    toml_path = (repo / rel).parent / "Cargo.toml"
    if toml_path.exists():
        try:
            ct = tomllib.loads(toml_path.read_text())
            dev_names = set(ct.get("dev-dependencies", {})) | set(ct.get("build-dependencies", {}))
            pg.name = ct.get("package", {}).get("name", pg.name)
        except tomllib.TOMLDecodeError:
            pass
    for p in pkgs:
        parent = ids.get((p["name"], p["version"]))
        for spec in p.get("dependencies", []):
            child = resolve(spec)
            if not child:
                continue
            if parent:
                pg.edges.append((parent, child))
            elif p in members:
                pg.direct.setdefault(child, "dev" if spec.split()[0] in dev_names else "prod")
    return assemble(pg)


def parse_gemfile_lock(repo, rel):
    text = (repo / rel).read_text(errors="replace")
    pg = ProjectGraph(rel, "gem", (repo / rel).parent.name)
    section, cur, ids, deps, direct = None, None, {}, {}, []
    for line in text.splitlines():
        if line and not line.startswith(" "):
            section = line.strip(); continue
        if section == "GEM" or section in ("GIT", "PATH"):
            m4 = re.match(r"^    (\S+) \(([^)]+)\)$", line)
            m6 = re.match(r"^      (\S+)", line)
            if m4:
                name, ver = m4.group(1), m4.group(2).split("-")[0]
                cur = pg.add(name, ver, source_url="https://rubygems.org" if section == "GEM" else section.lower())
                ids[name] = cur
            elif m6 and cur:
                deps.setdefault(cur, []).append(m6.group(1))
        elif section == "DEPENDENCIES":
            m = re.match(r"^  (\S+?)!?(\s|$)", line)
            if m:
                direct.append(m.group(1))
    for parent, names in deps.items():
        for n in names:
            if n in ids:
                pg.edges.append((parent, ids[n]))
    for n in direct:
        if n in ids:
            pg.direct[ids[n]] = "prod"
    return assemble(pg)


def parse_composer(repo, rel):
    path = repo / rel
    pg = ProjectGraph(rel, "composer", path.parent.name)
    cj_path = path.parent / "composer.json"
    cj = json.loads(cj_path.read_text()) if cj_path.exists() else {}
    pg.name = cj.get("name", pg.name)
    platform = lambda n: n == "php" or n.startswith(("ext-", "lib-")) or "/" not in n
    if path.name == "composer.lock":
        data = json.loads(path.read_text())
        ids, reqs = {}, {}
        for section, scope in (("packages", "prod"), ("packages-dev", "dev")):
            for p in data.get(section) or []:
                cid = pg.add(p["name"], str(p.get("version", "")).lstrip("v"),
                             source_url=(p.get("dist") or {}).get("url"), license=", ".join(p.get("license") or []) or None)
                ids[p["name"]] = cid
                reqs[cid] = [n for n in (p.get("require") or {}) if not platform(n)]
                if scope == "dev":
                    pg.hints[cid] = {"scope": "dev"}
        for parent, names in reqs.items():
            for n in names:
                if n in ids:
                    pg.edges.append((parent, ids[n]))
        for section, scope in (("require", "prod"), ("require-dev", "dev")):
            for n in cj.get(section) or {}:
                if n in ids:
                    pg.direct[ids[n]] = scope
    else:
        for section, scope in (("require", "prod"), ("require-dev", "dev")):
            for n, spec in (cj.get(section) or {}).items():
                if not platform(n):
                    pg.direct[pg.add(n, "", resolution="declared-only", spec=spec)] = scope
        pg.gap("no_lockfile", "composer.json without composer.lock: versions are constraints, transitive deps unknown")
    return assemble(pg)


def _apply_mvn_tree_text(pg, text):
    """Parse `mvn dependency:tree` text output (3 chars indent per level) into direct and transitive edges."""
    stack = []
    added = 0
    for ln in text.splitlines():
        r = re.match(r"^(?:\[INFO\] )?([|+\\ -]*)([\w.\-]+(?::[\w.\-]+){3,5})\s*$", ln)
        if not r or not r.group(1):
            continue
        p = r.group(2).split(":")
        ver = p[-2] if len(p) in (5, 6) else p[-1]
        scope_str = p[-1] if len(p) in (5, 6) else "compile"
        scope = "dev" if scope_str in ("test", "provided") else "prod"
        cid = pg.add(f"{p[0]}:{p[1]}", ver, resolution="locked")
        added += 1
        lvl = len(r.group(1)) // 3
        stack = stack[:max(0, lvl - 1)]
        if lvl == 1:
            pg.direct[cid] = scope
        elif stack:
            pg.edges.append((stack[-1], cid))
            if scope == "dev":
                pg.hints.setdefault(cid, {})["scope"] = "dev"
        stack.append(cid)
    return added


def parse_mvn_tree(repo, rel):
    path = repo / rel
    text = path.read_text(errors="replace")
    root_m = re.search(r"^(?:\[INFO\] )?([\w.\-]+:[\w.\-]+):(?:jar|war|pom|ear|bundle):([\w.\-]+)\s*$", text, re.M)
    name = root_m.group(1) if root_m else path.parent.name
    ver = root_m.group(2) if root_m else ""
    pg = ProjectGraph(rel, "maven", name, ver)
    _apply_mvn_tree_text(pg, text)
    return assemble(pg)


def parse_pom(repo, rel):
    path = repo / rel
    try:
        root = ET.parse(path).getroot()
    except ET.ParseError as e:
        pg = ProjectGraph(rel, "maven", path.parent.name); pg.gap("scan_error", f"pom.xml parse error: {e}")
        return assemble(pg)
    ns = {"m": root.tag.split("}")[0].strip("{")} if root.tag.startswith("{") else {"m": ""}
    f = (lambda el, tag: el.find(f"m:{tag}", ns)) if ns["m"] else (lambda el, tag: el.find(tag))
    txt = lambda el, tag: (f(el, tag).text or "").strip() if f(el, tag) is not None else ""
    props = {}
    pe = f(root, "properties")
    if pe is not None:
        for child in pe:
            props[child.tag.split("}")[-1]] = (child.text or "").strip()
    props["project.version"] = txt(root, "version")
    sub = lambda v: re.sub(r"\$\{([^}]+)\}", lambda m: props.get(m.group(1), m.group(0)), v)
    pg = ProjectGraph(rel, "maven", f"{txt(root, 'groupId')}:{txt(root, 'artifactId')}", props["project.version"])
    deps_el = f(root, "dependencies")
    unresolved = 0
    for d in (list(deps_el) if deps_el is not None else []):
        g, a, v = sub(txt(d, "groupId")), sub(txt(d, "artifactId")), sub(txt(d, "version"))
        ok = v and "${" not in v
        unresolved += 0 if ok else 1
        cid = pg.add(f"{g}:{a}", v if ok else "", resolution="locked" if ok else "declared-only")
        pg.direct[cid] = "dev" if txt(d, "scope") in ("test", "provided") else "prod"
    tree_used = False
    for cand_name in ("mvn-tree.txt", "dependency-tree.txt", "mvn_dependency_tree.txt", ".mvn-tree"):
        cand = path.parent / cand_name
        if cand.is_file():
            if _apply_mvn_tree_text(pg, cand.read_text(errors="replace")) > 0:
                tree_used = True
                break
    if pg.packages and not tree_used:
        pg.gap("unresolved_dependency", "Maven transitive dependencies need `mvn dependency:tree`; only declared "
                                        "dependencies are listed")
    if unresolved and not tree_used:
        pg.gap("unresolved_dependency", f"{unresolved} dependency version(s) come from a parent POM or BOM and are unknown")
    return assemble(pg)


def parse_ros_package(repo, rel):
    path = repo / rel
    try:
        root = ET.parse(path).getroot()
    except ET.ParseError:
        return None
    if root.tag != "package":
        return None
    pg = ProjectGraph(rel, "ros", (root.findtext("name") or path.parent.name).strip(), (root.findtext("version") or "").strip())
    for tag, scope in (("depend", "prod"), ("exec_depend", "prod"), ("build_depend", "dev"),
                       ("buildtool_depend", "dev"), ("test_depend", "dev"), ("build_export_depend", "dev")):
        for el in root.findall(tag):
            if el.text:
                cid = pg.add(el.text.strip(), "", resolution="declared-only")
                pg.direct[cid] = "prod" if scope == "prod" or pg.direct.get(cid) == "prod" else "dev"
    if pg.packages:
        pg.gap("unresolved_dependency", f"{len(pg.packages)} ROS dependencies are rosdep keys without versions; they "
                                        "resolve to apt packages at build time and cannot be matched to advisories statically")
    return assemble(pg)


def parse_repos_file(repo, rel):
    text = (repo / rel).read_text(errors="replace")
    pg = ProjectGraph(rel, "git", (repo / rel).stem)
    for m in re.finditer(r"url:\s*(\S+)\s*\n\s*version:\s*(\S+)", text):
        url, ver = m.group(1), m.group(2)
        cid = pg.add(url.removesuffix(".git").split("github.com/")[-1], ver, source_url=url,
                     resolution="locked" if re.fullmatch(r"[0-9a-f]{40}", ver) else "declared-only")
        pg.direct[cid] = "prod"
    return assemble(pg)


def parse_gitmodules(repo, rel):
    text = (repo / rel).read_text(errors="replace")
    pg = ProjectGraph(rel, "git", "submodules")
    for m in re.finditer(r"path\s*=\s*(\S+)\s*\n\s*url\s*=\s*(\S+)", text):
        cid = pg.add(m.group(2).removesuffix(".git").split("github.com/")[-1], "", source_url=m.group(2),
                     resolution="declared-only")
        pg.direct[cid] = "prod"
    if pg.packages:
        pg.gap("unresolved_dependency", "submodule commits are not read from git objects; versions unknown")
    return assemble(pg)
