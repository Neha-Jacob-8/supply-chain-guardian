"""Part 3: collapse instances to unique name@version nodes, compute direct/transitive + shortest paths."""
from collections import deque
from .lockfile import pkg_name, make_purl, resolve
from .models import Component, CoverageGap


def build_components(packages: dict, edges: dict, root_name: str, root_version: str):
    root_id = make_purl(root_name, root_version)
    key_to_id, comps, gaps, dev_flags = {"": root_id}, {}, [], {}

    for key, p in packages.items():
        if key == "":
            continue
        name, version = pkg_name(key), p.get("version")
        if not version:   # link/workspace entries carry no version
            gaps.append(CoverageGap(key, "unsupported_format", "entry has no version (link/workspace)"))
            continue
        cid = make_purl(name, version)
        key_to_id[key] = cid
        c = comps.setdefault(cid, Component(component_id=cid, name=name, version=version))
        c.found_in.append(key)
        c.source_url = c.source_url or p.get("resolved")
        c.integrity = c.integrity or p.get("integrity")
        c.license = c.license or (p.get("license") if isinstance(p.get("license"), str) else None)
        c.has_install_script = c.has_install_script or bool(p.get("hasInstallScript"))
        dev_flags.setdefault(cid, []).append(bool(p.get("dev")))

    # prod if ANY installed copy is not dev-only (npm's own "dev" flag)
    for cid, flags in dev_flags.items():
        comps[cid].scope = "dev" if all(flags) else "prod"
    prod_direct = {key_to_id[ck] for ck in
                   (resolve("", n, packages) for n in packages[""].get("dependencies", {})) if ck}

    # purl-level adjacency
    adj = {root_id: set()}
    for parent_key, children in edges.items():
        pid = key_to_id.get(parent_key)
        if pid is None:
            continue
        for ck in children:
            cid = key_to_id.get(ck)
            if cid:
                adj.setdefault(pid, set()).add(cid)

    def bfs(allowed):
        prev, dist, q = {root_id: None}, {root_id: 0}, deque([root_id])
        while q:
            n = q.popleft()
            for m in sorted(adj.get(n, ())):
                if m not in prev and allowed(n, m):
                    prev[m], dist[m] = n, dist[n] + 1
                    q.append(m)
        return prev, dist

    prev, dist = bfs(lambda n, m: True)
    # prod components get a path through prod dependencies only, so path and scope agree
    pprev, _ = bfs(lambda n, m: (m in prod_direct) if n == root_id else comps[m].scope == "prod")

    for cid, c in comps.items():
        if cid in prev:
            chain = pprev if (c.scope == "prod" and cid in pprev) else prev
            path, n = [], cid
            while n is not None:
                path.append(n); n = chain[n]
            c.path = path[::-1]
            c.relationship = "direct" if dist[cid] == 1 else "transitive"
        else:
            gaps.append(CoverageGap(cid, "unreachable", "in lockfile but no path from root"))
    for parent, kids in adj.items():
        for k in kids:
            if k in comps and parent not in comps[k].parents:
                comps[k].parents.append(parent)
    for c in comps.values():
        c.parents.sort()
    return root_id, comps, {k: sorted(v) for k, v in adj.items()}, gaps
