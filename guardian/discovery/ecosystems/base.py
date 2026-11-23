"""Common project-graph model and assembly for every ecosystem parser.

A parser returns a ProjectGraph: packages keyed by purl, parent->child edges, the direct dependencies
of the project with their scope, and coverage gaps. `assemble` turns it into Components with
direct/transitive, prod/dev and a shortest dependency path (prod paths preferred for prod packages).
"""
from collections import deque
from dataclasses import dataclass, field

from ...models import Component, CoverageGap
from ..purl import purl


@dataclass
class ProjectGraph:
    manifest: str                     # path of the manifest/lockfile, relative to the repo
    ecosystem: str                    # npm | pypi | golang | cargo | gem | composer | maven
    name: str
    version: str = ""
    packages: dict = field(default_factory=dict)   # purl -> dict(name, version, source_url, integrity, license, ...)
    edges: list = field(default_factory=list)      # (parent purl, child purl)
    direct: dict = field(default_factory=dict)     # child purl -> "prod" | "dev"
    gaps: list = field(default_factory=list)
    hints: dict = field(default_factory=dict)      # purl -> {"scope": ..., "relationship": ...} from the lockfile

    @property
    def root_id(self):
        return f"project:{self.manifest}"

    def add(self, name, version, **attrs):
        cid = purl(self.ecosystem, name, version or None)
        p = self.packages.setdefault(cid, {"name": name, "version": version or "", "found_in": []})
        for k, v in attrs.items():
            if v not in (None, "", False) and not p.get(k):
                p[k] = v
        p["found_in"].append(self.manifest)
        return cid

    def gap(self, kind, detail, path=None):
        self.gaps.append(CoverageGap(path or self.manifest, kind, detail))


def _bfs(root, adj, start_filter=None):
    prev, dist, q = {root: None}, {root: 0}, deque([root])
    while q:
        n = q.popleft()
        for m in sorted(adj.get(n, ())):
            if m in prev or (n == root and start_filter and not start_filter(m)):
                continue
            prev[m], dist[m] = n, dist[n] + 1
            q.append(m)
    return prev, dist


def assemble(pg: ProjectGraph):
    root = pg.root_id
    adj = {root: set(pg.direct)}
    for a, b in pg.edges:
        if a in pg.packages or a == root:
            adj.setdefault(a, set()).add(b)
    prev, dist = _bfs(root, adj)
    pprev, _ = _bfs(root, adj, start_filter=lambda m: pg.direct.get(m) == "prod")
    comps = {}
    for cid, p in pg.packages.items():
        hint = pg.hints.get(cid, {})
        scope = hint.get("scope") or ("prod" if cid in pprev else "dev")
        c = Component(component_id=cid, name=p["name"], version=p["version"], ecosystem=pg.ecosystem,
                      scope=scope, source_url=p.get("source_url"), integrity=p.get("integrity"),
                      license=p.get("license"), has_install_script=bool(p.get("has_install_script")),
                      resolution=p.get("resolution") or ("locked" if p["version"] else "declared-only"),
                      found_in=sorted(set(p["found_in"])), projects=[pg.manifest])
        chain = pprev if (scope == "prod" and cid in pprev) else prev
        if cid in chain:
            path, n = [], cid
            while n is not None:
                path.append(n); n = chain[n]
            c.path = path[::-1]
            c.relationship = "direct" if dist.get(cid) == 1 else "transitive"
        else:
            c.path = [root, cid]
            c.relationship = hint.get("relationship", "transitive")
        if hint.get("relationship"):
            c.relationship = hint["relationship"]
        comps[cid] = c
    for parent, kids in adj.items():
        for k in kids:
            if k in comps and parent not in comps[k].parents:
                comps[k].parents.append(parent)
    for c in comps.values():
        c.parents.sort()
    return {"root": root, "name": pg.name, "version": pg.version, "ecosystem": pg.ecosystem, "manifest": pg.manifest,
            "components": comps, "adjacency": {k: sorted(v) for k, v in adj.items()}, "gaps": pg.gaps}
