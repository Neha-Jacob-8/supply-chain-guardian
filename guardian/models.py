from dataclasses import dataclass, field


@dataclass
class Component:
    component_id: str            # purl, e.g. pkg:npm/lodash@4.17.11
    name: str
    version: str
    ecosystem: str = "npm"
    relationship: str = "transitive"   # direct | transitive
    scope: str = "prod"                # prod | dev
    parents: list = field(default_factory=list)   # component_ids that depend on this
    path: list = field(default_factory=list)      # shortest root -> ... -> this (component_ids)
    source_url: str | None = None
    integrity: str | None = None
    license: str | None = None
    has_install_script: bool = False
    resolution: str = "locked"         # locked | unresolved
    found_in: list = field(default_factory=list)  # lockfile keys / manifests where it appears
    projects: list = field(default_factory=list)  # manifests (projects) that depend on it
    # filled in later by the vulnerability stage
    advisory_ids: list = field(default_factory=list)
    cvss: float | None = None
    severity: str | None = None
    affected_range: str | None = None
    fixed_version: str | None = None
    risk_status: str = "not-scanned"


@dataclass
class CoverageGap:
    path: str
    kind: str      # unresolved_dependency | unsupported_format | unreachable
    detail: str
