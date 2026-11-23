"""Part 4: CycloneDX 1.5 JSON SBOM."""
import base64, uuid
from datetime import datetime, timezone

ALG = {"sha512": "SHA-512", "sha384": "SHA-384", "sha256": "SHA-256", "sha1": "SHA-1"}


def _hashes(integrity):
    out = []
    for part in (integrity or "").split():
        alg, _, b64 = part.partition("-")
        if alg in ALG:
            try:
                out.append({"alg": ALG[alg], "content": base64.b64decode(b64).hex()})
            except ValueError:
                pass
    return out


def build_sbom(root_id, repo_name, projects, comps, adj):
    components = []
    for pr in projects:
        if pr["root"] != root_id:
            components.append({"type": "application", "bom-ref": pr["root"], "name": pr["name"],
                               "version": pr.get("version") or "", "description": f"{pr['ecosystem']} project {pr['manifest']}"})
    for c in sorted(comps.values(), key=lambda c: c.component_id):
        item = {"type": "library", "bom-ref": c.component_id, "name": c.name, "purl": c.component_id,
                "scope": "required" if c.scope == "prod" else "optional",
                "properties": [{"name": "guardian:ecosystem", "value": c.ecosystem},
                               {"name": "guardian:resolution", "value": c.resolution}]}
        if c.version:
            item["version"] = c.version
        if c.license:
            item["licenses"] = [{"license": {"name": c.license}}]
        if h := _hashes(c.integrity):
            item["hashes"] = h
        if c.source_url:
            item["externalReferences"] = [{"type": "distribution", "url": c.source_url}]
        components.append(item)
    main = next((p for p in projects if p["root"] == root_id), None)
    return {
        "bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "tools": {"components": [{"type": "application", "name": "guardian-discovery"}]},
            "component": {"type": "application", "bom-ref": root_id, "name": main["name"] if main else repo_name,
                          "version": (main or {}).get("version") or ""},
        },
        "components": components,
        "dependencies": [{"ref": ref, "dependsOn": deps} for ref, deps in sorted(adj.items())],
    }
