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


def build_sbom(root_id, root_name, root_version, comps, adj):
    components = []
    for c in sorted(comps.values(), key=lambda c: c.component_id):
        item = {"type": "library", "bom-ref": c.component_id, "name": c.name,
                "version": c.version, "purl": c.component_id,
                "scope": "required" if c.scope == "prod" else "optional"}
        if c.license:
            item["licenses"] = [{"license": {"name": c.license}}]
        if h := _hashes(c.integrity):
            item["hashes"] = h
        if c.source_url:
            item["externalReferences"] = [{"type": "distribution", "url": c.source_url}]
        components.append(item)
    return {
        "bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "tools": {"components": [{"type": "application", "name": "guardian-discovery"}]},
            "component": {"type": "application", "bom-ref": root_id, "name": root_name,
                          "version": root_version, "purl": root_id},
        },
        "components": components,
        "dependencies": [{"ref": ref, "dependsOn": deps} for ref, deps in sorted(adj.items())],
    }
