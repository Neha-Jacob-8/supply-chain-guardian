"""Package URLs (purl) and OSV ecosystem names for every supported ecosystem."""
import re
from urllib.parse import quote

OSV_ECOSYSTEM = {"npm": "npm", "pypi": "PyPI", "golang": "Go", "cargo": "crates.io", "gem": "RubyGems",
                 "composer": "Packagist", "maven": "Maven"}


def normalize_name(eco, name):
    if eco == "pypi":
        return re.sub(r"[-_.]+", "-", name).lower()
    return name


def purl(eco, name, version=None):
    name = normalize_name(eco, name)
    if eco == "npm" and name.startswith("@"):
        path = "%40" + name[1:]
    elif eco == "maven" and ":" in name:
        path = "/".join(quote(p, safe="") for p in name.split(":", 1))
    elif eco in ("golang", "composer"):
        path = "/".join(quote(p, safe="") for p in name.split("/"))
    else:
        path = quote(name, safe="")
    return f"pkg:{eco}/{path}" + (f"@{quote(version, safe='+')}" if version else "")


def short(cid):
    """'pkg:npm/%40s/x@1.0' -> '@s/x@1.0' (for display)."""
    if not cid or not cid.startswith("pkg:"):
        return (cid or "").split(":", 1)[-1]
    body = cid.split("/", 1)[1] if "/" in cid else cid
    return body.replace("%40", "@").replace("%2F", "/")
