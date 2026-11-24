"""Find every supported manifest/lockfile in a repository and parse it with its ecosystem parser."""
import subprocess
from pathlib import Path

from ...models import CoverageGap
from . import npm, python, others

SKIP_DIRS = {"node_modules", ".git", "vendor", "dist", "build", "target", "__pycache__", ".venv", "venv",
             "site-packages", "fixtures", "__fixtures__", "testdata", "test-fixtures", "test_fixtures", ".tox",
             "bower_components", "stubs"}            # compared case-insensitively
MAX_PROJECTS = 60

# (filename predicate, parser, files in the same directory that take precedence)
PARSERS = [
    (lambda n: n == "package-lock.json", npm.parse_package_lock, ()),
    (lambda n: n == "npm-shrinkwrap.json", npm.parse_package_lock, ("package-lock.json",)),
    (lambda n: n == "yarn.lock", npm.parse_yarn_lock, ("package-lock.json",)),
    (lambda n: n == "package.json", npm.parse_package_json, ("package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml")),
    (lambda n: n == "poetry.lock", python.parse_poetry_lock, ()),
    (lambda n: n == "uv.lock", python.parse_uv_lock, ("poetry.lock",)),
    (lambda n: n == "Pipfile.lock", python.parse_pipfile_lock, ("poetry.lock", "uv.lock")),
    (lambda n: n.startswith("requirements") and n.endswith(".txt"), python.parse_requirements, ()),
    (lambda n: n == "pyproject.toml", python.parse_pyproject, ("poetry.lock", "uv.lock", "Pipfile.lock", "pdm.lock")),
    (lambda n: n == "go.mod", others.parse_go_mod, ()),
    (lambda n: n == "Cargo.lock", others.parse_cargo_lock, ()),
    (lambda n: n == "Gemfile.lock", others.parse_gemfile_lock, ()),
    (lambda n: n == "composer.lock", others.parse_composer, ()),
    (lambda n: n == "composer.json", others.parse_composer, ("composer.lock",)),
    (lambda n: n in ("mvn-tree.txt", "dependency-tree.txt", "mvn_dependency_tree.txt", ".mvn-tree"), others.parse_mvn_tree, ("pom.xml",)),
    (lambda n: n == "pom.xml", others.parse_pom, ()),
    (lambda n: n == "package.xml", others.parse_ros_package, ()),
    (lambda n: n.endswith(".repos"), others.parse_repos_file, ()),
    (lambda n: n == ".gitmodules", others.parse_gitmodules, ()),
]
# filename -> (coverage-gap label, files in the same directory that make it irrelevant)
KNOWN_UNSUPPORTED = {
    "build.gradle": ("Gradle build: dependencies need `gradle dependencies`", ()),
    "build.gradle.kts": ("Gradle build: dependencies need `gradle dependencies`", ()),
    "Cargo.toml": ("Cargo.toml without Cargo.lock: versions unresolved", ("Cargo.lock",)),
    "Gemfile": ("Gemfile without Gemfile.lock: versions unresolved", ("Gemfile.lock",)),
    "Pipfile": ("Pipfile without Pipfile.lock: versions unresolved", ("Pipfile.lock",)),
    "pdm.lock": ("PDM lockfile is not parsed", ()),
    "setup.py": ("setup.py dependencies are dynamic and not parsed", ("pyproject.toml", "requirements.txt", "poetry.lock", "uv.lock")),
    "conanfile.txt": ("Conan (C/C++) is not parsed", ()), "conanfile.py": ("Conan (C/C++) is not parsed", ()),
    "vcpkg.json": ("vcpkg (C/C++) is not parsed", ()),
    "CMakeLists.txt": ("CMake: C/C++ dependencies are not declared in a machine-readable lockfile", ("package.xml", "conanfile.txt", "vcpkg.json")),
    "packages.config": ("NuGet is not parsed", ()), "Package.resolved": ("SwiftPM is not parsed", ()), "mix.lock": ("Elixir mix.lock is not parsed", ()),
}


def _repo_files(repo):
    """Files that belong to the repository: tracked + untracked-but-not-ignored when it is a git checkout
    (so build output, virtualenvs and other .gitignore'd folders are never mistaken for projects)."""
    if (repo / ".git").exists():
        r = subprocess.run(["git", "-C", str(repo), "-c", "core.hooksPath=/dev/null", "ls-files", "-z",
                            "--cached", "--others", "--exclude-standard"], capture_output=True, text=True)
        if r.returncode == 0:
            return sorted(Path(f) for f in r.stdout.split("\0") if f and (repo / f).is_file())
    return sorted(p.relative_to(repo) for p in repo.rglob("*") if p.is_file())


def discover_projects(repo):
    repo = Path(repo)
    files = [rel for rel in _repo_files(repo) if not SKIP_DIRS & {d.lower() for d in rel.parts[:-1]}]
    names_by_dir = {}
    for rel in files:
        names_by_dir.setdefault(rel.parent, set()).add(rel.name)
    results, gaps = [], []
    # pnpm workspaces: one lockfile covers many package.json files; parse it first and skip what it covers
    covered = set()
    for rel in [f for f in files if f.name == "pnpm-lock.yaml"]:
        try:
            for r in npm.parse_pnpm_lock(repo, str(rel)):
                results.append(r)
                covered.add(Path(r["manifest"]).parent)
            covered.add(rel.parent)
        except Exception as e:
            gaps.append(CoverageGap(str(rel), "scan_error", f"{type(e).__name__}: {e}"))
    for rel in files:
        if rel.name == "pnpm-lock.yaml" or (rel.name == "package.json" and rel.parent in covered):
            continue
        for pred, parser, shadowed_by in PARSERS:
            if not pred(rel.name):
                continue
            if set(shadowed_by) & names_by_dir[rel.parent]:
                break
            if len(results) >= MAX_PROJECTS:
                gaps.append(CoverageGap(str(rel), "scan_error", f"more than {MAX_PROJECTS} projects; skipped"))
                break
            try:
                r = parser(repo, str(rel))
            except Exception as e:   # one broken manifest must not stop the scan
                gaps.append(CoverageGap(str(rel), "scan_error", f"{type(e).__name__}: {e}"))
                break
            if r and r["components"]:
                results.append(r)
            elif r:
                gaps.extend(r["gaps"])
            break
        else:
            label, shadowed = KNOWN_UNSUPPORTED.get(rel.name, (None, ()))
            if label and not set(shadowed) & names_by_dir[rel.parent] and not (
                    rel.name == "Cargo.toml" and any(f.name == "Cargo.lock" for f in files)):   # workspace member
                gaps.append(CoverageGap(str(rel), "unsupported_format", label))
    return results, gaps
