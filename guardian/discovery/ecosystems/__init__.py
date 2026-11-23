"""Find every supported manifest/lockfile in a repository and parse it with its ecosystem parser."""
from pathlib import Path

from ...models import CoverageGap
from . import npm, python, others

SKIP_DIRS = {"node_modules", ".git", "vendor", "dist", "build", "target", "__pycache__", ".venv", "venv",
             "site-packages", "fixtures", "__fixtures__", "testdata", ".tox", "bower_components"}
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
    (lambda n: n == "go.mod", others.parse_go_mod, ()),
    (lambda n: n == "Cargo.lock", others.parse_cargo_lock, ()),
    (lambda n: n == "Gemfile.lock", others.parse_gemfile_lock, ()),
    (lambda n: n == "composer.lock", others.parse_composer, ()),
    (lambda n: n == "composer.json", others.parse_composer, ("composer.lock",)),
    (lambda n: n == "pom.xml", others.parse_pom, ()),
    (lambda n: n == "package.xml", others.parse_ros_package, ()),
    (lambda n: n.endswith(".repos"), others.parse_repos_file, ()),
    (lambda n: n == ".gitmodules", others.parse_gitmodules, ()),
]
KNOWN_UNSUPPORTED = {"pnpm-lock.yaml": "pnpm lockfile", "build.gradle": "Gradle build", "build.gradle.kts": "Gradle build",
                     "Cargo.toml": None, "Gemfile": None, "pyproject.toml": None, "Pipfile": None,
                     "conanfile.txt": "Conan (C/C++)", "conanfile.py": "Conan (C/C++)", "vcpkg.json": "vcpkg (C/C++)",
                     "CMakeLists.txt": "CMake (C/C++ dependencies are not declared in a machine-readable lockfile)",
                     "packages.config": "NuGet", "Package.resolved": "SwiftPM", "mix.lock": "Elixir"}


def discover_projects(repo):
    repo = Path(repo)
    files = []
    for p in sorted(repo.rglob("*")):
        rel = p.relative_to(repo)
        if p.is_file() and not SKIP_DIRS & set(rel.parts[:-1]):
            files.append(rel)
    names_by_dir = {}
    for rel in files:
        names_by_dir.setdefault(rel.parent, set()).add(rel.name)
    results, gaps = [], []
    for rel in files:
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
            label = KNOWN_UNSUPPORTED.get(rel.name)
            if label:
                gaps.append(CoverageGap(str(rel), "unsupported_format", f"{label} is not parsed"))
    return results, gaps
