import tempfile
import unittest
from pathlib import Path

from guardian.discovery import build_inventory
from guardian.discovery.purl import purl, short


def repo_with(files):
    d = Path(tempfile.mkdtemp())
    for name, text in files.items():
        (d / name).parent.mkdir(parents=True, exist_ok=True)
        (d / name).write_text(text)
    return d


class Purls(unittest.TestCase):
    def test_purl_forms(self):
        self.assertEqual(purl("npm", "@s/x", "1.0.0"), "pkg:npm/%40s/x@1.0.0")
        self.assertEqual(purl("pypi", "Flask_Login", "0.6"), "pkg:pypi/flask-login@0.6")
        self.assertEqual(purl("golang", "github.com/gin-gonic/gin", "v1.9.1"), "pkg:golang/github.com/gin-gonic/gin@v1.9.1")
        self.assertEqual(purl("maven", "org.x:core", "2.0"), "pkg:maven/org.x/core@2.0")
        self.assertEqual(short("pkg:npm/%40s/x@1.0.0"), "@s/x@1.0.0")


class Parsers(unittest.TestCase):
    def test_pip_compile_via_builds_edges(self):
        inv = build_inventory(repo_with({"requirements.txt":
            "flask==3.0.0\n    # via -r requirements.in\nwerkzeug==3.0.1\n    # via flask\nunpinned>=1.0\n"}))
        c = inv["components"]
        self.assertEqual(c["pkg:pypi/werkzeug@3.0.1"].relationship, "transitive")
        self.assertEqual(c["pkg:pypi/flask@3.0.0"].relationship, "direct")
        self.assertEqual(c["pkg:pypi/unpinned"].resolution, "declared-only")

    def test_cargo_lock_graph_and_workspace_root(self):
        inv = build_inventory(repo_with({"Cargo.lock": """
[[package]]
name = "app"
version = "0.1.0"
dependencies = ["serde"]

[[package]]
name = "serde"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
dependencies = ["itoa"]

[[package]]
name = "itoa"
version = "1.0.1"
source = "registry+https://github.com/rust-lang/crates.io-index"
"""}))
        c = inv["components"]
        self.assertEqual(c["pkg:cargo/serde@1.0.0"].relationship, "direct")
        self.assertEqual(c["pkg:cargo/itoa@1.0.1"].relationship, "transitive")
        self.assertEqual(len(c["pkg:cargo/itoa@1.0.1"].path), 3)

    def test_go_mod_direct_and_indirect(self):
        inv = build_inventory(repo_with({"go.mod": "module example.com/x\n\ngo 1.22\n\nrequire (\n\tgithub.com/a/b v1.2.3\n\tgolang.org/x/net v0.1.0 // indirect\n)\n"}))
        c = inv["components"]
        self.assertEqual(c["pkg:golang/github.com/a/b@v1.2.3"].relationship, "direct")
        self.assertEqual(c["pkg:golang/golang.org/x/net@v0.1.0"].relationship, "transitive")
        self.assertEqual(c["pkg:golang/golang.org/x/net@v0.1.0"].scope, "prod")
        self.assertTrue(any("indirect" in g["detail"] for g in inv["gaps"]))

    def test_gemfile_lock(self):
        inv = build_inventory(repo_with({"Gemfile.lock": "GEM\n  remote: https://rubygems.org/\n  specs:\n    rails (7.1.0)\n      rack (>= 2)\n    rack (3.0.8)\n\nDEPENDENCIES\n  rails\n"}))
        c = inv["components"]
        self.assertEqual(c["pkg:gem/rack@3.0.8"].relationship, "transitive")

    def test_monorepo_merges_projects_under_repo_root(self):
        inv = build_inventory(repo_with({"api/requirements.txt": "requests==2.31.0\n",
                                         "web/package.json": '{"name": "web", "dependencies": {"left-pad": "1.3.0"}}'}))
        self.assertTrue(inv["root"].startswith("repo:"))
        self.assertEqual(len(inv["projects"]), 2)
        self.assertEqual(set(inv["adjacency"][inv["root"]]), {p["root"] for p in inv["projects"]})

    def test_ros_and_repos_files(self):
        inv = build_inventory(repo_with({
            "pkg/package.xml": "<package><name>pkg</name><version>1.0.0</version><depend>rclcpp</depend><test_depend>gtest</test_depend></package>",
            "deps.repos": "repositories:\n  x:\n    type: git\n    url: https://github.com/o/x.git\n    version: main\n"}))
        c = inv["components"]
        self.assertEqual(c["pkg:ros/rclcpp"].resolution, "declared-only")
        self.assertIn("pkg:git/o%2Fx@main", c)

    def test_pnpm_workspace_importers_and_edges(self):
        lock = """lockfileVersion: '9.0'
importers:
  .:
    devDependencies:
      vite: {specifier: ^5.0.0, version: 5.0.0}
  packages/app:
    dependencies:
      lodash: {specifier: ^4.17.0, version: 4.17.21}
      shared: {specifier: workspace:*, version: link:../shared}
packages:
  vite@5.0.0: {resolution: {integrity: sha512-AAA}}
  esbuild@0.19.0: {resolution: {integrity: sha512-BBB}}
  lodash@4.17.21: {resolution: {integrity: sha512-CCC}}
snapshots:
  vite@5.0.0:
    dependencies:
      esbuild: 0.19.0
  esbuild@0.19.0: {}
  lodash@4.17.21: {}
"""
        inv = build_inventory(repo_with({"pnpm-lock.yaml": lock, "package.json": '{"name": "root"}',
                                         "packages/app/package.json": '{"name": "app"}'}))
        self.assertEqual(sorted(p["manifest"] for p in inv["projects"]), ["package.json", "packages/app/package.json"])
        c = inv["components"]
        self.assertEqual(c["pkg:npm/esbuild@0.19.0"].relationship, "transitive")
        self.assertEqual(c["pkg:npm/esbuild@0.19.0"].scope, "dev")
        self.assertEqual(c["pkg:npm/lodash@4.17.21"].scope, "prod")
        self.assertNotIn("pkg:npm/shared", " ".join(c))       # workspace links are not packages


if __name__ == "__main__":
    unittest.main()
