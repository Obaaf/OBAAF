"""D-011: OBAAF's pipeline install and its release build install dependencies by hash.

requirements.txt must pin exactly the versions in constraints.txt, each with at least
one SHA-256, and every install path that can use hash-checking mode must use it.
"""

import importlib.util
import re
import unittest

from helpers import ROOT

SETUP = ROOT / "actions" / "setup-obaaf"
REQ = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)==(\S+) \\$")
HASH = re.compile(r"^--hash=sha256:([0-9a-f]{64})( \\)?$")


def _lock_module():
    spec = importlib.util.spec_from_file_location("lock_setup_obaaf", ROOT / "scripts" / "lock_setup_obaaf.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _parse_lock(text):
    """{name: (version, [digests])} from a generated requirements file."""
    out, current = {}, None
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        req = REQ.match(line)
        if req:
            current = req.group(1)
            out[current] = (req.group(2), [])
            continue
        digest = HASH.match(line)
        if not digest or current is None:
            raise AssertionError(f"unexpected line in requirements.txt: {raw!r}")
        out[current][1].append(digest.group(1))
    return out


class LockFileTest(unittest.TestCase):
    def test_lock_pins_exactly_the_constraints_with_hashes(self):
        lock_path = SETUP / "requirements.txt"
        self.assertTrue(lock_path.is_file(), "run: python scripts/lock_setup_obaaf.py")
        lock = _parse_lock(lock_path.read_text(encoding="utf-8"))
        pins = dict(_lock_module().pins((SETUP / "constraints.txt").read_text(encoding="utf-8")))
        self.assertEqual({n: v for n, (v, _) in lock.items()}, pins)
        for name, (_, digests) in lock.items():
            with self.subTest(package=name):
                self.assertTrue(digests)
                self.assertEqual(len(digests), len(set(digests)))

    def test_generator_output_is_deterministic(self):
        module = _lock_module()
        files = [{"digests": {"sha256": "b" * 64}}, {"digests": {"sha256": "a" * 64}}, {"digests": {"sha256": "a" * 64}}]
        digests = module.pypi_hashes("pkg", "1.0", fetch=lambda url: {"urls": files})
        self.assertEqual(digests, ["a" * 64, "b" * 64])
        text = module.render([("pkg", "1.0", digests)])
        self.assertEqual(_parse_lock(text), {"pkg": ("1.0", ["a" * 64, "b" * 64])})

    def test_generator_refuses_a_version_without_digests(self):
        module = _lock_module()
        with self.assertRaises(ValueError):
            module.pypi_hashes("pkg", "1.0", fetch=lambda url: {"urls": []})

    def test_generator_rejects_unpinned_constraints(self):
        with self.assertRaises(ValueError):
            _lock_module().pins("PyYAML>=6\n")


class InstallPathsTest(unittest.TestCase):
    def test_setup_action_installs_by_hash_only(self):
        text = (SETUP / "action.yml").read_text(encoding="utf-8")
        self.assertIn("--require-hashes", text)
        self.assertIn('--requirement "$GITHUB_ACTION_PATH/requirements.txt"', text)
        self.assertNotIn("--constraint", text)

    def test_release_build_installs_by_hash(self):
        text = (ROOT / ".github" / "workflows" / "release-pypi.yml").read_text(encoding="utf-8")
        installs = [line for line in text.splitlines() if "pip install" in line]
        self.assertTrue(installs)
        for line in installs:
            with self.subTest(line=line.strip()):
                self.assertTrue("--require-hashes" in line or "--no-deps" in line, line)

    def test_ci_checks_the_lock_and_runs_the_action_on_every_os(self):
        text = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        self.assertIn("python scripts/lock_setup_obaaf.py --check", text)
        # A failed check attaches the expected file, so it can be committed without PyPI access.
        self.assertIn("name: setup-obaaf-requirements", text)
        self.assertIn("os: [ubuntu-latest, macos-latest, windows-latest]", text)


if __name__ == "__main__":
    unittest.main()
