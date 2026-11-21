"""Offline settings evidence, using the existing audit producer and its benign replay fixture."""
import copy
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from helpers import run_cli
from obaaf.audit import snapshot
from obaaf.settings_evidence import SettingsEvidence
from test_settings_audit import recording, take


class EvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.recorded, _ = take(recording("admin-token"), token="dummy")
        cls.when = datetime(2026, 11, 12, 1, tzinfo=timezone.utc)

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.path = self.root / "policy/settings.json"
        self.data = copy.deepcopy(self.recorded)
        self.settings = self.data["settings"]
        self.env = self.settings["environments"]["value"][1]
        self.env["branch_policies"] = [{"type": "branch", "name": "main"}]

    def read(self, *, now=None, repository="example-studio/game"):
        snapshot.write(self.data, self.path)
        return SettingsEvidence.load(self.path, repository, now or self.when)

    def result(self):
        return self.read().assess("PACKAGE_INDEX_TOKEN", "release")

    def test_complete_observations_and_protected_only_mode(self):
        self.assertEqual(self.result().verdict, "verified")
        self.env["deployment_branches"] = "protected"
        self.env.pop("branch_policies")
        self.assertEqual(self.result().verdict, "cannot tell")
        fixture = Path(__file__).parent / "fixtures/settings/classic-before-2b6/snapshot.json"
        self.settings["branch_protection"] = json.loads(fixture.read_text())["settings"]["branch_protection"]
        self.assertEqual(self.result().verdict, "verified")

    def test_timestamp_boundary_future_identity_and_invalid_date(self):
        for age, verdict in [(timedelta(days=30), "verified"), (timedelta(days=30, seconds=1), "cannot tell"),
                             (timedelta(seconds=-1), "cannot tell")]:
            with self.subTest(age=age):
                e = self.read(now=self.when + age)
                self.assertEqual(e.taken_at, "2026-11-12T01:00:00Z")
                self.assertEqual(e.assess("PACKAGE_INDEX_TOKEN", "release").verdict, verdict)
        for identity in (None, "other/repo"):
            self.assertTrue(self.read(repository=identity).limitations)
        self.data["taken_at"] = "2026-02-31T01:00:00Z"
        with self.assertRaisesRegex(snapshot.SnapshotError, "valid UTC"):
            self.read()

    def test_unread_partial_and_absent_inventory_remain_unknown(self):
        for key in ("environments", "environment_secrets", "repository_secrets", "organization_secrets", "branches"):
            with self.subTest(key=key):
                old = self.settings[key]
                self.settings[key] = {"status": "unread", "reason_code": "forbidden", "reason": "read refused",
                                      "needs": "read"}
                result = self.result()
                self.assertEqual(result.verdict, "cannot tell")
                self.assertIn("read refused", result.reason)
                self.settings[key] = old
        self.settings["environment_secrets"].update(status="partial", needs="read", problems=[
            {"key": "main-only", "what": "environment", "reason_code": "forbidden", "reason": "scope unavailable"}])
        self.assertIn("scope unavailable", self.result().reason)
        self.settings["environment_secrets"] = {"status": "read", "value": {"release": ["PACKAGE_INDEX_TOKEN"]}}
        self.assertIn("inventories disagree", self.result().reason)

    def test_evidence_of_another_copy_or_an_unprotected_branch(self):
        for key in ("repository_secrets", "organization_secrets"):
            self.settings[key]["value"].append("package_index_token")
            self.assertEqual(self.result().verdict, "not met")
            self.settings[key]["value"].pop()
        self.settings["environment_secrets"]["value"]["main-only"].append("PACKAGE_INDEX_TOKEN")
        self.assertEqual(self.result().verdict, "not met")
        self.settings["environment_secrets"]["value"]["main-only"].pop()
        self.settings["branches"]["value"]["main"]["protected"] = False
        self.assertEqual(self.result().verdict, "not met")
        self.env["branch_policies"][0]["name"] = "release-*"
        self.assertEqual(self.result().verdict, "cannot tell")
        self.env["branch_policies"][0]["type"] = "tag"
        self.assertEqual(self.result().verdict, "not met")

    def test_each_check_named_in_d104_decides_on_its_own(self):
        """One change per case, each of which only that check catches (review of #284: with any one of
        these checks removed, the other tests still passed)."""
        def protected_mode_unread(s, e):
            e["deployment_branches"] = "protected"
            e.pop("branch_policies")
            s["branch_protection"] = {"status": "unread", "reason_code": "forbidden",
                                      "reason": "protection refused", "needs": "read"}

        def twin(s, e, name):
            s["environments"]["value"].append({**copy.deepcopy(e), "name": name})
            s["environment_secrets"]["value"].setdefault(name, [])

        cases = [
            ("api host", lambda s, e: self.data.update(api="https://github.example.com/api/v3"),
             "release", "API host differs"),
            ("observed name", lambda s, e: s["repository"]["value"].update(full_name="example-studio/other"),
             "release", "observed repository identity"),
            ("repository unread", lambda s, e: s.update(repository={
                "status": "unread", "reason_code": "forbidden", "reason": "repository refused", "needs": "read"}),
             "release", "repository refused"),
            ("environment listed twice", lambda s, e: s["environments"]["value"].append(copy.deepcopy(e)),
             "release", "inventories disagree"),
            ("two environments one name", lambda s, e: twin(s, e, "Release"), "release", "ambiguous"),
            ("computed environment", lambda s, e: None, "${{ inputs.target }}", "literal environment"),
            ("policy of no type", lambda s, e: e["branch_policies"][0].update(type="other"),
             "release", "literal branches"),
            ("brace in a policy", lambda s, e: e["branch_policies"][0].update(name="{main,dev}"),
             "release", "literal branches"),
            ("branch not observed", lambda s, e: e["branch_policies"][0].update(name="develop"),
             "release", "was not observed"),
            ("protection unread", protected_mode_unread, "release", "protection refused"),
        ]
        for label, change, environment, reason in cases:
            with self.subTest(label):
                self.setUp()
                change(self.settings, self.env)
                try:
                    result = self.read().assess("PACKAGE_INDEX_TOKEN", environment)
                except snapshot.SnapshotError as exc:
                    self.fail(f"the snapshot format refused the case itself: {exc}")
                self.assertEqual(result.verdict, "cannot tell", result.reason)
                self.assertIn(reason, result.reason)
        self.setUp()
        result = self.read().assess("PACKAGE_*", "release")
        self.assertEqual((result.verdict, result.reason), ("cannot tell", "a literal secret name is needed"))

    def test_personal_repository_requires_observed_owner_type(self):
        self.settings["organization_secrets"] = {"status": "not_applicable", "reason": "personal repository"}
        self.assertEqual(self.result().verdict, "cannot tell")
        self.settings["repository"]["value"]["owner_type"] = "User"
        self.assertEqual(self.result().verdict, "verified")

    def test_cli_clears_only_with_five_verified_controls(self):
        from test_egress_recognised import catalog, keyed, workflow
        subprocess.run(["git", "init", "-q", str(self.root)], check=True)
        subprocess.run(["git", "-C", str(self.root), "remote", "add", "origin",
                        "https://github.com/example-studio/game.git"], check=True)
        folder = self.root / ".github"
        (folder / "workflows").mkdir(parents=True)
        (folder / "CODEOWNERS").write_text("* @example/build\n")
        (folder / "obaaf.yml").write_text("protected_secrets: {PACKAGE_INDEX_TOKEN: release}\n"
                                         "lanes: {'.github/workflows/ci.yml#agent': agent}\n")
        step = keyed(step_env={"ANTHROPIC_API_KEY": "${{ secrets.PACKAGE_INDEX_TOKEN }}"})
        workflow_path = folder / "workflows/ci.yml"
        workflow_path.write_text(workflow(step, job_extra="    environment: release"))
        self.data["taken_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        args = ("check", str(self.root), "--format", "json", "--fail-on", "never")
        rule = "OBAAF-GHA-005"

        def report(*flags):
            status, out, err = run_cli(*args, *flags)
            self.assertEqual(status, 0, err)
            return json.loads(out)

        with patch("obaaf.checker.load", return_value=catalog()):
            before = report()
            snapshot.write(self.data, self.path)
            selected = ("--settings", str(self.path))
            complete = report(*selected)
            finding = next(f for f in complete["fixed"] if f["rule"] == rule)
            self.assertEqual([c["verdict"] for c in finding["controls"]], ["verified"] * 5)
            self.assertIn(self.data["taken_at"], finding["controls"][1]["detail"])
            self.assertFalse(any(f["rule"] == rule for f in complete["findings"]))
            self.assertEqual(complete["summary"]["fixed"], before["summary"]["fixed"] + 1)
            # The PR workflow selects the target snapshot even when the PR changed or deleted it.
            def git(*arguments):
                return subprocess.run(
                    ["git", "-C", str(self.root), "-c", "user.name=Evidence Test",
                     "-c", "user.email=evidence@example.invalid", "-c", "commit.gpgsign=false",
                     *arguments], check=True, capture_output=True,
                ).stdout

            relative = self.path.relative_to(self.root).as_posix()
            git("add", "--", relative)
            git("commit", "-qm", "target snapshot")
            target = git("rev-parse", "HEAD").decode().strip()
            for change in ("changed", "deleted"):
                with self.subTest(pr_snapshot=change):
                    if change == "changed":
                        self.path.write_text("{}")
                    else:
                        self.path.unlink()
                    git("add", "-u", "--", relative)
                    git("commit", "-qm", change + " PR snapshot")
                    self.path.write_bytes(git("show", f"{target}:{relative}"))
                    copied = next(f for f in report(*selected)["fixed"] if f["rule"] == rule)
                    self.assertEqual([c["verdict"] for c in copied["controls"]], ["verified"] * 5)
            (folder / "CODEOWNERS").write_text("/.github/ @example/build\n")
            unowned = report(*selected)
            self.assertTrue(any(f["rule"] == rule for f in unowned["fixed"]))
            self.assertTrue(any(f["rule"] == "OBAAF-REPO-001" and "policy/settings.json" in f["message"]
                                for f in unowned["findings"]))
            self.assertGreater(unowned["summary"]["new"], complete["summary"]["new"])
            workflow_path.write_text(workflow(step, job_extra="    environment: release", on="issues"))
            outstanding = next(f for f in report(*selected)["findings"] if f["rule"] == rule)
            self.assertEqual(outstanding["controls"][1]["verdict"], "verified")
            self.assertNotEqual(outstanding["controls"][2]["verdict"], "verified")
            workflow_path.write_text(workflow(step, job_extra="    environment: release"))
            with (folder / "obaaf.yml").open("a") as config:
                config.write("ignore:\n  - rule: OBAAF-GHA-005\n    path: .github/workflows/ci.yml\n"
                             "    job: agent\n    owner: '@example/build'\n"
                             "    reason: The build team reviewed this temporary credential risk\n"
                             f"    until: {(datetime.now(timezone.utc) + timedelta(days=7)).date()}\n")
            self.assertTrue(any(f["rule"] == rule for f in report(*selected)["fixed"]))
            self.settings["repository_secrets"]["value"].append("PACKAGE_INDEX_TOKEN")
            snapshot.write(self.data, self.path)
            outstanding = next(f for f in report(*selected)["findings"] if f["rule"] == rule)
            self.assertEqual(outstanding["controls"][1]["verdict"], "not met")
            self.assertEqual(outstanding["state"], "accepted")
            self.settings["organization_secrets"] = {"status": "unread", "reason_code": "forbidden",
                                                     "reason": "inventory not available", "needs": "read"}
            snapshot.write(self.data, self.path)
            outstanding = next(f for f in report(*selected)["findings"] if f["rule"] == rule)
            self.assertEqual(outstanding["controls"][1]["verdict"], "cannot tell")
            self.assertIn("inventory not available", outstanding["controls"][1]["detail"])
            self.data["taken_at"] = "2020-01-01T00:00:00Z"
            snapshot.write(self.data, self.path)
            outstanding = next(f for f in report(*selected)["findings"] if f["rule"] == rule)
            self.assertEqual(outstanding["controls"][1]["verdict"], "cannot tell")
            self.assertIn("30 days", outstanding["controls"][1]["detail"])

    def test_normal_cli_reads_only_selected_file_and_checks_ownership(self):
        subprocess.run(["git", "init", "-q", str(self.root)], check=True)
        subprocess.run(["git", "-C", str(self.root), "remote", "add", "origin",
                        "https://github.com/example-studio/game.git"], check=True)
        folder = self.root / ".github"
        (folder / "workflows").mkdir(parents=True)
        (folder / "workflows/ci.yml").write_text("""on: workflow_dispatch
permissions: {contents: read}
jobs:
  assistant:
    runs-on: ubuntu-latest
    environment: release
    env:
      API_KEY: ${{ secrets.PACKAGE_INDEX_TOKEN }}
    steps:
      - uses: openai/codex-action@1111111111111111111111111111111111111111
""")
        (folder / "CODEOWNERS").write_text("/.github/ @example/build\n")
        (folder / "obaaf.yml").write_text("protected_secrets: {PACKAGE_INDEX_TOKEN: release}\n")
        self.data["taken_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        snapshot.write(self.data, self.path)
        args = ("check", str(self.root), "--format", "json", "--fail-on", "never")
        status, out, err = run_cli(*args)
        self.assertEqual(status, 0, err)
        self.assertNotIn("Settings snapshot", err)
        before = json.loads(out)["findings"]
        self.assertTrue(any(f["rule"] == "OBAAF-GHA-005" for f in before))
        status, out, err = run_cli(*args, "--settings", str(self.path))
        self.assertEqual(status, 0, err)
        self.assertIn(self.data["taken_at"], err)
        self.assertIn("PACKAGE_INDEX_TOKEN: verified", err)
        found = json.loads(out)["findings"]
        self.assertTrue(any(f["rule"] == "OBAAF-REPO-001" and "policy/settings.json" in str(f) for f in found))
        other = lambda rows: [f for f in rows if f["rule"] not in {"OBAAF-REPO-001", "OBAAF-GHA-005"}]
        self.assertEqual(other(found), other(before))
        control = next(f for f in found if f["rule"] == "OBAAF-GHA-005")["controls"][1]
        self.assertEqual(control["verdict"], "verified")
        self.assertIn(self.data["taken_at"], control["detail"])
        # The library enrolls the snapshot itself, even if the caller supplies no gate_files.
        from obaaf import checker
        evidence = SettingsEvidence.load(self.path, "example-studio/game")
        config = checker.Config.load(self.root)
        workflow_path = folder / "workflows/ci.yml"
        for target, files in [(workflow_path, None), (self.root, [workflow_path]), (self.root, None)]:
            with self.subTest(target=target, files=files):
                result = checker.check(target, files=files, config=config, settings=evidence)
                setting = next(f for f in result.findings if f.rule == "OBAAF-GHA-005").controls[1]
                if target == self.root and files is None:
                    self.assertEqual(setting.verdict, "verified")
                    self.assertTrue(any(f.rule == "OBAAF-REPO-001" and "policy/settings.json" in f.message
                                        for f in result.findings))
                else:
                    self.assertEqual(setting.verdict, "cannot tell")
                    self.assertIn("does not check snapshot code ownership", setting.detail)
        workflow = folder / "workflows/ci.yml"
        partials = [(str(workflow), "--config", str(folder / "obaaf.yml")), (str(self.root), "--lanes")]
        for partial in partials:
            with self.subTest(partial=partial):
                status, _, err = run_cli("check", *partial, "--settings", str(self.path), "--fail-on", "never")
                self.assertEqual(status, 0, err)
                self.assertIn("PACKAGE_INDEX_TOKEN: cannot tell", err)
                self.assertIn("does not check snapshot code ownership", err)
                self.assertNotIn("PACKAGE_INDEX_TOKEN: verified", err)
        with tempfile.TemporaryDirectory() as directory:
            outside = Path(directory) / "settings.json"
            snapshot.write(self.data, outside)
            status, _, err = run_cli(*args, "--settings", str(outside))
            self.assertEqual(status, 0, err)
            self.assertIn("PACKAGE_INDEX_TOKEN: cannot tell", err)
            self.assertIn("outside the checked repository", err)
            # A link from outside to the repository's snapshot: the file is inside, but the path given is
            # not one OBAAF-REPO-001 checks for an owner, so nothing has checked who may change it.
            link = Path(directory) / "link.json"
            link.symlink_to(self.path)
            status, out, err = run_cli(*args, "--settings", str(link))
            self.assertEqual(status, 0, err)
            self.assertIn("PACKAGE_INDEX_TOKEN: cannot tell", err)
            self.assertIn("outside the checked repository", err)
            self.assertFalse(any("settings.json" in str(f) for f in json.loads(out)["findings"]
                                 if f["rule"] == "OBAAF-REPO-001"))
            # And the reverse: a link inside the repository to a snapshot outside it. The link has an
            # owner, but what it leads to does not.
            inner = self.root / ".github/outside-link.json"
            inner.symlink_to(outside)
            status, _, err = run_cli(*args, "--settings", str(inner))
            self.assertEqual(status, 0, err)
            self.assertIn("PACKAGE_INDEX_TOKEN: cannot tell", err)
            self.assertIn("outside the checked repository", err)
            inner.unlink()
        self.path.write_text("{}")
        self.assertEqual(run_cli(*args)[0], 0)
        self.assertEqual(run_cli(*args, "--settings", str(self.path))[0], 2)
