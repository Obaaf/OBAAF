"""FR10: sign a record of each agent run.

Acceptance criterion: agent tools and models are pinned by digest, and each
run produces a record of its inputs and their trust levels, the authority
granted, the model and tool versions, and its outputs, valid against the
published schema.
"""

import json
import re
import unittest

from helpers import TEMPLATES, TempDir, all_steps, run_cli, template_workflow
from scenario import AGENT_WORKFLOW, take_snapshot

from obaaf import predicates
from obaaf.attest import records
from obaaf.attest.common import validate_predicate
from obaaf.predicates import AGENT_RUN

SHA = re.compile(r"^[0-9a-f]{40}$")


def proposal(tmp):
    root = tmp / "proposal"
    root.mkdir()
    (root / "comment.md").write_text("Thanks, a maintainer will look.\n", encoding="utf-8")
    return root


class PinnedToolsTest(unittest.TestCase):
    def test_every_action_in_every_template_is_pinned_to_a_commit(self):
        for path in sorted((TEMPLATES / "workflows").glob("*.yml")):
            wf = template_workflow(path.name)
            for job, step in all_steps(wf):
                if step.uses and not step.uses.startswith("./"):
                    with self.subTest(workflow=path.name, step=step.name):
                        ref = step.uses.split("@", 1)[1]
                        self.assertRegex(ref, SHA)
                        uses_line = wf.text.splitlines()[step.raw.line_of("uses") - 1]
                        if not step.uses.startswith("OBAAF_OWNER/"):
                            self.assertRegex(uses_line, r"# v\d", "keep the version in a comment for Dependabot")

    def test_templates_use_the_published_predicate_types(self):
        text = "".join(p.read_text() for p in (TEMPLATES / "workflows").glob("*.yml"))
        self.assertIn(predicates.AGENT_RUN, text)
        self.assertIn(predicates.AGENT_APPROVAL, text)
        self.assertIn(predicates.BUILD_RECORD, text)


class AgentRunRecordTest(unittest.TestCase):
    def make(self, tmp, **kwargs):
        snap = take_snapshot(tmp / "snap")
        return records.agent_run_predicate(snap, proposal(tmp), AGENT_WORKFLOW, "agent", **kwargs)

    def test_record_is_valid_and_complete(self):
        with TempDir() as tmp:
            subjects, pred = self.make(tmp)
            self.assertEqual(validate_predicate(AGENT_RUN, pred), [])
            self.assertEqual([s["name"] for s in subjects], ["comment.md"])
            self.assertEqual(pred["inputs"]["integrityLevel"], "Public")
            self.assertTrue(all(i["digest"]["sha256"] and i["label"] for i in pred["inputs"]["items"]))
            auth = pred["authority"]
            self.assertEqual(auth["tokenPermissions"], {"declared": True, "scopes": {"contents": "read"}})
            self.assertEqual((auth["secrets"], auth["oidc"], auth["cacheMode"]), ([], False, "none"))
            self.assertIn("inference proxy", auth["network"]["declaredPolicy"])
            for action in pred["agent"]["actions"]:
                if not action["uses"].startswith("OBAAF_OWNER/"):
                    self.assertRegex(action["digest"]["gitCommit"], SHA)
            self.assertEqual(pred["agent"]["model"]["reportedBy"], "none")
            self.assertIsNone(pred["trace"])

    def test_model_comes_from_the_proxy_and_the_trace_is_untrusted(self):
        with TempDir() as tmp:
            receipt = tmp / "receipt.json"
            receipt.write_text(json.dumps({"format": "obaaf-model-receipt/v0.1", "model": "example-model",
                                           "version": "2026-09-01", "requests": 3}))
            trace = tmp / "trace.jsonl"
            trace.write_text('{"tool":"read_file"}\n')
            _, pred = self.make(tmp, model_receipt=receipt, trace=trace)
            self.assertEqual(pred["agent"]["model"]["reportedBy"], "inference-proxy")
            self.assertEqual(pred["agent"]["model"]["id"], "example-model")
            self.assertFalse(pred["trace"]["trusted"])
            self.assertEqual(validate_predicate(AGENT_RUN, pred), [])

    def test_schema_rejects_a_trusted_trace_or_unknown_levels(self):
        with TempDir() as tmp:
            _, pred = self.make(tmp)
            pred["trace"] = {"digest": {"sha256": "0" * 64}, "trusted": True}
            self.assertTrue(validate_predicate(AGENT_RUN, pred))
            other = tmp / "b"
            other.mkdir()
            _, pred = self.make(other)
            pred["inputs"]["integrityLevel"] = "Admin"
            self.assertTrue(validate_predicate(AGENT_RUN, pred))

    def test_snapshot_digest_mismatch_stops_the_record(self):
        with TempDir() as tmp:
            snap = take_snapshot(tmp / "snap")
            code, _, err = run_cli("attest", "agent-run", "--snapshot", snap, "--snapshot-digest", "0" * 64,
                                   "--proposal", proposal(tmp), "--workflow-file", AGENT_WORKFLOW, "--job", "agent",
                                   "--out", tmp / "out.json")
            self.assertEqual(code, 1)
            self.assertIn("does not match", err)

    def test_cli_writes_predicate_and_statement(self):
        with TempDir() as tmp:
            snap = take_snapshot(tmp / "snap")
            from obaaf.attest import snapshot

            code, out, err = run_cli("attest", "agent-run", "--snapshot", snap, "--snapshot-digest",
                                     snapshot.digest(snap), "--proposal", proposal(tmp), "--workflow-file",
                                     AGENT_WORKFLOW, "--job", "agent", "--out", tmp / "pred.json",
                                     "--statement-out", tmp / "stmt.json")
            self.assertEqual(code, 0, err)
            stmt = json.loads((tmp / "stmt.json").read_text())
            self.assertEqual(stmt["_type"], "https://in-toto.io/Statement/v1")
            self.assertEqual(stmt["predicateType"], AGENT_RUN)


if __name__ == "__main__":
    unittest.main()
