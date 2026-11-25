"""Operation counts and stable attribution in the static artifact-transfer matcher."""

import unittest
from types import SimpleNamespace
from unittest.mock import patch

from obaaf.checker import artifact_consumers as artifacts


def step(action="", run="", **inputs):
    return SimpleNamespace(uses=action, clean_action=action, with_=inputs, raw={}, run=run)


def workflow(steps):
    return SimpleNamespace(
        path="fixture.yml", raw={}, triggers={},
        jobs={"producer": SimpleNamespace(id="producer", in_lane=lambda lane: lane == "agent", steps=steps)},
    )


class ArtifactConsumerIndexTest(unittest.TestCase):
    def test_repeated_downloads_and_sources_parse_each_candidate_once(self):
        upload = step("actions/upload-artifact", name="sample", path="sample.txt")
        wf = workflow([upload] * 128)
        sources = artifacts.uploads([wf])
        downloads = [step("actions/download-artifact", name="sample", path="result") for _ in range(96)]
        consume = step(run="sh result/sample.txt")
        read = step(run="cat result/sample.txt")
        job = SimpleNamespace(id="reader", raw={}, steps=[*downloads, read, consume])
        with patch.object(artifacts, "_executed_paths", wraps=artifacts._executed_paths) as parse:
            hits = list(artifacts.consumers(wf, job, sources))
        self.assertLessEqual(parse.call_count, len(job.steps))
        self.assertEqual(len(hits), 1)
        source, download, candidate, path = hits[0]
        self.assertEqual((source.name, path), ("sample", "result/sample.txt"))
        self.assertIs(download, downloads[0])
        self.assertIs(candidate, consume)

    def test_earliest_compatible_source_and_download_win_across_operands(self):
        wf = workflow([
            step("actions/upload-artifact", name="first", path="notes.txt"),
            step("actions/upload-artifact", name="second", path="other.txt"),
        ])
        first_download = step("actions/download-artifact", path="reports")
        next_download = step("actions/download-artifact", name="second", path="reports/first")
        consume = step(run="sh reports/second/other.txt\nsh reports/first/notes.txt")
        job = SimpleNamespace(id="reader", raw={}, steps=[first_download, next_download, consume])
        hits = list(artifacts.consumers(wf, job, artifacts.uploads([wf])))
        self.assertEqual(len(hits), 1)
        source, download, candidate, path = hits[0]
        self.assertEqual((source.name, path), ("first", "reports/first/notes.txt"))
        self.assertIs(download, first_download)
        self.assertIs(candidate, consume)
