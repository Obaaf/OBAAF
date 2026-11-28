import json
import os
from pathlib import Path
from test_jenkins_release import JenkinsReleaseLaneTest, publish_run, tag_build

case = JenkinsReleaseLaneTest()
case.setUp()
case.write_records()
case.key.unlink()
(case.tmp / "publish-run.json").write_text(json.dumps(publish_run()))
(case.tmp / "release-run.json").write_text(json.dumps(tag_build(case.rev)))
(case.tmp / "revision").write_text(case.rev)
Path(os.environ["PROBE_ROOT"], "fixture-path").write_text(str(case.tmp))
