"""Flagship slice 2d.14 (#289): OBAAF-GHA-006 for a job that may publish.

OBAAF-GHA-006 was about release jobs only. A job OBAAF does not put in the release lane, because no step
it knows publishes, could still restore a cache and then hold a publishing credential: zizmor's test
workflow `cache-poisoning.yml` (v1.32.0) restores setup-uv's cache and then runs `uv build publish`
with `PYPI_PUBLISH_TOKEN`. Code from a poisoned cache entry runs with what the job holds, whether or not
the job itself publishes, so such a job is now reported at medium, as one the checker cannot tell
releases (kind `capability-restores`, or `capability-needed-job-restores` when the cache is restored by
a job it needs and downloads from).

What counts as holding what publishing needs is what OBAAF-GHA-015 already counts for a job nothing
marks a release job (`packages: write`, a step using an action under `publishing_actions`, a secret
whose name says it publishes), a reference that can read every secret, and a token with
`contents: write` in a job a release event, a tag push or a tag's creation can start.
"""

import unittest

from helpers import TempDir

from obaaf import checker

SHA = "1111111111111111111111111111111111111111"
RULE = "OBAAF-GHA-006"


def check(tmp, text, name="wf.yml", extra=None):
    root = tmp / "repo"
    (root / ".github" / "workflows").mkdir(parents=True, exist_ok=True)
    for old in (root / ".github" / "workflows").iterdir():
        old.unlink()
    (root / ".github" / "workflows" / name).write_text(text, encoding="utf-8")
    for path, body in (extra or {}).items():
        target = root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(body, encoding="utf-8")
    return checker.check(root)


def of(result, rule=RULE):
    return [f for f in result.findings if f.rule == rule]


def kinds(result, rule=RULE):
    return sorted((f.severity, f.kind) for f in of(result, rule))


SETUP_UV = f"      - name: Setup uv\n        uses: astral-sh/setup-uv@{SHA}\n"
PUBLISH = ("      - name: Publish\n        run: uv build publish\n        env:\n"
           "          UV_PUBLISH_TOKEN: ${{ secrets.PYPI_PUBLISH_TOKEN }}\n")
GO = f"      - name: Setup Go\n        uses: actions/setup-go@{SHA}\n"


def job(steps, on="release", job_extra="", top="permissions: {}\n"):
    return (f"on: {on}\n{top}jobs:\n  publish:\n    runs-on: ubuntu-latest\n{job_extra}"
            f"    steps:\n{steps}")


class ZizmorCaseTest(unittest.TestCase):
    """The case the parity test found (#289)."""

    def test_a_cache_restored_before_a_publishing_secret_is_reported(self):
        with TempDir() as tmp:
            found = of(check(tmp, job(SETUP_UV + PUBLISH)))
            self.assertEqual([(f.severity, f.kind) for f in found], [("medium", "capability-restores")])
            finding = found[0]
            self.assertEqual(finding.step, "Setup uv")
            self.assertEqual(finding.facts["capabilities"], ["secret PYPI_PUBLISH_TOKEN"])
            self.assertEqual(finding.facts["steps"], ["Setup uv (astral-sh/setup-uv)"])
            self.assertEqual(finding.facts["mode"], "")
            self.assertIn("cannot tell whether it releases", finding.message)
            self.assertIn("PYPI_PUBLISH_TOKEN", finding.message)

    def test_the_finding_names_what_the_job_holds(self):
        """An acceptance written for one credential does not cover another one added later."""
        with TempDir() as tmp:
            one = of(check(tmp, job(SETUP_UV + PUBLISH)))[0]
            more = PUBLISH + "          TWINE_PASSWORD: ${{ secrets.TWINE_PASSWORD }}\n"
            two = of(check(tmp, job(SETUP_UV + more)))[0]
            self.assertNotEqual(one.facts, two.facts)
            self.assertEqual(two.facts["capabilities"], ["secret PYPI_PUBLISH_TOKEN", "secret TWINE_PASSWORD"])


class WhatClearsItTest(unittest.TestCase):
    def test_cache_mode_none_or_write_only_clears_it(self):
        for mode in ("none", "write-only"):
            with self.subTest(mode=mode), TempDir() as tmp:
                self.assertEqual(of(check(tmp, job(SETUP_UV + PUBLISH, job_extra=f"    cache-mode: {mode}\n"))), [])

    def test_a_cache_mode_that_is_not_exactly_none_does_not(self):
        for mode in ("None", "read", "write", "${{ 'none' }}"):
            with self.subTest(mode=mode), TempDir() as tmp:
                text = job(SETUP_UV + PUBLISH, job_extra=f"    cache-mode: \"{mode}\"\n")
                self.assertEqual(kinds(check(tmp, text)), [("medium", "capability-restores")])

    def test_turning_the_cache_off_clears_it(self):
        with TempDir() as tmp:
            off = f"      - uses: astral-sh/setup-uv@{SHA}\n        with:\n          enable-cache: false\n"
            self.assertEqual(of(check(tmp, job(off + PUBLISH))), [])

    def test_no_cache_step_is_no_finding(self):
        """A job that may publish but restores no cache gets no `no-cache-mode` finding: that is for
        release jobs only."""
        with TempDir() as tmp:
            self.assertEqual(of(check(tmp, job(PUBLISH))), [])


class WhatHoldsWhatPublishingNeedsTest(unittest.TestCase):
    def test_a_job_that_holds_nothing_for_publishing_is_not_reported(self):
        with TempDir() as tmp:
            plain = PUBLISH.replace("PYPI_PUBLISH_TOKEN", "SOME_VALUE")
            self.assertEqual(of(check(tmp, job(SETUP_UV + plain))), [])

    def test_packages_write_on_any_trigger(self):
        for on in ("push", "workflow_dispatch", "schedule"):
            with self.subTest(on=on), TempDir() as tmp:
                text = job(GO + "      - run: make\n", on=on, top="permissions:\n  packages: write\n")
                found = of(check(tmp, text))
                self.assertEqual([(f.severity, f.kind) for f in found], [("medium", "capability-restores")])
                self.assertEqual(found[0].facts["capabilities"], ["packages: write"])

    def test_write_all_counts(self):
        with TempDir() as tmp:
            text = job(GO + "      - run: make\n", on="push", top="permissions: write-all\n")
            self.assertEqual(kinds(check(tmp, text)), [("medium", "capability-restores")])

    def test_a_publishing_action(self):
        with TempDir() as tmp:
            steps = GO + f"      - run: make site\n      - uses: actions/deploy-pages@{SHA}\n"
            found = of(check(tmp, job(steps, on="push")))
            self.assertEqual([(f.severity, f.kind) for f in found], [("medium", "capability-restores")])
            self.assertEqual(found[0].facts["capabilities"], ["uses actions/deploy-pages"])

    def test_an_image_build_that_cannot_push_is_not_counted(self):
        """docker/build-push-action is listed under publishing_actions, but with no push and no output
        that pushes it only builds; an image build with a GitHub Actions cache is common in jobs that
        publish nothing (zizmor's issue-642-repro.yml is one)."""
        builds = {
            "no push": "",
            "push false": "          push: false\n",
            "push False": "          push: False\n",
            "local output": "          outputs: type=docker\n",
        }
        for name, extra in builds.items():
            with self.subTest(build=name), TempDir() as tmp:
                step = (f"      - uses: docker/build-push-action@{SHA}\n        with:\n"
                        f"          cache-from: type=gha\n{extra}")
                self.assertEqual(of(check(tmp, job(step, on="push"))), [])

    def test_an_image_build_that_may_push_is_counted(self):
        """A build-push step with `push:` and no value may push: it counts as what publishing needs. One
        that pushes is an upload, so its job is a release job and gets the release job's finding."""
        with TempDir() as tmp:
            step = (f"      - uses: docker/build-push-action@{SHA}\n        with:\n"
                    "          cache-from: type=gha\n          push:\n")
            self.assertEqual(kinds(check(tmp, job(step, on="push"))), [("medium", "capability-restores")])
        pushes = {
            "push true": "          push: true\n",
            "push in upper case": "          PUSH: true\n",
            "registry output": "          outputs: type=registry\n",
            "image output that pushes": "          outputs: type=image,name=x,push=true\n",
            "output from an expression": "          outputs: ${{ inputs.out }}\n",
        }
        for name, extra in pushes.items():
            with self.subTest(build=name), TempDir() as tmp:
                step = (f"      - uses: docker/build-push-action@{SHA}\n        with:\n"
                        f"          cache-from: type=gha\n{extra}")
                self.assertEqual(kinds(check(tmp, job(step, on="push"))), [("high", "restores")])

    def test_an_image_build_with_inputs_written_as_one_expression_is_counted(self):
        with TempDir() as tmp:
            step = f"      - uses: docker/build-push-action@{SHA}\n        with: ${{{{ fromJSON(inputs.w) }}}}\n"
            found = of(check(tmp, job(step, on="push")))
            self.assertEqual([(f.severity, f.kind) for f in found], [("medium", "capability-restores")])

    def test_a_reference_that_can_read_every_secret(self):
        forms = {
            "toJSON": "${{ toJSON(secrets) }}",
            "computed": "${{ secrets[format('{0}_TOKEN', 'X')] }}",
        }
        for name, value in forms.items():
            with self.subTest(form=name), TempDir() as tmp:
                step = f"      - run: ./build.sh\n        env:\n          ALL: {value}\n"
                found = of(check(tmp, job(GO + step, on="push")))
                self.assertEqual([(f.severity, f.kind) for f in found], [("medium", "capability-restores")])
                self.assertEqual(len(found[0].facts["capabilities"]), 1)
                self.assertIn("every secret", found[0].facts["capabilities"][0])


class ContentsWriteTest(unittest.TestCase):
    """A token that can write contents can create a GitHub release and upload its assets. It counts in a
    job a release event, a tag push or a tag's creation can start; on other events it is too common
    (a job that commits back) to say the job may release."""

    CONTENTS = "    permissions:\n      contents: write\n"

    def found(self, on, extra=CONTENTS, steps=None):
        with TempDir() as tmp:
            return of(check(tmp, job(steps or (GO + "      - run: make\n"), on=on, job_extra=extra)))

    def test_counts_where_a_release_or_a_tag_can_start_the_job(self):
        starts = {
            "release": "release",
            "release with types": "\n  release:\n    types: [published]",
            "tag push": "\n  push:\n    tags: ['v*']",
            "tags-ignore": "\n  push:\n    tags-ignore: ['nightly']",
            "push with no filter": "push",
            "push in a list": "[push, pull_request]",
            "push with paths only": "\n  push:\n    paths: ['src/**']",
            "push with branches and tags": "\n  push:\n    branches: [main]\n    tags: ['v*']",
            "push with an odd key": "\n  push:\n    Branches: [main]",
            "create": "create",
        }
        for name, on in starts.items():
            with self.subTest(start=name):
                found = self.found(on)
                self.assertEqual([(f.severity, f.kind) for f in found], [("medium", "capability-restores")])
                self.assertTrue(found[0].facts["capabilities"][0].startswith("contents: write"),
                                found[0].facts)

    def test_not_where_no_release_or_tag_can_start_it(self):
        starts = {
            "branch push": "\n  push:\n    branches: [main]",
            "branches-ignore": "\n  push:\n    branches-ignore: [wip]",
            "pull request": "pull_request",
            "dispatch": "workflow_dispatch",
            "schedule": "\n  schedule:\n    - cron: '0 0 * * *'",
        }
        for name, on in starts.items():
            with self.subTest(start=name):
                self.assertEqual(self.found(on), [])

    def test_an_if_that_keeps_the_release_out(self):
        extra = self.CONTENTS + "    if: github.event_name == 'workflow_dispatch'\n"
        self.assertEqual(self.found("[release, workflow_dispatch]", extra=extra), [])

    def test_contents_read_or_undeclared_is_not_counted(self):
        self.assertEqual(self.found("release", extra="    permissions:\n      contents: read\n"), [])
        self.assertEqual(self.found("release", extra=""), [])


class ReleaseJobsAreUnchangedTest(unittest.TestCase):
    def test_a_release_job_gets_the_high_finding_and_not_this_one(self):
        with TempDir() as tmp:
            steps = SETUP_UV + PUBLISH.replace("uv build publish", "uv publish")
            self.assertEqual(kinds(check(tmp, job(steps))), [("high", "restores")])

    def test_a_declared_release_job_too(self):
        with TempDir() as tmp:
            extra = "    env:\n      OBAAF_LANE: release\n"
            self.assertEqual(kinds(check(tmp, job(SETUP_UV + PUBLISH, job_extra=extra))), [("high", "restores")])


class ImagePushesTest(unittest.TestCase):
    """Image pushes the release lane now reads as uploads (the review's sample of public workflows found
    both in one project's image workflow): build-push-action's or bake-action's outputs that push, a
    `docker build` whose `--output` pushes, and `docker buildx imagetools create`, which pushes a
    manifest list unless it is given `--dry-run`."""

    def lane(self, step, on="push"):
        with TempDir() as tmp:
            result = check(tmp, job(step, on=on, job_extra="    environment: ci\n"))
            return [(f.rule, f.kind) for f in result.findings
                    if f.rule in ("OBAAF-GHA-006", "OBAAF-GHA-016", "OBAAF-GHA-017")]

    def test_action_outputs_and_bake_set_that_push(self):
        steps = {
            "build-push registry": ("docker/build-push-action", "outputs: type=registry"),
            "build-push push=true": ("docker/build-push-action", "outputs: type=image,name=x,push=true"),
            "build-push push=TRUE": ("docker/build-push-action", "outputs: type=image,name=x,push=TRUE"),
            "build-push list": ("docker/build-push-action", "outputs: |\n            type=docker\n"
                                                             "            type=registry"),
            "bake set": ("docker/bake-action", "set: '*.output=type=registry'"),
            "bake set push": ("docker/bake-action", "set: '*.push=true'"),
        }
        for name, (action, extra) in steps.items():
            with self.subTest(step=name):
                step = f"      - uses: {action}@{SHA}\n        with:\n          {extra}\n"
                found = self.lane(step)
                self.assertIn(("OBAAF-GHA-016", "unchecked"), found)

    def test_action_outputs_that_do_not_push(self):
        for extra in ("outputs: type=docker", "outputs: type=image,name=x,push=false",
                      "outputs: type=local,dest=out", "set: '*.platform=linux/amd64'"):
            for action in ("docker/build-push-action", "docker/bake-action"):
                with self.subTest(step=extra, action=action):
                    step = f"      - uses: {action}@{SHA}\n        with:\n          {extra}\n"
                    self.assertNotIn(("OBAAF-GHA-016", "unchecked"), self.lane(step))

    def test_commands_that_push(self):
        commands = (
            "docker buildx build -o type=registry -t r/x .",
            "docker buildx build --output=type=image,push=true -t r/x .",
            "docker build --output type=registry .",
            "docker buildx bake --set '*.output=type=registry'",
            "docker buildx imagetools create -t r/x:1 r/x@sha256:a r/x@sha256:b",
            "docker buildx imagetools create --dry-run=false -t r/x:1 r/x@sha256:a",
        )
        for command in commands:
            with self.subTest(command=command):
                self.assertIn(("OBAAF-GHA-016", "unchecked"), self.lane(f"      - run: {command}\n"))

    def test_commands_that_do_not_push(self):
        commands = (
            "docker buildx build -o type=docker -t r/x .",
            "docker buildx build --output type=image,push=false .",
            "docker buildx imagetools create --dry-run -t r/x:1 r/x@sha256:a",
            "docker buildx imagetools create -t r/x:1 r/x@sha256:a --dry-run",
            "docker buildx imagetools inspect r/x:1",
        )
        for command in commands:
            with self.subTest(command=command):
                self.assertNotIn(("OBAAF-GHA-016", "unchecked"), self.lane(f"      - run: {command}\n"))


class ImageBuildsThatDoNotPushTest(unittest.TestCase):
    """The first review's false positives: image steps that push nothing are not release jobs. An
    expression counts only where it can give the output's type or a push, and a bake `set` only for an
    `output` or a `push`; in a command only `-o`/`--output` and bake's `--set` are read."""

    def lane(self, step):
        with TempDir() as tmp:
            result = check(tmp, job(step, on="pull_request", job_extra="    environment: ci\n"))
            return [(f.rule, f.kind) for f in result.findings if f.rule in ("OBAAF-GHA-016", "OBAAF-GHA-006")]

    def test_action_inputs(self):
        steps = {
            "docker output to a file": ("docker/build-push-action", "outputs: type=docker,dest=${{ runner.temp }}/img.tar"),
            "bake platform from a matrix": ("docker/bake-action", "set: '*.platform=${{ matrix.platforms }}'"),
            "bake docker output named by an expression": ("docker/bake-action",
                                                          "set: '*.output=type=docker,name=${{ env.TEST_IMAGE_ID }}'"),
            "bake registry cache": ("docker/bake-action", "set: '*.cache-to=type=registry,ref=ghcr.io/o/a:cache'"),
            "local output": ("docker/build-push-action", "outputs: type=local,dest=./pushdir"),
            "docker output named like a registry": ("docker/build-push-action",
                                                    "outputs: type=docker,name=myregistry.azurecr.io/x"),
        }
        for name, (action, extra) in steps.items():
            with self.subTest(step=name):
                step = f"      - uses: {action}@{SHA}\n        with:\n          {extra}\n"
                self.assertEqual(self.lane(step), [])

    def test_bake_overrides_from_a_written_out_matrix(self):
        """docker/buildx's own e2e workflow takes bake's `set` from the matrix: read through it."""
        def text(*overrides):
            include = "".join(f"          - overrides: '{o}'\n" for o in overrides) + "          - other: x\n"
            return ("on: pull_request\npermissions: {}\njobs:\n  bake:\n    runs-on: ubuntu-latest\n"
                    f"    environment: ci\n    strategy:\n      matrix:\n        include:\n{include}"
                    f"    steps:\n      - uses: docker/bake-action@{SHA}\n        with:\n"
                    "          set: ${{ matrix.overrides }}\n")
        with TempDir() as tmp:
            quiet = check(tmp, text("*.output=/tmp/bake-build", "t.output=type=local,dest=./dist"))
            self.assertEqual([f for f in quiet.findings if f.rule == "OBAAF-GHA-016"], [])
            loud = check(tmp, text("*.output=/tmp/bake-build", "t.output=type=registry"))
            self.assertEqual([f.kind for f in loud.findings if f.rule == "OBAAF-GHA-016"], ["unchecked"])

    def test_image_output_with_an_expression_may_push(self):
        step = (f"      - uses: docker/build-push-action@{SHA}\n        with:\n"
                "          outputs: type=image,name=${{ env.IMAGE }}\n")
        self.assertIn(("OBAAF-GHA-016", "unchecked"), self.lane(step))

    def test_commands(self):
        commands = (
            "docker buildx build --cache-from type=registry,ref=ghcr.io/o/a:cache -t a --load .",
            "docker buildx build --cache-to type=registry,ref=ghcr.io/o/a:cache -t a --load .",
            "docker buildx bake --set '*.cache-from=type=registry,ref=x'",
            "docker build --build-arg push=yes -t a .",
            "docker build -t a . && echo type=registry",
            "docker buildx build -o type=docker,dest=out.tar .",
        )
        for command in commands:
            with self.subTest(command=command):
                self.assertEqual(self.lane(f"      - run: {command}\n"), [])

    def test_the_new_command_pattern_costs_what_it_reads(self):
        """The image-output pattern looks at most 8,192 characters into a command, and reads each output's
        pieces up to a bound, so a long line costs about what the older `--push` pattern's does (slow
        patterns older than this slice are #179). The third review's chain of `-o,` took 132 s at 100 KB, and
        the fourth review's groups of `docker build` and `-o,` chains 12 s a search, and the fifth review's
        `${{ docker build -o ... }}` blocks 147 s a search."""
        import re
        import time
        from obaaf.catalog import load
        pattern = next(p for p in load().detection["upload_commands"] if "imagetools" not in p and "--output" in p)
        rx = re.compile(pattern, re.M)
        for line in ("docker build ; " * 16000, "docker build " * 10000, ("docker build --set a.b=" + "x" * 50 + " ") * 3000,
                     "docker build" + " -o," * 25000, "docker build" + " --output=," * 3000,
                     "docker build" + " -otype=image," * 2000, "docker build" + " --set=x.output=," * 2000,
                     "docker build -o " + "${{a}}" * 3000, "docker build '" + "a " * 20000,
                     (" docker build" + " -o," * 200 + ",") * 125, (" docker build" + " -o, x, x, x," * 60 + ",") * 125,
                     "docker build -o a " + ("${{ docker build -o " + "b" * 20 + " }}") * 2500):
            started = time.monotonic()
            rx.search(line)
            self.assertLess(time.monotonic() - started, 10)


class SecondReviewTest(unittest.TestCase):
    """The second review's ways past and false positives."""

    def lane(self, step, matrix=""):
        with TempDir() as tmp:
            result = check(tmp, job(step, on="pull_request", job_extra=f"    environment: ci\n{matrix}"))
            return [f.kind for f in result.findings if f.rule == "OBAAF-GHA-016"]

    def test_expressions_in_commands_are_read_as_in_inputs(self):
        for command in ("docker buildx build --output ${{ inputs.output }} .",
                        "docker buildx build -o type=${{ inputs.type }} .",
                        "docker buildx build -o type=image,name=${{ env.IMG }} .",
                        "docker buildx bake --set '*.output=${{ inputs.o }}'",
                        "docker buildx bake --set '*.${{ inputs.key }}=type=registry'"):
            with self.subTest(command=command):
                self.assertEqual(self.lane(f"      - run: {command}\n"), ["unchecked"])
        self.assertEqual(self.lane("      - run: docker buildx build -o type=docker,dest=${{ runner.temp }}/x .\n"), [])

    def test_bake_keys_set_when_the_job_runs_and_appended_outputs(self):
        for extra in ("set: '*.${{ matrix.k }}=${{ matrix.v }}'", "set: '*.${{ inputs.key }}=type=registry'",
                      "set: '${{ inputs.target }}.${{ inputs.key }}=true'", "set: '*.output+=type=registry'",
                      "set: 't.output+=type=image,push=true'"):
            with self.subTest(set=extra):
                step = f"      - uses: docker/bake-action@{SHA}\n        with:\n          {extra}\n"
                self.assertEqual(self.lane(step), ["unchecked"])
        for command in ("docker buildx bake --set '*.output+=type=registry'",
                        "docker buildx bake --set 't.output+=type=image,push=true'"):
            with self.subTest(command=command):
                self.assertEqual(self.lane(f"      - run: {command}\n"), ["unchecked"])

    def test_a_long_continued_command_still_pushes(self):
        labels = "".join(f"  --label l{n}=value{n} \\\n" for n in range(70))
        for end in ("--push .", "--output type=registry ."):
            with self.subTest(end=end):
                script = "".join(f"          {line}\n" for line in f"docker buildx build \\\n{labels}  {end}".splitlines())
                self.assertEqual(self.lane(f"      - run: |\n{script}"), ["unchecked"])

    def test_quoted_separators_and_spaced_expressions_in_commands(self):
        """The third review: a `;` or `&` in a quoted argument, and an expression with spaces before `type=`."""
        for command in ("docker buildx build --build-arg 'URL=https://x?a=1&b=2' -o type=registry .",
                        'docker buildx build --label "d=R&D tools" --output type=image,name=x,push=true .',
                        "docker buildx build --build-arg 'X=a;b' -o type=registry .",
                        'docker buildx build -o "name=${{ env.IMAGE }},type=registry" .',
                        "docker buildx build -o push=true,name=${{ env.IMAGE }},type=image ."):
            with self.subTest(command=command):
                self.assertEqual(self.lane(f"      - run: {command}\n"), ["unchecked"])

    def test_quoted_fields_and_trimmed_keys(self):
        for extra in ('outputs: type=image,name=x,"push=true"', 'outputs: name=x,"type=registry"',
                      "outputs: type=image, push=true"):
            with self.subTest(outputs=extra):
                step = f"      - uses: docker/build-push-action@{SHA}\n        with:\n          {extra}\n"
                self.assertEqual(self.lane(step), ["unchecked"])

    def test_false_positives(self):
        steps = {
            "build argument named push": (f"      - uses: docker/bake-action@{SHA}\n        with:\n"
                                           "          set: '*.args.PUSH=true'\n", ""),
            "--outputs is not --output": ("      - run: docker buildx build --outputs=type=registry .\n", ""),
        }
        for name, (step, matrix) in steps.items():
            with self.subTest(step=name):
                self.assertEqual(self.lane(step, matrix), [])

    def test_push_from_the_matrix(self):
        """`push` is read through the matrix like `outputs`, within `Job._matrix_values`' limits: a value YAML
        could read as other than text (`false`, quoted or not) is not read, so the step may push."""
        step = (f"      - uses: docker/build-push-action@{SHA}\n        with:\n          push: ${{{{ matrix.push }}}}\n")
        for listed in ("[false]", "['false']"):
            with self.subTest(listed=listed):
                self.assertEqual(self.lane(step, f"    strategy:\n      matrix:\n        push: {listed}\n"), ["unchecked"])

    def test_more_command_forms(self):
        for command in ("docker image build -o type=registry .", "docker builder build -o type=registry .",
                        "docker buildx b -o type=registry ."):
            with self.subTest(command=command):
                self.assertEqual(self.lane(f"      - run: {command}\n"), ["unchecked"])

    def test_a_step_named_like_a_read_local_action_is_not_taken_for_it(self):
        outer = ("runs:\n  using: composite\n  steps:\n    - name: Setup\n      uses: ./.github/actions/inner\n"
                 "    - name: Setup\n      uses: ./.github/actions/js\n")
        inner = "runs:\n  using: composite\n  steps:\n    - run: make\n      shell: bash\n"
        js = "runs:\n  using: node20\n  main: index.js\n"
        with TempDir() as tmp:
            extra = {".github/actions/outer/action.yml": outer, ".github/actions/inner/action.yml": inner,
                     ".github/actions/js/action.yml": js}
            found = of(check(tmp, job("      - uses: ./.github/actions/outer\n" + PUBLISH), extra=extra))
            self.assertEqual(sorted({f.kind for f in found}), ["capability-restores"])


class CallerGrantsTest(unittest.TestCase):
    """A called job that declares no permissions holds the token its callers grant (the first review)."""

    CALLED = ("on:\n  workflow_call:\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n"
              f"      - uses: actions/setup-go@{SHA}\n      - run: make\n")

    def found(self, grant, on="release"):
        caller = (f"on: {on}\n{grant}jobs:\n  ship:\n    uses: ./.github/workflows/build.yml\n")
        with TempDir() as tmp:
            result = check(tmp, caller, name="caller.yml", extra={".github/workflows/build.yml": self.CALLED})
            return [f for f in of(result) if f.job == "build"]

    def test_granted_write_scopes_count(self):
        grants = {
            "write-all": ("permissions: write-all\n", "packages: write, granted by"),
            "packages": ("permissions:\n  packages: write\n", "packages: write, granted by"),
            "contents": ("permissions:\n  contents: write\n", "contents: write, on"),
        }
        for name, (grant, said) in grants.items():
            with self.subTest(grant=name):
                found = self.found(grant)
                self.assertEqual([(f.severity, f.kind) for f in found], [("medium", "capability-restores")])
                self.assertTrue(any(c.startswith(said) for c in found[0].facts["capabilities"]), found[0].facts)
                self.assertTrue(any("caller.yml job 'ship'" in c for c in found[0].facts["capabilities"]))

    def test_a_caller_that_grants_no_write_scope_or_declares_nothing(self):
        self.assertEqual(self.found("permissions:\n  contents: read\n"), [])
        self.assertEqual(self.found(""), [])


class WorkflowCallTest(unittest.TestCase):
    def test_contents_write_in_a_workflow_only_another_workflow_calls(self):
        """`workflow_call` stands for a calling workflow's event, which may be a release."""
        text = ("on:\n  workflow_call:\njobs:\n  publish:\n    runs-on: ubuntu-latest\n"
                f"    permissions:\n      contents: write\n    steps:\n{GO}      - run: make\n")
        with TempDir() as tmp:
            found = of(check(tmp, text))
            self.assertEqual([(f.severity, f.kind) for f in found], [("medium", "capability-restores")])
            self.assertEqual(found[0].facts["capabilities"], ["contents: write, on a call from another workflow"])


class ReleaseCaseAnswersTheCapabilityCaseTest(unittest.TestCase):
    """Where a local action's steps make the job a release job, its release case answers the first
    pass's "cannot tell whether it releases" (the first review found both on one step)."""

    ACTION = "runs:\n  using: composite\n  steps:\n    - run: uv publish\n      shell: bash\n"

    def test_one_finding_on_the_step(self):
        with TempDir() as tmp:
            steps = SETUP_UV + "      - uses: ./.github/actions/publish\n        env:\n" \
                "          UV_PUBLISH_TOKEN: ${{ secrets.PYPI_PUBLISH_TOKEN }}\n"
            found = of(check(tmp, job(steps), extra={".github/actions/publish/action.yml": self.ACTION}))
            self.assertEqual(sorted((f.severity, f.kind) for f in found), [("high", "restores")])

    def test_the_same_for_obaaf_gha_015(self):
        action = "runs:\n  using: composite\n  steps:\n    - run: npm publish\n      shell: bash\n"
        text = ("on: pull_request_target\npermissions: {}\njobs:\n  publish:\n    runs-on: ubuntu-latest\n"
                "    steps:\n      - uses: ./.github/actions/publish\n        env:\n"
                "          NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}\n")
        with TempDir() as tmp:
            found = of(check(tmp, text, extra={".github/actions/publish/action.yml": action}), "OBAAF-GHA-015")
            self.assertEqual([f.kind for f in found], [""])

    def test_a_local_action_with_no_cache_step_is_not_a_cache_step(self):
        action = "runs:\n  using: composite\n  steps:\n    - run: make\n      shell: bash\n"
        with TempDir() as tmp:
            steps = "      - uses: ./.github/actions/build\n" + PUBLISH
            self.assertEqual(of(check(tmp, job(steps), extra={".github/actions/build/action.yml": action})), [])

    def test_a_nested_local_action_with_no_cache_step(self):
        outer = "runs:\n  using: composite\n  steps:\n    - uses: ./.github/actions/inner\n"
        inner = "runs:\n  using: composite\n  steps:\n    - run: make\n      shell: bash\n"
        with TempDir() as tmp:
            steps = "      - uses: ./.github/actions/outer\n" + PUBLISH
            extra = {".github/actions/outer/action.yml": outer, ".github/actions/inner/action.yml": inner}
            self.assertEqual(of(check(tmp, job(steps), extra=extra)), [])

    def test_a_local_action_that_is_not_composite_is_taken_to_restore(self):
        action = "runs:\n  using: node20\n  main: index.js\n"
        with TempDir() as tmp:
            steps = "      - uses: ./.github/actions/js\n" + PUBLISH
            found = of(check(tmp, job(steps), extra={".github/actions/js/action.yml": action}))
            self.assertEqual([(f.severity, f.kind) for f in found], [("medium", "capability-restores")])


class SelfHostedTest(unittest.TestCase):
    def test_self_hosted_has_its_own_kind(self):
        with TempDir() as tmp:
            text = job(SETUP_UV + PUBLISH).replace("runs-on: ubuntu-latest", "runs-on: [self-hosted, linux]")
            found = of(check(tmp, text))
            self.assertEqual([(f.severity, f.kind) for f in found], [("medium", "capability-restores-self-hosted")])
            self.assertIn("self-hosted", found[0].message)


class NeededJobsTest(unittest.TestCase):
    """A job that may publish and downloads what a job it needs built, where that job restores a cache,
    as OBAAF-GHA-006 reports for a release job (`needed-job-restores`)."""

    def workflow(self, download=True, mode=""):
        get = f"      - uses: actions/download-artifact@{SHA}\n" if download else ""
        return ("on: release\npermissions: {}\njobs:\n"
                f"  build:\n    runs-on: ubuntu-latest\n{mode}    steps:\n{SETUP_UV}      - run: uv build\n"
                "  publish:\n    needs: build\n    runs-on: ubuntu-latest\n    steps:\n"
                f"{get}{PUBLISH}")

    def test_reported(self):
        with TempDir() as tmp:
            found = of(check(tmp, self.workflow()))
            self.assertEqual([(f.severity, f.kind, f.job) for f in found],
                             [("medium", "capability-needed-job-restores", "publish")])
            self.assertEqual(found[0].facts["jobs"], ["build"])
            self.assertEqual(found[0].facts["capabilities"], ["secret PYPI_PUBLISH_TOKEN"])

    def test_not_without_a_download_or_when_the_needed_job_forbids_restoring(self):
        with TempDir() as tmp:
            self.assertEqual(of(check(tmp, self.workflow(download=False))), [])
            self.assertEqual(of(check(tmp, self.workflow(mode="    cache-mode: none\n"))), [])


class CallingJobTest(unittest.TestCase):
    """A job that calls a workflow of the repository is read for the jobs it needs, as a release job is:
    what the called jobs download counts as its download (slice 2d.4b3b)."""

    CALLED = ("on:\n  workflow_call:\npermissions: {}\njobs:\n  s:\n    runs-on: ubuntu-latest\n    steps:\n"
              f"      - uses: actions/download-artifact@{SHA}\n      - run: ./ship.sh\n")

    def workflow(self, secrets):
        return ("on: push\npermissions: {}\njobs:\n"
                f"  build:\n    runs-on: ubuntu-latest\n    steps:\n{SETUP_UV}      - run: uv build\n"
                f"  ship:\n    needs: build\n    uses: ./.github/workflows/ship.yml\n{secrets}")

    def test_passing_every_secret_after_a_job_that_restores(self):
        with TempDir() as tmp:
            result = check(tmp, self.workflow("    secrets: inherit\n"),
                           extra={".github/workflows/ship.yml": self.CALLED})
            found = [f for f in of(result) if f.job == "ship"]
            self.assertEqual([(f.severity, f.kind) for f in found], [("medium", "capability-needed-job-restores")])
            self.assertIn("every secret", found[0].facts["capabilities"][0])

    def test_passing_a_publishing_secret_by_name(self):
        with TempDir() as tmp:
            passed = "    secrets:\n      token: ${{ secrets.PYPI_TOKEN }}\n"
            result = check(tmp, self.workflow(passed), extra={".github/workflows/ship.yml": self.CALLED})
            found = [f for f in of(result) if f.job == "ship"]
            self.assertEqual([(f.kind, f.facts["capabilities"]) for f in found],
                             [("capability-needed-job-restores", ["secret PYPI_TOKEN"])])

    def test_passing_nothing_for_publishing(self):
        with TempDir() as tmp:
            result = check(tmp, self.workflow(""), extra={".github/workflows/ship.yml": self.CALLED})
            self.assertEqual(of(result), [])


class LocalActionTest(unittest.TestCase):
    def test_a_cache_inside_a_local_composite_action(self):
        action = ("runs:\n  using: composite\n  steps:\n"
                  f"    - uses: astral-sh/setup-uv@{SHA}\n")
        with TempDir() as tmp:
            steps = "      - uses: ./.github/actions/setup\n" + PUBLISH
            found = of(check(tmp, job(steps), extra={".github/actions/setup/action.yml": action}))
            self.assertEqual(sorted({f.kind for f in found}), ["capability-restores"])
            self.assertTrue(all(f.severity == "medium" for f in found))


if __name__ == "__main__":
    unittest.main()
