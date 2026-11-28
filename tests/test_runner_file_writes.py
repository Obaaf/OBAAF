"""Flagship slice 2d.26, from #232: OBAAF-GHA-028, an outsider's text written to GITHUB_ENV or GITHUB_PATH.

OBAAF-GHA-010 reports a `${{ }}` expression of an outsider-written field inside a script, and its fix is to pass the
text through an environment variable and read it quoted. Before this slice, a script that then wrote that variable
to GITHUB_ENV or GITHUB_PATH got no finding at all (#232's workflow: 0 findings, exit 0). The runner reads every line
of GITHUB_ENV into every later step as a variable, and every line of GITHUB_PATH as a folder to put first on PATH,
so a line break in the text sets `BASH_ENV`, `LD_PRELOAD` and the rest. zizmor's `github-env` and Octoscan's
`dangerous-write` report it.
"""

import time
import unittest

from helpers import TempDir

from obaaf import checker
from obaaf.checker import rules

BODY = "${{ github.event.pull_request.body }}"
TITLE = "${{ github.event.pull_request.title }}"


def check(text):
    with TempDir() as tmp:
        root = tmp / "repo"
        (root / ".github" / "workflows").mkdir(parents=True)
        (root / ".github" / "CODEOWNERS").write_text("* @example/maintainers\n", encoding="utf-8")
        (root / ".github" / "workflows" / "wf.yml").write_text(text, encoding="utf-8")
        return checker.check(root)


def job(script, on="pull_request_target", env=f"BODY: {BODY}", shell="", uses=None, with_=None, job_env=""):
    lines = "".join(f"          {line}\n" for line in script.splitlines())
    env_block = "".join(f"          {pair}\n" for pair in env.splitlines() if pair)
    step = "      - name: Save\n"
    if env_block:
        step += f"        env:\n{env_block}"
    if uses:
        step += f"        uses: {uses}\n        with:\n" + "".join(
            f"          {k}: |\n" + "".join(f"            {line}\n" for line in v.splitlines())
            for k, v in (with_ or {}).items())
    else:
        if shell:
            step += f"        shell: {shell}\n"
        step += f"        run: |\n{lines}"
    jenv = "".join(f"      {pair}\n" for pair in job_env.splitlines() if pair)
    return (f"on: {on}\npermissions:\n  contents: read\njobs:\n  label:\n    runs-on: ubuntu-latest\n"
            + (f"    env:\n{jenv}" if jenv else "")
            + f"    steps:\n{step}      - name: Use it\n        run: echo done\n")


def gha028(result):
    return [f for f in result.findings if f.rule == "OBAAF-GHA-028"]


class TheIssueTest(unittest.TestCase):
    def test_issue_232s_workflow(self):
        text = ("on:\n  pull_request_target:\npermissions:\n  contents: read\njobs:\n  label:\n"
                "    runs-on: ubuntu-latest\n    steps:\n      - name: Save the body\n        env:\n"
                f"          BODY: {BODY}\n        run: echo \"PR_BODY=$BODY\" >> \"$GITHUB_ENV\"\n"
                "      - name: Use it\n        run: echo \"$PR_BODY\"\n")
        result = check(text)
        self.assertEqual([(f.rule, f.severity, f.kind) for f in result.findings],
                         [("OBAAF-GHA-028", "high", "")], [f.message for f in result.findings])
        (found,) = result.findings
        self.assertEqual(found.message, "Step 'Save the body' writes $BODY to GITHUB_ENV, and that text holds "
                                        "github.event.pull_request.body.")
        self.assertEqual(found.facts["references"], ["$BODY"])
        self.assertEqual(found.facts["files"], ["GITHUB_ENV"])
        self.assertEqual(found.facts["fields"], ["github.event.pull_request.body"])

    def test_the_path_and_the_title(self):
        (found,) = gha028(check(job('echo "$BODY" >> "$GITHUB_PATH"')))
        self.assertEqual((found.severity, found.facts["files"]), ("high", ["GITHUB_PATH"]))
        (found,) = gha028(check(job('echo "T=$TITLE" >> "$GITHUB_ENV"', env=f"TITLE: {TITLE}")))
        self.assertEqual(found.facts["fields"], ["github.event.pull_request.title"])


class WrittenTest(unittest.TestCase):
    """Every way below writes the text, and is high on `pull_request_target`."""

    CASES = {
        "plain redirect": 'echo "PR_BODY=$BODY" >>$GITHUB_ENV',
        "braced target": 'echo "PR_BODY=${BODY}" >> "${GITHUB_ENV}"',
        "default target": 'echo "PR_BODY=$BODY" >> "${GITHUB_ENV:-/dev/stdout}"',
        "expression target": 'echo "PR_BODY=$BODY" >> ${{ github.env }}',
        "tee": 'echo "PR_BODY=$BODY" | tee -a "$GITHUB_ENV"',
        "tee of a context": 'echo "$BODY" | tee -a "${{ github.path }}"',
        "printf": 'printf "PR_BODY=%s\\n" "$BODY" >> "$GITHUB_ENV"',
        "heredoc": 'cat >> "$GITHUB_ENV" <<EOF\nPR_BODY=$BODY\nEOF',
        "multi-line form": '{\n  echo "PR_BODY<<EOF"\n  echo "$BODY"\n  echo "EOF"\n} >> "$GITHUB_ENV"',
        "parameter expansion": 'echo "X=${BODY//a/b}" >> "$GITHUB_ENV"',
        "a copy": 'T="$BODY"\necho "X=$T" >> "$GITHUB_ENV"',
        "a copy of a copy": 'A="$BODY"\nB="pre-$A"\necho "X=$B" >> "$GITHUB_ENV"',
        "export": 'export T="$BODY"\necho "X=$T" >> "$GITHUB_ENV"',
        "local in a function": 'f() { local t="$BODY"; echo "X=$t" >> "$GITHUB_ENV"; }\nf',
        "for": 'for t in $BODY; do echo "X=$t" >> "$GITHUB_ENV"; done',
        "every variable": 'env >> "$GITHUB_ENV"',
        "every variable, export -p": 'export -p >> "$GITHUB_ENV"',
        "python reads it": 'python3 -c \'import os; print("X=" + os.environ["BODY"])\' >> "$GITHUB_ENV"',
        "in an if": 'if [ -n "$BODY" ]; then echo "X=$BODY" >> "$GITHUB_ENV"; fi',
    }

    def test_each_way(self):
        for name, script in self.CASES.items():
            with self.subTest(name):
                found = gha028(check(job(script)))
                self.assertEqual([(f.severity, f.kind) for f in found], [("high", "")],
                                 [(f.kind, f.message) for f in found])

    def test_the_job_s_and_the_workflow_s_env(self):
        found = gha028(check(job('echo "X=$BODY" >> "$GITHUB_ENV"', env="", job_env=f"BODY: {BODY}")))
        self.assertEqual([f.severity for f in found], ["high"])
        text = job('echo "X=$B" >> "$GITHUB_ENV"', env="B: ${{ env.A }}").replace(
            "permissions:", f"env:\n  A: {BODY}\npermissions:", 1)
        self.assertEqual([f.severity for f in gha028(check(text))], ["high"])

    def test_an_env_written_as_one_expression_holds_every_name(self):
        text = job('echo "X=$ANYTHING" >> "$GITHUB_ENV"', env="").replace(
            "      - name: Save\n", "      - name: Save\n        env: ${{ fromJSON(github.event.pull_request.body) }}\n")
        self.assertEqual([f.severity for f in gha028(check(text))], ["high"])


class SeverityTest(unittest.TestCase):
    def test_as_obaaf_gha_010_gives_the_triggers(self):
        script = 'echo "X=$BODY" >> "$GITHUB_ENV"'
        for on, severity in (("pull_request_target", "high"), ("pull_request", "high"), ("issue_comment", "high"),
                             ("workflow_call", "high"), ("workflow_dispatch", "medium"), ("push", "medium")):
            with self.subTest(on):
                self.assertEqual([f.severity for f in gha028(check(job(script, on=on)))], [severity])

    def test_a_commit_s_text_on_push_is_high(self):
        script = 'echo "X=$MSG" >> "$GITHUB_ENV"'
        found = gha028(check(job(script, on="push", env="MSG: ${{ github.event.head_commit.message }}")))
        self.assertEqual([f.severity for f in found], ["high"])


class UnresolvedTest(unittest.TestCase):
    """Where the text written could still be the outsider's: "cannot tell", at medium, on any trigger."""

    CASES = {
        "a repository script": "./scripts/version.sh >> \"$GITHUB_ENV\"",
        "envsubst": "envsubst < template.env >> \"$GITHUB_ENV\"",
        "exec": "exec >> \"$GITHUB_ENV\"\necho A=1",
        "a group with a program": "{ echo A=1; ./scripts/more.sh; } >> \"$GITHUB_ENV\"",
        "a path in a variable": "F=\"$GITHUB_ENV\"\necho A=1 >> \"$F\"",
        "a file the script wrote": "echo \"$BODY\" > body.txt\ncat body.txt >> \"$GITHUB_ENV\"",
        "the runner's folder": "echo A=1 >> \"$(dirname \"$GITHUB_OUTPUT\")/set_env_x\"",
        "an unread script": "echo \"A=1 >> $GITHUB_ENV",
        "a computed command": "$CMD >> \"$GITHUB_ENV\"",
        "a function's argument": 'f() { echo "X=$1" >> "$GITHUB_ENV"; }\nf "$BODY"',
        "read": 'read -r t <<< "$BODY"\necho "X=$t" >> "$GITHUB_ENV"',
        "printf -v": 'printf -v t "%s" "$BODY"\necho "X=$t" >> "$GITHUB_ENV"',
        "eval": 'eval "t=$BODY"\necho "X=$u" >> "$GITHUB_ENV"',
        "a pipeline": 'echo "$BODY" | tr -d "\\r" | sed "s/^/X=/" >> "$GITHUB_ENV"',
        "a command substitution": 'echo "X=$(echo "$BODY" | head -1)" >> "$GITHUB_ENV"',
        "indirect": 'n=BODY\necho "X=${!n}" >> "$GITHUB_ENV"',
        "a here-string to jq": 'jq -r .x <<< "$BODY" >> "$GITHUB_ENV"',
        "git": 'git rev-parse --short HEAD | sed "s/^/SHA=/" >> "$GITHUB_ENV"',
        "a file named like the variable": 'cat body.txt >> "$GITHUB_ENV"',
    }

    def test_each_way(self):
        for name, script in self.CASES.items():
            with self.subTest(name):
                found = gha028(check(job(script)))
                self.assertEqual([(f.severity, f.kind) for f in found], [("medium", "unresolved")],
                                 [(f.kind, f.message) for f in found])

    def test_pwsh_and_python(self):
        for shell, script in (("pwsh", '"X=$env:BODY" >> $env:GITHUB_ENV'),
                              ("python", "import os\nopen(os.environ['GITHUB_ENV'], 'a').write('X=1')")):
            with self.subTest(shell):
                found = gha028(check(job(script, shell=shell)))
                self.assertEqual([(f.severity, f.kind) for f in found], [("medium", "unresolved")])

    def test_github_script(self):
        script = "core.exportVariable('T', context.payload.pull_request.title)"
        found = gha028(check(job("", env="", uses="actions/github-script@" + "1" * 40, with_={"script": script})))
        self.assertEqual([(f.severity, f.kind) for f in found], [("medium", "unresolved")])
        self.assertIn("the event's payload", found[0].message)
        quiet = "core.exportVariable('T', 'release')"
        self.assertEqual(gha028(check(job("", env="", uses="actions/github-script@" + "1" * 40,
                                          with_={"script": quiet}))), [])

    def test_the_script_is_a_fact(self):
        one = gha028(check(job("./a.sh >> \"$GITHUB_ENV\"")))[0]
        two = gha028(check(job("./b.sh >> \"$GITHUB_ENV\"")))[0]
        self.assertNotEqual(one.facts["script"], two.facts["script"])


class QuietTest(unittest.TestCase):
    """What gets no finding: nothing an outsider writes reaches the files."""

    CASES = {
        "a plain value": 'echo "IS_BUG=true" >> "$GITHUB_ENV"',
        "the text read, a plain value written": (
            'if echo "$BODY" | grep -q bug; then echo "IS_BUG=true" >> "$GITHUB_ENV"; fi'),
        "a quoted here-document": "cat >> \"$GITHUB_ENV\" <<'EOF'\nX=$BODY\nEOF",
        "another variable": 'echo "SHA=$GITHUB_SHA" >> "$GITHUB_ENV"',
        "an output": 'echo "body=$BODY" >> "$GITHUB_OUTPUT"',
        "the summary": 'echo "$BODY" >> "$GITHUB_STEP_SUMMARY"',
        "a loop of plain values": 'for f in a b; do echo "$f=1"; done >> "$GITHUB_ENV"',
        "a group of plain values": '{ echo A=1; echo "B=$GITHUB_SHA"; } >> "$GITHUB_ENV"',
    }

    def test_each_way(self):
        for name, script in self.CASES.items():
            with self.subTest(name):
                found = gha028(check(job(script)))
                self.assertEqual(found, [], [(f.kind, f.message) for f in found])

    def test_no_outsider_text_in_the_environment(self):
        for script in ('./scripts/version.sh >> "$GITHUB_ENV"', 'env >> "$GITHUB_ENV"', 'echo "X=$A" >> "$GITHUB_ENV"'):
            with self.subTest(script):
                self.assertEqual(gha028(check(job(script, env="A: plain"))), [])

    def test_an_expression_in_the_script_is_obaaf_gha_010s(self):
        result = check(job(f'echo "X={BODY}" >> "$GITHUB_ENV"', env=""))
        self.assertEqual(sorted(f.rule for f in result.findings), ["OBAAF-GHA-010"])


class FirstReviewTest(unittest.TestCase):
    """The first review of slice 2d.26 (8073f1a): ways past, false highs and costs, each now a case."""

    def outcome(self, script, env=f"BODY: {BODY}", **kwargs):
        return [(f.severity, f.kind) for f in gha028(check(job(script, env=env, **kwargs)))]

    def test_ways_past_are_reported(self):
        high = [("high", "")]
        unread = [("medium", "unresolved")]
        cases = {
            'ARGS=("$BODY")\necho "T=${ARGS[0]}" >> "$GITHUB_ENV"': high,
            'declare -a arr=("$BODY")\necho "T=${arr[0]}" >> "$GITHUB_ENV"': high,
            'export "V=$BODY"\necho "X=$V" >> "$GITHUB_ENV"': high,
            'local "v=$BODY"; echo "X=$v" >> "$GITHUB_ENV"': high,
            'until echo "X=$BODY"; do :; done >> "$GITHUB_ENV"': high,
            'cat /proc/self/environ >> "$GITHUB_ENV"': high,
            'v=$(printenv BODY)\necho "X=$v" >> "$GITHUB_ENV"': unread,
            'get() { echo "$BODY"; }\nT=$(get)\necho "T=$T" >> "$GITHUB_ENV"': unread,
            'n=v; declare "$n=$BODY"\necho "X=$v" >> "$GITHUB_ENV"': unread,
            'setvar() { declare -g "$1=$2"; }\nsetvar COPY "$BODY"\necho "X=$COPY" >> "$GITHUB_ENV"': unread,
            'if [[ "$BODY" =~ ^\\[(.*)\\] ]]; then echo "S=${BASH_REMATCH[1]}" >> "$GITHUB_ENV"; fi': unread,
            'echo "$BODY" > f.txt\nv=$(cat f.txt)\necho "X=$v" >> "$GITHUB_ENV"': unread,
            'echo "$BODY" | sed "s/x/y/" > body.txt\ncat body.txt >> "$GITHUB_ENV"': unread,
            'echo() { printenv BODY; }\necho >> "$GITHUB_ENV"': unread,
            'echo env | sed "s/.*/&/e" >> "$GITHUB_ENV"': unread,
            'echo "X=$BODY" >> "$GITHUB_ENV_FILE"': unread,
        }
        for script, expected in cases.items():
            with self.subTest(script):
                self.assertEqual(self.outcome(script), expected)

    def test_the_event_file(self):
        script = 'B=$(jq -r .pull_request.body "$GITHUB_EVENT_PATH")\necho "PR_BODY=$B" >> "$GITHUB_ENV"'
        self.assertEqual(self.outcome(script, env=""), [("medium", "unresolved")])
        self.assertEqual(self.outcome('echo "A=1" >> "$GITHUB_ENV"\ncat "$GITHUB_EVENT_PATH"', env=""), [])

    def test_the_file_s_path_in_env(self):
        found = gha028(check(job('echo "X=$BODY" >> "$OUT"', env=f"BODY: {BODY}\nOUT: ${{{{ github.env }}}}")))
        self.assertEqual([(f.severity, f.kind) for f in found], [("medium", "unresolved")])

    def test_no_false_high(self):
        cases = {
            'if [ -z "$BODY" ]; then echo "BODY=main" >> "$GITHUB_ENV"; fi': [],
            'grep -q "$BODY" < "$GITHUB_ENV" && echo found': [],
            'echo "SHA=${GITHUB_SHA::7}" >> "$GITHUB_ENV"': [],
            'echo "$HOME/.local/bin" >> "$GITHUB_PATH"': [],
            'V=1.2\nW="v$V"\necho "VERSION=$W" >> "$GITHUB_ENV"': [],
            'add_env() { echo "$1=$2" >> "$GITHUB_ENV"; }\nadd_env SKIP true\n[ -n "$BODY" ]': [("medium", "unresolved")],
            ('for y in 1; do echo "Body is: $BODY"; for f in dist/*; do if [ -s "$f" ]; then echo "HAS_$(basename "$f")=1";'
             ' fi\ndone >> "$GITHUB_ENV"; done'): [("medium", "unresolved")],
            'title=fixed\necho "T=$title" >> "$GITHUB_ENV"': [],
        }
        for script, expected in cases.items():
            with self.subTest(script):
                self.assertEqual(self.outcome(script), expected)

    def test_an_acceptance_names_the_script(self):
        one = gha028(check(job('S=$(echo "$BODY" | tr -cd a-z)\necho "S=$S" >> "$GITHUB_ENV"\necho "X=$BODY" >> "$GITHUB_ENV"')))
        two = gha028(check(job('S="$BODY"\necho "S=$S" >> "$GITHUB_ENV"\necho "X=$BODY" >> "$GITHUB_ENV"')))
        self.assertNotEqual(one[0].facts["script"], two[0].facts["script"])


class SecondReviewTest(unittest.TestCase):
    """The second review of slice 2d.26 (b27fee9): each case now a test."""

    def outcome(self, script, env=f"BODY: {BODY}", **kwargs):
        return [(f.severity, f.kind) for f in gha028(check(job(script, env=env, **kwargs)))]

    def test_not_silent(self):
        high = [("high", "")]
        unread = [("medium", "unresolved")]
        cases = {
            'FILES=()\necho "PR_BODY=$BODY" >> "$GITHUB_ENV"': high,
            'ARGS=()\nARGS+=("$BODY")\necho "ARGS=${ARGS[*]}" >> "$GITHUB_ENV"': high,
            'ARGS=(\n"--body"\n"$BODY"\n)\necho "ARGS=${ARGS[*]}" >> "$GITHUB_ENV"': unread,
            'cat >> "$GITHUB_ENV" <<EOT\nX=\\\\$BODY\nEOT': high,
            'echo | cat <<< "X=$BODY" >> "$GITHUB_ENV"': high,
            'echo A=1 | tee -a "$GITHUB_ENV" <<< "X=$BODY"': high,
            'echo "$BODY" > t.txt\necho A=1 | cat < t.txt >> "$GITHUB_ENV"': unread,
            "cat() { printenv BODY; }\ncat >> \"$GITHUB_ENV\" <<'EOT'\nA=1\nEOT": unread,
            './echo "A=1" >> "$GITHUB_ENV"': unread,
            ': "${RUNNER_X:=$BODY}"\necho "X=$RUNNER_X" >> "$GITHUB_ENV"': high,
            '{ [ "$BODY" -eq 1 ] || echo A=1; } &>> "$GITHUB_ENV"': unread,
            "trap 'printenv BODY' DEBUG\n{ echo A=1; } >> \"$GITHUB_ENV\"": unread,
            'set -x\n{ echo A=1; } >> "$GITHUB_ENV" 2>&1': unread,
            "{\necho \"X=$BODY\"\n'{' 2>/dev/null || true\n} >> \"$GITHUB_ENV\"": high,
            'for f in "$RUNNER_TEMP"/_runner_file_comm*/set_env_*; do echo "X=$BODY" >> "$f"; done': unread,
        }
        for script, expected in cases.items():
            with self.subTest(script):
                self.assertEqual(self.outcome(script), expected)

    def test_the_event_file_by_its_path(self):
        script = "jq -r '\"T=\" + .pull_request.title' \"$RUNNER_TEMP/_github_workflow/event.json\" >> \"$GITHUB_ENV\""
        self.assertEqual(self.outcome(script, env=""), [("medium", "unresolved")])

    def test_no_false_high_from_a_name_in_literal_text(self):
        for script in ('git rev-parse --abbrev-ref HEAD | sed "s/^/BODY=/" >> "$GITHUB_ENV"',
                       "jq -r '\"BODY=\" + .title' meta.json >> \"$GITHUB_ENV\"",
                       "python3 -c 'print(\"BODY=fixed\")' >> \"$GITHUB_ENV\""):
            with self.subTest(script):
                self.assertEqual(self.outcome(script), [("medium", "unresolved")])
        script = "python3 -c 'import os; print(os.environ[\"BODY\"])' >> \"$GITHUB_ENV\""
        self.assertEqual(self.outcome(script), [("high", "")])

    def test_clean_writes_stay_clean(self):
        for script in ('shopt -s nullglob\necho "A=1" >> "$GITHUB_ENV"',
                       'echo "SHA=${{ github.sha }}" >> "$GITHUB_ENV"',
                       'echo "${{ github.workspace }}/bin" >> "$GITHUB_PATH"',
                       'for f in a.txt; do\n  case "$f" in\n    *.txt) echo "T=1" ;;\n  esac\ndone >> "$GITHUB_ENV"'):
            with self.subTest(script):
                self.assertEqual(self.outcome(script), [])

    def test_nested_groups_and_many_steps_cost_little(self):
        nested = "\n".join(["for x in a; do"] * 8000 + ['done >> "$GITHUB_ENV"'] * 8000)
        started = time.monotonic()
        rules._runner_file_writes(nested, frozenset({"BODY"}))
        self.assertLess(time.monotonic() - started, 5)
        steps = "".join(f"      - name: s{n}\n        env:\n          BODY: {BODY}\n"
                        f"        run: echo \"A=1\" >> \"$GITHUB_ENV\"\n" for n in range(1500))
        text = "on: pull_request_target\npermissions:\n  contents: read\njobs:\n  a:\n    runs-on: ubuntu-latest\n" \
               "    steps:\n" + steps
        started = time.monotonic()
        check(text)
        self.assertLess(time.monotonic() - started, 20)


class CostTest(unittest.TestCase):
    def test_many_names_and_many_writes(self):
        # The first review: 1,000 copies and 1,000 writes took 45.7 s; 10,000 redirected loops 16.1 s.
        script = "\n".join([f'V{n}="$BODY"' for n in range(1000)] + ['echo "A=1" >> "$GITHUB_ENV"'] * 1000)
        started = time.monotonic()
        rules._runner_file_writes(script, frozenset({"BODY"}))
        loops = "\n".join(["for x in a; do echo \"A=$x\"; done >> \"$GITHUB_ENV\""] * 10000)
        rules._runner_file_writes(loops, frozenset({"BODY"}))
        self.assertLess(time.monotonic() - started, 10)

    def test_a_long_chain_of_copies_is_read_in_linear_time(self):
        # Each line copies the one after it, so a reading that repeats rounds would take one per line.
        lines = [f'V{n}="$V{n + 1}"' for n in range(4000)] + ['V4000="$BODY"', 'echo "X=$V0" >> "$GITHUB_ENV"']
        started = time.monotonic()
        found = rules._runner_file_writes("\n".join(lines), frozenset({"BODY"}))
        self.assertLess(time.monotonic() - started, 10)
        self.assertEqual(found.state, "written")


if __name__ == "__main__":
    unittest.main()
