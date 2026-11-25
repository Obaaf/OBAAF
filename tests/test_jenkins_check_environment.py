"""The review of pull request #365 (#344): a check counts for OBAAF-JEN-010, 011 and 012 only when nothing around it
changes the program its shell runs.

Before the review the shell reader stopped at an `export` inside the check's own script, but a `withEnv` entry, an
`environment { }` block or `env.PATH = ...` in a script changed nothing, so `withEnv(["PATH+X=${env.WORKSPACE}/x"])`
around `obaaf verify release` made all three rules pass, whatever `x` held. The names are those the GitHub rules read
since slice 2d.13 (`obaaf.checker.rules.steers`). Each case is a Jenkinsfile and what OBAAF-JEN-010, 011 and 012 say:
"pass", "unknown" (cannot tell) or "finding-high" / "finding-medium".
"""
import textwrap
import unittest

from obaaf.catalog import load
from obaaf.checker import jenkins

RULES = ("OBAAF-JEN-010", "OBAAF-JEN-011", "OBAAF-JEN-012")
CHECK = "obaaf verify release --policy p.yaml --artifacts dist --approvals a.json --repo-dir . --source-revision {rev}"
REV = "0123456789abcdef0123456789abcdef01234567"


def pipeline(verify: str, *, top: str = "", build: str = "sh 'make'", verify_env: str = "") -> str:
    """A pipeline that copies artifacts by a reference that moves, checks them, then publishes."""
    return textwrap.dedent("""\
        pipeline {{
          agent any
          {top}
          stages {{
            stage('Fetch') {{
              steps {{
                copyArtifacts(projectName: 'build', selector: lastSuccessful(), filter: 'dist/**')
                {build}
              }}
            }}
            stage('Verify') {{
              {verify_env}
              steps {{
                {verify}
              }}
            }}
            stage('Publish') {{
              steps {{
                sh './scripts/publish.sh dist'
              }}
            }}
          }}
        }}
        """).format(top=top, build=build, verify=verify, verify_env=verify_env)


PLAIN = f"sh '{CHECK.format(rev=REV)}'"


def wrapped(entries: str) -> str:
    return f"withEnv({entries}) {{ {PLAIN} }}"


U = ("unknown",) * 3
P = ("pass",) * 3
CASES = [
    ("plain check", pipeline(PLAIN), P),
    ("withEnv PATH+X", pipeline(wrapped('["PATH+X=${env.WORKSPACE}/tools"]')), U),
    ("withEnv PATH=", pipeline(wrapped("['PATH=/opt/tools:/usr/bin:/bin']")), U),
    ("withEnv path+x in another letter case", pipeline(wrapped("['path+x=/opt/tools']")), U),
    ("withEnv PATH with space before the equals", pipeline(wrapped("['PATH =/opt/tools']")), U),
    ("withEnv LD_PRELOAD", pipeline(wrapped("['LD_PRELOAD=./evil.so']")), U),
    ("withEnv PYTHONPATH", pipeline(wrapped("['PYTHONPATH=.']")), U),
    ("withEnv BASH_ENV", pipeline(wrapped("['BASH_ENV=./env.sh']")), U),
    ("withEnv HOME", pipeline(wrapped('["HOME=${env.WORKSPACE}"]')), U),
    ("withEnv PATH joined with +", pipeline(wrapped("['PATH+X=' + env.WORKSPACE + '/tools']")), U),
    ("withEnv name joined with +", pipeline(wrapped("['PA' + 'TH=/opt/tools']")), U),
    ("withEnv list in a variable", pipeline("script { def e = ['FOO=bar']; " + wrapped("e") + " }"), U),
    ("withEnv computed name", pipeline("script { def n = 'PATH'; " + wrapped('["${n}=/opt/tools"]') + " }"), U),
    ("withEnv plain variable", pipeline(wrapped("['FOO=bar']")), P),
    ("withEnv PYTHONUNBUFFERED", pipeline(wrapped("['PYTHONUNBUFFERED=1']")), P),
    ("withEnv PATH around another step only", pipeline(PLAIN, build="withEnv(['PATH+X=/opt/tools']) { sh 'make' }"), P),
    ("withEnv nested, PATH outside", pipeline(
        "withEnv(['PATH+X=/opt/tools']) { withEnv(['FOO=bar']) { " + PLAIN + " } }"), U),
    ("stage environment PATH", pipeline(PLAIN, verify_env="environment { PATH = \"/opt/tools:${env.PATH}\" }"), U),
    ("pipeline environment PATH", pipeline(PLAIN, top="environment { PATH = \"/opt/tools:${env.PATH}\" }"), U),
    ("pipeline environment LD_LIBRARY_PATH", pipeline(PLAIN, top="environment { LD_LIBRARY_PATH = '/opt/lib' }"), U),
    ("pipeline environment plain", pipeline(PLAIN, top="environment { FOO = 'bar' }"), P),
    ("environment PATH in another stage", pipeline(
        PLAIN, build="sh 'make'").replace("stage('Fetch') {", "stage('Fetch') {\n      environment { PATH = '/x' }"), P),
    ("script env.PATH = in an earlier stage", pipeline(PLAIN, build="script { env.PATH = '/opt/tools:' + env.PATH }"), U),
    ("script env['PATH'] =", pipeline(PLAIN, build="script { env['PATH'] = '/opt/tools' }"), U),
    ("script env.setProperty('PATH', ...)", pipeline(PLAIN, build="script { env.setProperty('PATH', '/opt/tools') }"), U),
    ("script this.env.PATH =", pipeline(PLAIN, build="script { this.env.PATH = '/opt/tools' }"), U),
    ("script env computed name", pipeline(PLAIN, build="script { def n = 'PATH'; env.\"${n}\" = '/opt/tools' }"), U),
    ("script env[n] computed", pipeline(PLAIN, build="script { def n = sh(script: 'cat n', returnStdout: true); env[n] = '/x' }"), U),
    ("script env.FOO =", pipeline(PLAIN, build="script { env.FOO = 'bar' }"), P),
    # A failure the step ignores stays a finding whatever runs: OBAAF-JEN-011 reports it, and OBAAF-JEN-010 and 012
    # see no check, as before the review.
    ("withEnv PATH, failure ignored", pipeline(
        "withEnv(['PATH+X=/opt/tools']) { sh '" + CHECK.format(rev=REV) + " || true' }"),
        ("finding-medium", "finding-high", "finding-high")),
    # A check of everything but the approvals stays a medium OBAAF-JEN-012: whatever it runs, approvals are not checked.
    ("withEnv PATH, pre-approval only", pipeline(
        "withEnv(['PATH+X=/opt/tools']) { sh '" + CHECK.format(rev=REV) + " --pre-approval' }"),
        ("unknown", "unknown", "finding-medium")),
]


def verdicts(text: str) -> tuple:
    result = jenkins.analyze("Jenkinsfile", text.encode(), load(), None)
    rows = {row["rule"]: row for row in jenkins.coverage(result, result.findings)}
    out = []
    for rule in RULES:
        severities = {f.severity for f in result.findings if f.rule == rule}
        if severities:
            out.append("finding-high" if "high" in severities else "finding-medium")
        else:
            out.append(rows[rule]["status"] if rule in rows else "missing")
    return tuple(out)


class CheckEnvironmentTest(unittest.TestCase):
    def test_every_case(self):
        for name, text, expected in CASES:
            with self.subTest(case=name):
                self.assertEqual(verdicts(text), expected)

    def test_the_reason_names_the_variable_and_its_line(self):
        result = jenkins.analyze("Jenkinsfile", pipeline(wrapped("['LD_PRELOAD=./evil.so']")).encode(), load(), None)
        rows = {row["rule"]: row for row in jenkins.coverage(result, result.findings)}
        for rule in RULES:
            with self.subTest(rule=rule):
                self.assertTrue(any("LD_PRELOAD is set around the step" in r for r in rows[rule]["reasons"]),
                                rows[rule]["reasons"])


if __name__ == "__main__":
    unittest.main()
