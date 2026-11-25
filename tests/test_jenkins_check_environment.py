"""The review of pull request #365 (#344): a check counts for OBAAF-JEN-010, 011 and 012 only when nothing around it
changes the program its shell runs.

Before the review the shell reader stopped at an `export` inside the check's own script, but a `withEnv` entry, an
`environment { }` block or `env.PATH = ...` in a script changed nothing, so `withEnv(["PATH+X=${env.WORKSPACE}/x"])`
around `obaaf verify release` made all three rules pass, whatever `x` held. The names are those the GitHub rules read
since slice 2d.13 (`obaaf.checker.rules.steers`). Each case is a Jenkinsfile and what OBAAF-JEN-010, 011 and 012 say:
"pass", "unknown" (cannot tell) or "finding-high" / "finding-medium".
"""
import textwrap
import time
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


def in_when(code: str) -> str:
    """The plain pipeline with a stage before the copy whose `when { expression { } }` runs `code`."""
    return pipeline(PLAIN).replace("stage('Fetch') {", "stage('Prep') {\n      when { expression { " + code
                                   + "; return true } }\n      steps { sh 'true' }\n    }\n    stage('Fetch') {")


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
    ("script env.PATH = in an earlier stage",
     pipeline(PLAIN, build="script { env.PATH = '/opt/tools:' + env.PATH }"), U),
    ("script env['PATH'] =", pipeline(PLAIN, build="script { env['PATH'] = '/opt/tools' }"), U),
    ("script env.setProperty('PATH', ...)",
     pipeline(PLAIN, build="script { env.setProperty('PATH', '/opt/tools') }"), U),
    ("script this.env.PATH =", pipeline(PLAIN, build="script { this.env.PATH = '/opt/tools' }"), U),
    ("script env computed name", pipeline(PLAIN, build="script { def n = 'PATH'; env.\"${n}\" = '/opt/tools' }"), U),
    ("script env[n] computed",
     pipeline(PLAIN, build="script { def n = sh(script: 'cat n', returnStdout: true); env[n] = '/x' }"), U),
    ("script env.FOO =", pipeline(PLAIN, build="script { env.FOO = 'bar' }"), P),
    # From the review's attack on the first version of this change (each was a pass there):
    # Groovy reads \0 to \377 as an octal escape, so '\120ATH' is PATH.
    ("withEnv octal escape", pipeline(wrapped('["\\120ATH+X=${env.WORKSPACE}/tools"]')), U),
    ("script env['\\120ATH'] =", pipeline(PLAIN, build="script { env['\\120ATH'] = '/x' }"), U),
    ("script env.'\\120ATH' =", pipeline(PLAIN, build="script { env.'\\120ATH' = '/x' }"), U),
    # env reached through the script object or a variable holding it
    ("script this.env.setProperty", pipeline(PLAIN, build="script { this.env.setProperty('PATH', '/x') }"), U),
    ("steps.env['PATH'] =", pipeline(PLAIN, build="script { steps.env['PATH'] = '/x' }"), U),
    ("def s = this; s.env.PATH =", pipeline(PLAIN, build="script { def s = this; s.env.PATH = '/x' }"), U),
    ("a method given this sets script.env", "def setup(script) { script.env['PATH'] = '/tmp/x:' + script.env.PATH }\n"
     + pipeline(PLAIN, build="script { setup(this) }"), U),
    ("getProperty('env').PATH =", pipeline(PLAIN, build="script { getProperty('env').PATH = '/x' }"), U),
    ("env.with { }", pipeline(PLAIN, build="script { env.with { PATH = '/x' } }"), U),
    # withEnv reached other than by a call the walker reads
    ("s.withEnv with s = this", pipeline("script { def s = this; s.withEnv(['PATH+X=/opt/tools']) { " + PLAIN + " } }"),
     U),
    ("a method pointer to withEnv", pipeline("script { def we = this.&withEnv; we(['PATH+X=/opt/tools']) { " + PLAIN
                                             + " } }"), U),
    ("a quoted withEnv", pipeline("script { 'withEnv'(['PATH+X=/opt/tools']) { " + PLAIN + " } }"), U),
    ("options { withEnv }", pipeline(PLAIN, top="options { withEnv(['PATH+X=/x']) }"), U),
    # Groovy the walker does not walk
    ("env.PATH = in a when expression", pipeline(PLAIN).replace(
        "stage('Fetch') {", "stage('Prep') {\n      when { expression { env.PATH = \"${env.WORKSPACE}/t:${env.PATH}\"; "
        "return true } }\n      steps { sh 'true' }\n    }\n    stage('Fetch') {"), U),
    ("env.PATH = in a method an environment value calls", "def setUp() { env.PATH = '/x'; 'a' }\n"
     + pipeline(PLAIN, top="environment { FOO = setUp() }"), U),
    ("env.PATH = inside a GString", pipeline(PLAIN, build="echo \"${env.PATH = '/tmp/x:' + env.PATH}\""), U),
    ("env.PATH = in a for loop's start", pipeline(PLAIN, build="script { for (env.PATH = '/tmp/x'; false; ) {} }"), U),
    # Variables set around the step by a matrix axis or a credential binding
    ("a matrix axis named PATH", textwrap.dedent("""\
        pipeline {
          agent any
          stages {
            stage('Fetch') { steps { copyArtifacts(projectName: 'build', selector: lastSuccessful(), filter: 'dist/**') } }
            stage('Verify') {
              matrix {
                axes { axis { name 'PATH'; values '/tmp/x' } }
                stages { stage('cell') { steps { %s } } }
              }
            }
            stage('Publish') { steps { sh './scripts/publish.sh dist' } }
          }
        }
        """) % PLAIN, U),
    ("a credential bound to LD_PRELOAD", pipeline(
        "withCredentials([file(credentialsId: 'x', variable: 'LD_PRELOAD')]) { " + PLAIN + " }"), U),
    # Reading env is not writing it
    ("env.PATH compared", pipeline(PLAIN, build="script { if (env.PATH == '/x' || env.PATH =~ /y/) { echo 'z' } }"), P),
    # From the second attack pass on 9f9ffee (most passed there): Groovy the walker does not walk is read node by
    # node.
    ("an alias of env in a when expression", in_when("def e = env; e.PATH = \"${env.WORKSPACE}/t:${env.PATH}\""), U),
    ("an alias defined outside, used in a when expression", "def e = env\n" + in_when("e['PATH'] = '/x'"), U),
    ("a comment between env and the name", in_when("env/**/.PATH = '/x'"), U),
    ("env in parentheses", in_when("(env).PATH = '/x'"), U),
    ("a unicode escape in the name", in_when("env.\\u0050ATH = '/x'"), U),
    ("a triple-quoted property name", in_when("env." + "'" * 3 + "PATH" + "'" * 3 + " = '/x'"), U),
    ("a quoted setter", in_when("env.\"setProperty\"('PATH', '/x')"), U),
    ("this.\"env\"", in_when("this.\"env\".PATH = '/x'"), U),
    ("a multiple assignment", in_when("(env.PATH, env.FOO) = ['/x', 'y']"), U),
    ("a setter's computed name", in_when("env.setProperty('PA' + 'TH', '/x')"), U),
    ("a setter's computed name in a GString", pipeline(PLAIN, build="echo \"${env.setProperty('PA' + 'TH', '/x')}\""),
     U),
    ("a method pointer to setProperty", pipeline(PLAIN, build="script { def sp = env.&setProperty; sp('PATH', '/x') }"),
     U),
    ("env.identity { }", pipeline(PLAIN, build="script { env.identity { PATH = '/x' } }"), U),
    ("getProperty of a computed name", pipeline(PLAIN, build="script { getProperty('e' + 'nv').PATH = '/x' }"), U),
    ("this.\"${'env'}\"", pipeline(PLAIN, build="script { this.\"${'env'}\".PATH = '/x' }"), U),
    ("a computed withEnv", pipeline("script { def m = 'with' + 'Env'; \"$m\"([\"PATH+X=${env.WORKSPACE}/t\"]) { "
                                    + PLAIN + " } }"), U),
    ("a pointer to a computed method", pipeline("script { def m = 'withEnv'; def w = this.&\"$m\"; w(['PATH+X=/t']) { "
                                                + PLAIN + " } }"), U),
    ("an assignment in an argument", pipeline(PLAIN, build="script { echo(env.PATH = '/x') }"), U),
    ("an assignment in a while condition", pipeline(PLAIN, build="script { while ((env.PATH = '/x') == null) {} }"), U),
    # Reading env, or a computed property of another object, is not writing env
    ("a method on a computed parameter", pipeline(PLAIN, build="script { def k = 'X'; echo params.\"${k}\".trim() }"),
     P),
    ("reading env in a when expression", in_when("env.BRANCH_NAME.startsWith('release/')"), P),
    # From the third attack pass (each was a pass at 6007f19): env used as a value is not followed, so it counts.
    ("an alias through a ternary", in_when("def e = true ? env : null; e.PATH = '/x'"), U),
    ("an alias through ?: and as", pipeline(PLAIN, build="script { (env ?: null).PATH = '/x'; (env as Object).X = 1 }"),
     U),
    ("a method that returns env", "def g() { env }\n" + pipeline(PLAIN, build="script { g().PATH = '/x' }"), U),
    ("a closure whose delegate is env", "def inEnv(Closure body) { body.resolveStrategy = Closure.DELEGATE_FIRST; "
     "body.delegate = env; body() }\n" + pipeline(PLAIN, build="script { inEnv { PATH = '/x' } }"), U),
    ("a script property holding env", in_when("this.e = env; this.e.PATH = '/x'"), U),
    ("a method's default parameter", "def f(a = (env.PATH = '/tmp/x')) { a }\n"
     + pipeline(PLAIN, build="script { f() }"), U),
    ("a switch case closure",
     pipeline(PLAIN, build="script { switch (1) { case { env.PATH = '/tmp/x'; true }: break } }"),
     U),
    ("env.PATH++", pipeline(PLAIN, build="script { env.PATH++ }"), U),
    ("an unreadable statement inside a GString in a method", "def m() {\n  echo 'x'\n}\n" + pipeline(PLAIN) + "\n" * 20
     + "def late() { echo \"${(env.PATH, env.X) = ['/x', 'y']}\" }\n", U),
    # Ordinary reads stay passes
    ("a loop bounded by an env value", pipeline(PLAIN, build="script { for (int i = 0; i < env.N.toInteger(); i++) "
                                                             "{ echo 'x' } }"), P),
    ("env.getOverriddenEnvironment()",
     pipeline(PLAIN, build="script { echo env.getOverriddenEnvironment().toString() }"),
     P),
    # From the fourth attack pass (each was a pass at 75146e9)
    ("getProperty('env') on a closure's owner", pipeline(
        PLAIN, build="script { def c = { owner.getProperty('env').PATH = \"${env.WORKSPACE}/t\" }; c() }"), U),
    ("a computed property of a closure's delegate", pipeline(
        PLAIN, build="script { def n = 'env'; def c = { delegate.\"${n}\".PATH = '/t' }; c.delegate = this; c() }"), U),
    ("a pointer to getProperty", pipeline(PLAIN, build="script { def gp = this.&getProperty; gp('env').PATH = '/t' }"),
     U),
    ("a unicode-escaped env with ++", pipeline(PLAIN, build="script { \\u0065nv.PATH++ }"), U),
    ("a default reaching env by a computed name", "def setUp(a =\n    getProperty('e' + 'nv').setProperty('PATH', '/t')) {"
     " a }\n" + pipeline(PLAIN, build="script { setUp() }"), U),
    ("a loop header reaching env by a computed name", in_when("for (getProperty('e' + 'nv').PATH = '/t'; false; ) {}"),
     U),
    ("a case label over several lines", pipeline(PLAIN, build="script {\n switch (1) {\n  case {\n   "
                                                              "env.setProperty('PATH', '/t'); true\n  }:\n  case 2: "
                                                              "break }\n}"), U),
    # A property named env of something that cannot be the script, read, and the word env in a string, stay passes
    ("Artifactory's buildInfo.env", pipeline(PLAIN, build="script { def b = Artifactory.newBuildInfo(); "
                                                          "b.env.collect() }"), P),
    ("a YAML file's env",
     pipeline(PLAIN, build="script { def c = readYaml(file: 'c.yml'); def n = c.env.collect { it } }"),
     P),
    ("'env' as a default", "def deploy(String target = 'env') { echo target }\n"
     + pipeline(PLAIN, build="script { deploy() }"), P),
    ("'env' as a case label", pipeline(PLAIN, build="script { switch (params.T) { case 'env': echo 'x'; break } }"), P),
    # From the fifth attack pass (each was a pass at 3bb3520)
    ("getProperty on a method's result", "def me() { this }\n"
     + pipeline(PLAIN, build="script { me().getProperty('env').PATH = '/t' }"), U),
    ("getOwner().getProperty", pipeline(PLAIN, build="script { def c = { getOwner().getProperty('env').PATH = '/t' }; "
                                                    "c() }"), U),
    ("getAt on an index", pipeline(PLAIN, build="script { [this][0].getAt('env').PATH = '/t' }"), U),
    ("this['env'] in a default", "def f(a = this['env'].putAll([PATH: '/t'])) { a }\n"
     + pipeline(PLAIN, build="script { f() }"), U),
    ("this['env'] in a loop's header", in_when("for (this['env'].PATH = '/t'; false; ) {}"), U),
    ("this['env'] in a case label", pipeline(PLAIN, build="script { switch (1) { case { this['env'].putAll([PATH: '/t']); "
                                                         "true }: break } }"), U),
    ("this through a ternary", pipeline(PLAIN, build="script { def s = true ? this : null; s.env.putAll([PATH: '/t']) }"),
     U),
    ("owner.owner.env in a when expression", in_when("def c = { owner.owner.env.putAll([PATH: '/t']) }; c()"), U),
    ("it.env", pipeline(PLAIN, build="script { this.with { it.env.putAll([PATH: '/t']) } }"), U),
    # From the last attack pass: a triple-quoted 'env' in a default or a loop's header
    ("a triple-quoted env in a default", "def f(a = this[" + "'" * 3 + "env" + "'" * 3 + "].putAll([PATH: '/t'])) { a }\n"
     + pipeline(PLAIN, build="script { f() }"), U),
    ("a parameter's env given putAll", "def setup(s) { def t = s; t.env.putAll([PATH: '/t']) }\n"
     + pipeline(PLAIN, build="script { setup(this) }"), U),
    ("a parameter's env given to a variable, then written", "def setup(s) { def e = s.env; e.PATH = '/t' }\n"
     + pipeline(PLAIN, build="script { setup(this) }"), U),
    ("it in this.with, passed on", "def helper(e) { e.PATH = '/t' }\n"
     + pipeline(PLAIN, build="script { this.with { helper(it.env) } }"), U),
    ("it in this.with, returned", pipeline(PLAIN, build="script { def r = this.with { it.env }; r.PATH = '/t' }"), U),
    # A list of maps with an env key, read through it or a closure's parameter, stays a pass
    ("it.env read", pipeline(PLAIN, build="script { def targets = [[name: 'a', env: 'prod']]; "
                                          "targets.each { echo(it.env) }; targets.each { x -> echo(\"${x.env}\") } }"), P),
    ("a parameter's env collected", "def pub(b) { b.env.collect { it } }\n"
     + pipeline(PLAIN, build="script { pub([env: [1]]) }"), P),
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
    def test_text_that_looks_like_writes_is_not_slow(self):
        # The second version scanned the text with a pattern that took 135 s on a 256 KiB comment of `env[env[...`, and
        # counted lines from the start for every match (18.6 s on 1,000 KiB of `env.a=1` lines).
        for text in (pipeline(PLAIN, build="// " + "env[" * 64_000),
                     pipeline(PLAIN, build="\n".join("// env.a=1" for _ in range(100_000)))):
            started = time.monotonic()
            verdicts(text)
            self.assertLess(time.monotonic() - started, 10)

    def test_many_assignments_and_checks_are_read_once(self):
        # The first version read the file's assignments again for every check: 2,000 of each took 4.2 s here and
        # 6,300 took 27 (1.2 and 3.4 now).
        body = "\n".join(f"env.V{i} = '1'" for i in range(2000))
        checks = "\n".join(PLAIN for _ in range(2000))
        text = pipeline(checks, build="script {\n" + body + "\n}")
        started = time.monotonic()
        self.assertEqual(verdicts(text), P)
        self.assertLess(time.monotonic() - started, 3)

    def test_every_case(self):
        for name, text, expected in CASES:
            with self.subTest(case=name):
                self.assertEqual(verdicts(text), expected)

    def test_a_write_in_a_gstring_names_the_string_s_line(self):
        text = pipeline(PLAIN, build="echo \"${env.PATH = '/tmp/x:' + env.PATH}\"")
        line = text.split("\n").index(next(x for x in text.split("\n") if "echo \"${env.PATH" in x)) + 1
        result = jenkins.analyze("Jenkinsfile", text.encode(), load(), None)
        rows = {row["rule"]: row for row in jenkins.coverage(result, result.findings)}
        self.assertTrue(any(f"line {line} sets PATH" in r for r in rows["OBAAF-JEN-012"]["reasons"]),
                        rows["OBAAF-JEN-012"]["reasons"])

    def test_the_reason_names_the_variable_and_its_line(self):
        result = jenkins.analyze("Jenkinsfile", pipeline(wrapped("['LD_PRELOAD=./evil.so']")).encode(), load(), None)
        rows = {row["rule"]: row for row in jenkins.coverage(result, result.findings)}
        for rule in RULES:
            with self.subTest(rule=rule):
                self.assertTrue(any("LD_PRELOAD is set around the step (line 14)" in r for r in rows[rule]["reasons"]),
                                rows[rule]["reasons"])


if __name__ == "__main__":
    unittest.main()
