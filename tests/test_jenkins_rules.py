"""OBAAF-JEN rules (Jenkins design, sections 5 and 8; JT 01, 03, 04, 21).

Each rule has a positive case (the finding), a negative case (the safe form, no finding) and,
where the Jenkinsfile alone cannot decide, an unknown case (a coverage unknown, never a pass).
The test set in tests/fixtures/jenkins/risky must keep exercising every rule.
"""

import textwrap
import unittest

from helpers import FIXTURES, ROOT, TempDir

from obaaf import checker, render
from obaaf.catalog import load
from obaaf.checker import jenkins
from obaaf.checker.jenkins import model, parser

RISKY = FIXTURES / "jenkins" / "risky"
SAFE = FIXTURES / "jenkins" / "safe"


def analyze(text, root=None):
    return jenkins.analyze("Jenkinsfile", textwrap.dedent(text).encode(), load(), root)


def rules(text, root=None):
    return {f.rule: f.severity for f in analyze(text, root).findings}


def status(text, rule, root=None):
    result = analyze(text, root)
    return next(row["status"] for row in jenkins.coverage(result, result.findings) if row["rule"] == rule)


def declarative(steps, stage_extra="", top=""):
    return f"""
pipeline {{
  agent {{ label 'linux' }}
  {top}
  stages {{
    stage('S') {{
      {stage_extra}
      steps {{
        {steps}
      }}
    }}
  }}
}}
"""


class TestSetTest(unittest.TestCase):
    def test_every_fixture_reports_its_expected_rules(self):
        cases = render.read_test_set(RISKY)
        self.assertGreaterEqual(len(cases), 12)
        for case in cases:
            path = ROOT / case["file"]
            found = {f.rule for f in checker.check(path).findings}
            with self.subTest(case=path.name):
                self.assertTrue(set(case["expect"]) <= found, f"missing {set(case['expect']) - found}")

    def test_every_jenkins_rule_is_exercised(self):
        exercised = {rule for case in render.read_test_set(RISKY) for rule in case["expect"]}
        self.assertEqual({r for r in load().rules if r.startswith("OBAAF-JEN-")} - exercised, set())

    def test_test_set_is_published_in_the_rules_document(self):
        text = (ROOT / "spec" / "checker-rules.md").read_text()
        for case in render.read_test_set(RISKY):
            self.assertIn(case["file"], text)

    def test_safe_pipelines_have_no_gating_findings(self):
        for path in sorted(SAFE.glob("*.groovy")):
            findings = checker.check(path).findings
            with self.subTest(case=path.name):
                self.assertEqual([(f.rule, f.line) for f in findings if f.severity in ("high", "medium")], [])

    def test_rule_catalog_entries_are_complete(self):
        catalog = load()
        self.assertEqual(catalog.problems(), [])
        for rid in jenkins.RULES:
            rule = catalog.rules[rid]
            self.assertEqual(rule.get("platform"), "jenkins")
            self.assertTrue(rule["requirements"] or rule.get("agent_controls"), rid)


class ChangeRequestReachabilityTest(unittest.TestCase):
    def cr_of(self, text):
        pipeline = model.build(parser.parse(textwrap.dedent(text)).tree)
        return {s.call.args[0].text(): s.ctx.cr for s in pipeline.steps if s.name == "sh"}

    def test_declarative_when_conditions(self):
        text = """
pipeline {
  agent any
  stages {
    stage('a') {
      when { changeRequest() }
      steps { sh 'pr' }
    }
    stage('b') {
      when { branch 'main' }
      steps { sh 'main' }
    }
    stage('c') {
      when { not { changeRequest() } }
      steps { sh 'notpr' }
    }
    stage('d') {
      when {
        anyOf {
          branch 'main'
          changeRequest()
        }
      }
      steps { sh 'either' }
    }
    stage('e') {
      steps { sh 'any' }
    }
    stage('f') {
      when { expression { return currentBuild.number > 1 && isSpecial(env.X) } }
      steps { sh 'expr' }
    }
    stage('g') {
      when { expression { isRelease(env.BRANCH_NAME) } }
      steps { sh 'unknown' }
    }
    stage('g2') {
      when { expression { env.BRANCH_NAME.startsWith('rel') } }
      steps { sh 'startswith' }
    }
    stage('i') {
      when { not { changeRequest author: 'dependabot[bot]' } }
      steps { sh 'notbot' }
    }
    stage('j') {
      when { branch pattern: 'main|PR-\\\\d+', comparator: 'REGEXP' }
      steps { sh 'regexp' }
    }
    stage('h') {
      when { buildingTag() }
      steps { sh 'tag' }
    }
  }
}
"""
        self.assertEqual(self.cr_of(text), {"pr": "yes", "main": "no", "notpr": "no", "either": "yes",
                                            "any": "possible", "expr": "possible", "unknown": "unknown",
                                            "startswith": "no", "notbot": "possible", "regexp": "yes",
                                            "tag": "no"})

    def test_scripted_conditions_and_local_methods(self):
        text = """
node {
  if (isRelease()) { sh 'release' } else { sh 'other' }
  if (env.CHANGE_ID) { sh 'pr' }
  if (env.BRANCH_NAME == 'main' && params.DEPLOY) { sh 'deploy' }
  if (null != env.CHANGE_ID) { sh 'pr2' }
}
boolean isRelease() { return env.BRANCH_NAME == 'main' || env.BRANCH_NAME == 'release' }
"""
        self.assertEqual(self.cr_of(text), {"release": "no", "other": "possible", "pr": "yes", "deploy": "no",
                                            "pr2": "yes"})

    def test_pull_request_triggers_make_every_stage_reachable(self):
        text = """
pipeline {
  agent any
  triggers { GenericTrigger(genericVariables: [[key: 'T', value: '$.pull_request.title']]) }
  stages {
    stage('a') {
      steps { sh 'all' }
    }
    stage('b') {
      when { branch 'main' }
      steps { sh 'main' }
    }
  }
}
"""
        self.assertEqual(self.cr_of(text), {"all": "yes", "main": "no"})


class CredentialRulesTest(unittest.TestCase):
    def test_jen_001_pipeline_wide_credentials_reach_change_request_code(self):
        text = declarative("sh 'make test'", top="environment { TOKEN = credentials('t') }")
        self.assertEqual(rules(text).get("OBAAF-JEN-001"), "medium")

    def test_jen_001_change_request_only_stage_is_high(self):
        text = declarative("withCredentials([string(credentialsId: 't', variable: 'T')]) { sh 'npm test' }",
                           stage_extra="when { changeRequest() }")
        self.assertEqual(rules(text).get("OBAAF-JEN-001"), "high")

    def test_jen_001_fixed_tools_are_one_level_lower(self):
        text = declarative("withCredentials([string(credentialsId: 't', variable: 'T')]) { sh 'curl -sf x' }")
        self.assertEqual(rules(text).get("OBAAF-JEN-001"), "low")

    def test_jen_001_indirect_wrappers_bind_credentials(self):
        for wrapper in ("sshagent(['k'])", "withAWS(credentials: 'aws')", "withKubeConfig([credentialsId: 'kc'])",
                        "withDockerRegistry([credentialsId: 'r', url: ''])"):
            text = declarative(f"{wrapper} {{ sh './gradlew test' }}")
            self.assertIn("OBAAF-JEN-001", rules(text), wrapper)

    def test_jen_001_agent_with_any_credential_is_high(self):
        text = declarative("withCredentials([string(credentialsId: 'k', variable: 'K')]) { sh 'claude -p x' }",
                           stage_extra="when { branch 'main' }")
        self.assertEqual(rules(text).get("OBAAF-JEN-001"), "high")

    def test_jen_001_negative_protected_branch_only(self):
        text = declarative("withCredentials([string(credentialsId: 't', variable: 'T')]) { sh 'make deploy' }",
                           stage_extra="when { branch 'main' }")
        self.assertNotIn("OBAAF-JEN-001", rules(text))
        self.assertEqual(status(text, "OBAAF-JEN-001"), "pass")

    def test_jen_001_unknown_condition(self):
        text = declarative("withCredentials([string(credentialsId: 't', variable: 'T')]) { sh 'make' }",
                           stage_extra="when { expression { isReleaseBuild(env.BRANCH_NAME) } }")
        self.assertNotIn("OBAAF-JEN-001", rules(text))
        self.assertEqual(status(text, "OBAAF-JEN-001"), "unknown")

    def test_jen_013_secret_interpolation_and_its_safe_form(self):
        bind = "withCredentials([usernamePassword(credentialsId: 'c', usernameVariable: 'U', passwordVariable: 'P')])"
        when = "when { branch 'main' }"
        self.assertIn("OBAAF-JEN-013", rules(declarative(bind + ' { sh "curl -u ${U}:${P} x" }', when)))
        self.assertNotIn("OBAAF-JEN-013", rules(declarative(bind + " { sh 'curl -u \"$U:$P\" x' }", when)))

    def test_jen_013_file_paths_are_not_secrets(self):
        text = declarative('withCredentials([file(credentialsId: "kf", variable: "KEYFILE")]) '
                           '{ sh "tool --key ${KEYFILE}" }', "when { branch 'main' }")
        self.assertNotIn("OBAAF-JEN-013", rules(text))

    def test_jen_014_signing_material(self):
        text = declarative("withCredentials([file(credentialsId: 'apple-signing-cert', variable: 'CERT')]) "
                           "{ sh './build.sh' }", "when { branch 'main' }")
        self.assertIn("OBAAF-JEN-014", rules(text))
        self.assertNotIn("OBAAF-JEN-014", rules(declarative("sh './build.sh'")))


class PlacementRulesTest(unittest.TestCase):
    def test_jen_002_controller_and_floating_agents(self):
        self.assertEqual(rules("node('built-in') { sh 'make' }").get("OBAAF-JEN-002"), "high")
        self.assertEqual(rules("node('master') { if (env.BRANCH_NAME == 'main') { sh 'make' } }")
                         .get("OBAAF-JEN-002"), "medium")
        self.assertEqual(status("pipeline { agent any\n stages { stage('a') { steps { sh 'x' } } } }",
                                "OBAAF-JEN-002"), "unknown")
        # A labelled agent that change requests reach may be persistent and shared: only the controller knows.
        self.assertEqual(status(declarative("sh 'x'"), "OBAAF-JEN-002"), "unknown")
        self.assertEqual(status(declarative("sh 'x'", "when { branch 'main' }"), "OBAAF-JEN-002"), "pass")

    def test_jen_006_host_access_and_unknown_pod_templates(self):
        text = declarative("sh 'x'").replace("agent { label 'linux' }",
                                             "agent { docker { image 'node:20'; args '--privileged' } }")
        self.assertEqual(rules(text).get("OBAAF-JEN-006"), "high")
        safe = text.replace("args '--privileged'", "args '-e CI=1'")
        self.assertNotIn("OBAAF-JEN-006", rules(safe))
        inherited = declarative("sh 'x'").replace("agent { label 'linux' }",
                                                  "agent { kubernetes { inheritFrom 'shared-pod' } }")
        self.assertEqual(status(inherited, "OBAAF-JEN-006"), "unknown")

    def test_jen_006_pod_file_from_the_repository(self):
        pod = "apiVersion: v1\nkind: Pod\nspec:\n  hostNetwork: true\n  containers:\n  - name: a\n    image: x\n"
        text = declarative("sh 'x'").replace("agent { label 'linux' }",
                                             "agent { kubernetes { yamlFile 'ci/pod.yaml' } }")
        with TempDir() as tmp:
            (tmp / "ci").mkdir()
            (tmp / "ci" / "pod.yaml").write_text(pod)
            self.assertIn("OBAAF-JEN-006", rules(text, tmp))
            self.assertEqual(status(text.replace("ci/pod.yaml", "ci/missing.yaml"), "OBAAF-JEN-006", tmp), "unknown")

    def test_jen_006_agent_pods_should_not_mount_service_account_tokens(self):
        pod = "spec:\n  containers:\n  - name: a\n    image: x@sha256:" + "0" * 64 + "\n"
        text = declarative("container('a') { sh 'claude -p review' }").replace(
            "agent { label 'linux' }", f"agent {{ kubernetes {{ yaml '''{pod}''' }} }}")
        self.assertIn("OBAAF-JEN-006", rules(text))
        fixed = text.replace("spec:\n", "spec:\n  automountServiceAccountToken: false\n")
        self.assertNotIn("OBAAF-JEN-006", rules(fixed))


class AgentRulesTest(unittest.TestCase):
    def test_jen_003_effects_in_the_agent_stage(self):
        for effect in ("sh 'git push origin HEAD'", "build job: 'deploy'", "sh 'npm publish'"):
            self.assertIn("OBAAF-JEN-003", rules(declarative(f"sh 'claude -p fix'\n{effect}")), effect)
        self.assertNotIn("OBAAF-JEN-003", rules(declarative("sh 'claude -p fix > p.md'\narchiveArtifacts 'p.md'")))

    def test_agents_are_found_through_scripts_and_declarations(self):
        with TempDir() as tmp:
            (tmp / "ci").mkdir()
            (tmp / "ci" / "review.sh").write_text("#!/bin/sh\nclaude -p \"$PROMPT\"\n")
            self.assertIn("OBAAF-JEN-007", rules(declarative("sh './ci/review.sh'"), tmp))
        declared = declarative("sh './run.sh'", top="environment { OBAAF_LANE = 'agent' }")
        self.assertIn("OBAAF-JEN-007", rules(declared))
        self.assertEqual(status(declarative("sh 'make'"), "OBAAF-JEN-007"), "not applicable")

    def test_ai_agent_plugin_step(self):
        found = rules(declarative("aiAgent(prompt: 'review', apiCredentialsId: 'key')"))
        self.assertEqual(found.get("OBAAF-JEN-001"), "high")
        self.assertIn("OBAAF-JEN-007", found)

    def test_jen_008_agent_cli_versions(self):
        self.assertIn("OBAAF-JEN-008", rules(declarative("sh 'npm i -g @openai/codex@latest'")))
        self.assertIn("OBAAF-JEN-008", rules(declarative("sh 'pip install aider-chat'")))
        self.assertNotIn("OBAAF-JEN-008", rules(declarative("sh 'npm i -g @openai/codex@0.40.0'")))


class CodeAndInjectionRulesTest(unittest.TestCase):
    def test_jen_004_libraries_and_workspace_groovy(self):
        self.assertEqual(rules("@Library(\"lib@${env.CHANGE_BRANCH}\") _\nnode { sh 'x' }").get("OBAAF-JEN-004"),
                         "high")
        self.assertEqual(rules("node { load 'ci/steps.groovy' }").get("OBAAF-JEN-004"), "medium")
        self.assertNotIn("OBAAF-JEN-004", rules("node { evaluate(readTrusted('ci/steps.groovy')) }"))
        self.assertNotIn("OBAAF-JEN-004", rules("node { if (env.BRANCH_NAME == 'main') { load 'ci/x.groovy' } }"))

    def test_jen_008_library_and_image_pins(self):
        self.assertIn("OBAAF-JEN-008", rules("@Library('lib') _\nnode { sh 'x' }"))
        self.assertIn("OBAAF-JEN-008", rules("@Library('lib@main') _\nnode { sh 'x' }"))
        self.assertNotIn("OBAAF-JEN-008", rules(f"@Library('lib@{'a' * 40}') _\nnode {{ sh 'x' }}"))
        self.assertIn("OBAAF-JEN-008", rules("node { docker.image('node:20').inside { sh 'x' } }"))
        self.assertNotIn("OBAAF-JEN-008", rules(f"node {{ docker.image('node@sha256:{'0' * 64}').inside "
                                                "{ sh 'x' } }"))
        self.assertEqual(status("node { docker.image(\"${img}\").inside { sh 'x' } }", "OBAAF-JEN-008"), "unknown")

    def test_jen_009_sources_and_safe_forms(self):
        self.assertEqual(rules(declarative('sh "echo ${env.CHANGE_TITLE}"')).get("OBAAF-JEN-009"), "high")
        self.assertEqual(rules(declarative('sh "make " + env.CHANGE_BRANCH')).get("OBAAF-JEN-009"), "high")
        self.assertEqual(rules(declarative('sh "deploy ${params.TARGET}"')).get("OBAAF-JEN-009"), "medium")
        self.assertEqual(rules(declarative('sh "tag ${env.BRANCH_NAME}"')).get("OBAAF-JEN-009"), "low")
        self.assertNotIn("OBAAF-JEN-009", rules(declarative("sh 'echo \"$CHANGE_TITLE\"'")))
        self.assertNotIn("OBAAF-JEN-009", rules(declarative('sh "echo \\$CHANGE_TITLE"')))

    def test_jen_009_taint_through_variables_and_commit_text(self):
        via_var = "script { def t = env.CHANGE_TITLE\n sh \"echo ${t}\" }"
        self.assertEqual(rules(declarative(via_var)).get("OBAAF-JEN-009"), "high")
        commit = ("script { def msg = sh(script: 'git log -1 --pretty=%B', returnStdout: true).trim()\n"
                  " sh \"echo ${msg}\" }")
        self.assertEqual(rules(declarative(commit)).get("OBAAF-JEN-009"), "high")
        hashed = ("script { def rev = sh(script: 'git log -1 --format=%H', returnStdout: true).trim()\n"
                  " sh \"echo ${rev}\" }")
        self.assertNotIn("OBAAF-JEN-009", rules(declarative(hashed)))

    def test_jen_015_literal_tokens(self):
        base = "pipeline {{ agent any\n triggers {{ GenericTrigger({arg}) }}\n stages {{ stage('a') {{ steps {{ sh 'x' }} }} }} }}"
        self.assertIn("OBAAF-JEN-015", rules(base.format(arg="token: 'abc123'")))
        self.assertNotIn("OBAAF-JEN-015", rules(base.format(arg="tokenCredentialId: 'hook-token'")))


class ReleaseRulesTest(unittest.TestCase):
    def test_jen_005_approvals(self):
        self.assertIn("OBAAF-JEN-005", rules(declarative("input message: 'ok?'")))
        self.assertNotIn("OBAAF-JEN-005", rules(declarative("input message: 'ok?', submitter: 'release'")))
        self.assertEqual(status(declarative("input message: 'ok?', submitter: 'release'"), "OBAAF-JEN-005"),
                         "unknown")

    def test_jen_010_moving_artifact_references(self):
        copy = "copyArtifacts(projectName: 'b'{sel})\nsh 'aws s3 cp out s3://r/'"
        self.assertEqual(rules(declarative(copy.format(sel=""))).get("OBAAF-JEN-010"), "high")
        self.assertNotIn("OBAAF-JEN-010", rules(declarative(copy.format(sel=", selector: specific('42')"))))
        checked = "copyArtifacts(projectName: 'b')\nsh 'sha256sum -c SHA256SUMS'\nsh 'aws s3 cp out s3://r/'"
        self.assertNotIn("OBAAF-JEN-010", rules(declarative(checked)))
        self.assertEqual(status(declarative("copyArtifacts(projectName: 'b')\nsh 'make'"), "OBAAF-JEN-010"),
                         "not applicable")

    def test_jen_011_failure_paths(self):
        text = """
pipeline { agent any
  stages { stage('b') { steps { sh 'make' } } }
  post { failure { sh 'aws s3 cp out s3://r/' } }
}"""
        self.assertIn("OBAAF-JEN-011", rules(text))
        self.assertNotIn("OBAAF-JEN-011", rules(text.replace("failure {", "success {")))
        scripted = "node { try { sh 'make' } finally { sh 'twine upload dist/*' } }"
        self.assertIn("OBAAF-JEN-011", rules(scripted))

    def test_jen_012_verification_must_stop_the_build(self):
        good = declarative("sh 'obaaf verify release --policy p --artifacts a'\nsh 'npm publish'")
        self.assertNotIn("OBAAF-JEN-012", rules(good))
        for weak in ("sh 'obaaf verify release --policy p --artifacts a || true'",
                     "catchError { sh 'obaaf verify release --policy p --artifacts a' }",
                     "sh(script: 'obaaf verify release --policy p --artifacts a', returnStatus: true)"):
            found = rules(declarative(f"{weak}\nsh 'npm publish'"))
            self.assertEqual(found.get("OBAAF-JEN-012"), "high", weak)
        provenance = declarative("sh 'cosign verify-attestation --key k img'\nsh 'docker push img'")
        self.assertEqual(rules(provenance).get("OBAAF-JEN-012"), "medium")


class CoverageTest(unittest.TestCase):
    def test_shared_library_steps_make_every_rule_unknown(self):
        result = analyze("@Library('lib@" + "a" * 40 + "') _\nbuildPlugin()")
        rows = {r["rule"]: r["status"] for r in jenkins.coverage(result, result.findings)}
        self.assertTrue(all(s in ("unknown", "fail") for s in rows.values()), rows)
        summary = jenkins.summary(result)
        self.assertTrue(any("buildPlugin" in u for u in summary["unknowns"]))

    def test_generated_parallel_branches_and_loaded_code_are_unknown(self):
        result = analyze("node { parallel(makeBranches()) }\nnode { load 'x.groovy' }")
        self.assertTrue(jenkins.summary(result)["unknowns"])

    def test_unparseable_files_report_unknown_coverage(self):
        result = analyze("x = " + "(" * 5000)
        self.assertIsNotNone(result.error)
        self.assertTrue(all(r["status"] == "unknown" for r in jenkins.coverage(result, [])))

    def test_digest_of_analyzed_bytes(self):
        import hashlib
        data = b"node { sh 'x' }"
        self.assertEqual(jenkins.analyze("J", data, load(), None).digest,
                         "sha256:" + hashlib.sha256(data).hexdigest())


if __name__ == "__main__":
    unittest.main()


class ReviewRegressionTest(unittest.TestCase):
    """Bypasses and crashes found by an adversarial review of the first version (2026-10)."""

    def test_computed_parallel_branches_are_read(self):
        text = """
def platforms = ['linux', 'windows']
node('linux') {
  parallel platforms.collectEntries { p ->
    [(p): { withCredentials([string(credentialsId: 't', variable: 'T')]) { sh "./build.sh ${env.CHANGE_TITLE}" } }]
  }
}"""
        found = rules(text)
        self.assertIn("OBAAF-JEN-001", found)
        self.assertEqual(found.get("OBAAF-JEN-009"), "high")
        self.assertTrue(jenkins.summary(analyze("node { parallel generateBranches(['a']) }"))["unknowns"])

    def test_methods_get_the_callers_context(self):
        helpers = """
def runBuild() { sh './gradlew build' }
def upload() { sh 'aws s3 cp out s3://r/' }
def runAgent() { sh 'claude -p "fix the tests"' }
def notify(String msg) { sh "echo ${msg}" }
"""
        self.assertIn("OBAAF-JEN-001", rules(helpers + "node { withCredentials([string(credentialsId: 't', "
                                                       "variable: 'T')]) { runBuild() } }"))
        post = helpers + "pipeline { agent any\n stages { stage('b') { steps { sh 'make' } } }\n" \
                         " post { always { upload() } } }"
        self.assertIn("OBAAF-JEN-011", rules(post))
        self.assertIn("OBAAF-JEN-003", rules(helpers + "node { stage('fix') { runAgent()\n sh 'git push' } }"))
        self.assertEqual(rules(helpers + "node { notify(env.CHANGE_TITLE) }").get("OBAAF-JEN-009"), "high")

    def test_checks_that_cannot_stop_the_publish(self):
        verify = "obaaf verify release --policy p --artifacts a"
        weak = {
            "try/catch": f"try {{ sh '{verify}' }} catch (err) {{ echo 'failed' }}\nsh 'npm publish'",
            "pipe": f"sh '{verify} 2>&1 | tee v.log'\nsh 'npm publish'",
            "shebang": f"sh '''#!/bin/bash\n{verify}\necho done\n'''\nsh 'npm publish'",
            "bat": f"bat '''{verify}\necho done\n'''\nbat 'npm publish'",
            "map returnStatus": f"sh([script: '{verify}', returnStatus: true])\nsh 'npm publish'",
        }
        for label, steps in weak.items():
            found = rules(f"node {{\n{steps}\n}}")
            self.assertEqual(found.get("OBAAF-JEN-012"), "high", label)
            self.assertIn("OBAAF-JEN-011", found, label)
        strong = {
            "rethrow": f"try {{ sh '{verify}' }} catch (err) {{ error 'verification failed' }}\nsh 'npm publish'",
            "pipefail": f"sh 'set -o pipefail; {verify} | tee v.log'\nsh 'npm publish'",
            "shebang -e": f"sh '''#!/bin/bash -e\n{verify}\necho done\n'''\nsh 'npm publish'",
        }
        for label, steps in strong.items():
            self.assertNotIn("OBAAF-JEN-012", rules(f"node {{\n{steps}\n}}"), label)

    def test_parallel_and_conditional_checks_do_not_gate(self):
        verify = "sh 'obaaf verify release --policy p --artifacts a'"
        parallel = f"""
pipeline {{ agent any
  stages {{ stage('r') {{ parallel {{
    stage('Verify') {{ steps {{ {verify} }} }}
    stage('Publish') {{ steps {{ sh 'npm publish' }} }}
  }} }} }} }}"""
        self.assertEqual(rules(parallel).get("OBAAF-JEN-012"), "high")
        skippable = f"""
pipeline {{ agent any
  stages {{
    stage('Verify') {{
      when {{ expression {{ !params.SKIP_VERIFY }} }}
      steps {{ {verify} }}
    }}
    stage('Publish') {{ steps {{ sh 'npm publish' }} }}
  }} }}"""
        self.assertEqual(rules(skippable).get("OBAAF-JEN-012"), "high")
        same_guard = skippable.replace("expression { !params.SKIP_VERIFY }", "branch 'main'").replace(
            "stage('Publish') {", "stage('Publish') {\n      when { branch 'main' }")
        self.assertNotIn("OBAAF-JEN-012", rules(same_guard))

    def test_taint_through_ordinary_groovy(self):
        cases = ["def t = env.CHANGE_TITLE.trim()", "def t = env.CHANGE_TITLE ?: 'none'",
                 "def t = env['CHANGE_TITLE']", "def t = env.getProperty('CHANGE_BRANCH')",
                 "def m = [title: env.CHANGE_TITLE]\n def t = m", "def t = 'echo ' + env.CHANGE_TITLE",
                 "def t = String.format('%s', env.CHANGE_TITLE)",
                 "def t = sh(script: 'git --no-pager log -1 --pretty=%B', returnStdout: true)",
                 "def t = sh(script: 'git log -1 --format=\"%h %s\"', returnStdout: true)"]
        for case in cases:
            self.assertEqual(rules(f'node {{ {case}\n sh "echo ${{t}}" }}').get("OBAAF-JEN-009"), "high", case)
        self.assertEqual(rules("node { sh String.format('echo %s', env.CHANGE_TITLE) }").get("OBAAF-JEN-009"), "high")

    def test_more_credential_wrappers(self):
        for wrapper in ("docker.withRegistry(REGISTRY, REGISTRY_CREDS)",
                        "withVault(configuration: [vaultCredentialId: 'v'], vaultSecrets: [])",
                        "wrap([$class: 'VaultBuildWrapper', vaultSecrets: []])", "withAWS(role: 'deployer')"):
            self.assertIn("OBAAF-JEN-001", rules(f"node {{ {wrapper} {{ sh './gradlew test' }} }}"), wrapper)

    def test_inputs_that_crashed(self):
        for text in ("X", "node { sh 'x'" + " + 'x'" * 1200 + " }"):
            result = analyze(text)
            self.assertIsNone(result.error)

    def test_many_agents_are_linear(self):
        import time
        start = time.monotonic()
        result = analyze("node('n0') { sh 'make' }\n" * 4000)
        self.assertIsNone(result.error)
        self.assertLess(time.monotonic() - start, 10)

    def test_pod_specs_in_variables_and_resources(self):
        pod = "def podYaml = '''\nspec:\n  containers:\n  - name: a\n    image: x\n    securityContext:\n" \
              "      privileged: true\n'''\n"
        agent = "pipeline { agent { kubernetes { yaml %s } }\n stages { stage('a') { steps { sh 'make' } } } }"
        self.assertIn("OBAAF-JEN-006", rules(pod + agent % "podYaml"))
        self.assertEqual(status(agent % "libraryResource('pods/dind.yaml')", "OBAAF-JEN-006"), "unknown")

    def test_agent_stage_effects_in_post_and_git_options(self):
        post = """
pipeline { agent any
  stages { stage('fix') {
    steps { sh 'claude -p "fix"' }
    post { success { sh 'git push origin HEAD' } }
  } } }"""
        self.assertIn("OBAAF-JEN-003", rules(post))
        self.assertIn("OBAAF-JEN-003", rules(declarative("sh 'claude -p fix'\nsh 'git -C \"$WORKSPACE\" push'")))
        flags = declarative("withCredentials([string(credentialsId: 'k', variable: 'K')]) "
                            "{ sh 'claude --dangerously-skip-permissions -p \"review\"' }")
        self.assertEqual(rules(flags).get("OBAAF-JEN-001"), "high")

    def test_map_form_webhook_trigger(self):
        text = """
properties([pipelineTriggers([[$class: 'GenericTrigger', token: 'deploy-hook-4f1c2a',
  genericVariables: [[key: 'pr_title', value: '$.pull_request.title']]]])])
node { sh "echo Building ${pr_title}" }"""
        found = rules(text)
        self.assertIn("OBAAF-JEN-015", found)
        self.assertEqual(found.get("OBAAF-JEN-009"), "high")

    def test_inside_options_are_not_an_image(self):
        text = f"node {{ docker.image('maven@sha256:{'0' * 64}').inside('-u root -v $HOME/.m2:/root/.m2') {{ sh 'mvn' }} }}"
        self.assertNotIn("OBAAF-JEN-008", rules(text))
