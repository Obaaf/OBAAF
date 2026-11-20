"""Jenkins stages, agents and workspaces (flagship slice 2d.2j): OBAAF-JEN-002, 003, 006 and 007.

Every Jenkinsfile here is an inert test input: it is parsed, never run. The verdicts follow what the
Jenkins handbook says an agent does (Pipeline Syntax: the top-level agent is "where the entire Pipeline
... will execute"; `reuseNode` runs a container "on the node specified at the top-level of the Pipeline,
in the same workspace"), and what Jenkins does with a job's workspace directory on an agent: it keeps it
between allocations. docs/jenkins.md lists what the checker cannot decide.
"""

import textwrap
import unittest

import helpers  # noqa: F401  (puts src/ on the path)

from obaaf.catalog import load
from obaaf.checker import jenkins

CATALOG = load()


def analyze(text):
    return jenkins.analyze("Jenkinsfile", textwrap.dedent(text).encode(), CATALOG, None)


def findings(text, rule):
    return [(f.severity, f.line) for f in analyze(text).findings if f.rule == rule]


def status(text, rule):
    result = analyze(text)
    return next(row["status"] for row in jenkins.coverage(result, result.findings) if row["rule"] == rule)


def two_stages(first, second, top="agent { label 'linux' }", first_agent="", second_agent=""):
    return f"""
pipeline {{
  {top}
  stages {{
    stage('Fix') {{
      {first_agent}
      steps {{
        {first}
      }}
    }}
    stage('Push') {{
      {second_agent}
      steps {{
        {second}
      }}
    }}
  }}
}}
"""


AGENT = "sh 'claude -p \"fix the failing test\"'"
PUSH = "sh 'git push origin HEAD:main'"


class SharedWorkspaceTest(unittest.TestCase):
    """What the agent wrote reaches the effect in the same workspace: high."""

    def test_stages_under_the_top_level_agent_share_its_workspace(self):
        self.assertEqual(findings(two_stages(AGENT, PUSH), "OBAAF-JEN-003"), [("high", 14)])
        self.assertEqual(findings(two_stages(AGENT, PUSH, top="agent any"), "OBAAF-JEN-003"), [("high", 14)])

    def test_the_pipeline_post_block_runs_in_the_top_level_workspace(self):
        text = """
pipeline {
  agent { label 'linux' }
  stages {
    stage('Fix') {
      steps { sh 'claude -p fix' }
    }
  }
  post {
    success { sh 'git push origin HEAD' }
  }
}
"""
        self.assertEqual(findings(text, "OBAAF-JEN-003"), [("high", 10)])

    def test_nested_stages_and_the_parent_post_share_the_parent_workspace(self):
        text = """
pipeline {
  agent { label 'linux' }
  stages {
    stage('Maintain') {
      stages {
        stage('Fix') {
          steps { sh 'claude -p fix' }
        }
        stage('Ship') {
          steps { sh 'git push' }
        }
      }
      post {
        success { sh 'npm publish' }
      }
    }
  }
}
"""
        self.assertEqual(findings(text, "OBAAF-JEN-003"), [("high", 11), ("high", 15)])

    def test_scripted_stages_inside_one_node_share_its_workspace(self):
        text = """
node('linux') {
  sh 'claude -p fix'
  stage('Fix') { sh 'claude -p again' }
  stage('Push') { sh 'git push' }
}
"""
        self.assertEqual(findings(text, "OBAAF-JEN-003"), [("high", 5)])

    def test_reuse_node_runs_the_container_in_the_same_workspace(self):
        text = two_stages(AGENT, "sh 'npm publish'",
                          first_agent="agent { docker { image 'node:20'; reuseNode true } }")
        self.assertEqual(findings(text, "OBAAF-JEN-003"), [("high", 14)])
        # A reuseNode the file does not fix is read as reused.
        computed = text.replace("reuseNode true", "reuseNode params.REUSE")
        self.assertEqual(findings(computed, "OBAAF-JEN-003"), [("high", 14)])

    def test_a_stage_with_agent_none_stays_in_the_top_level_workspace(self):
        text = two_stages(AGENT, PUSH, second_agent="agent none")
        self.assertEqual(findings(text, "OBAAF-JEN-003"), [("high", 14)])

    def test_another_stage_starting_a_job_with_what_the_agent_wrote(self):
        text = two_stages("sh 'claude -p \"write NOTES.md\"'",
                          "build job: 'release', parameters: [string(name: 'NOTES', value: readFile('NOTES.md'))]")
        self.assertEqual(findings(text, "OBAAF-JEN-003"), [("high", 14)])

    def test_a_scripted_stage_inside_a_declarative_stage(self):
        text = """
pipeline {
  agent { label 'linux' }
  stages {
    stage('Fix') {
      steps {
        script {
          stage('Agent') { sh 'claude -p fix' }
          sh 'git push'
        }
      }
    }
  }
}
"""
        self.assertEqual(findings(text, "OBAAF-JEN-003"), [("high", 9)])

    def test_sibling_parallel_branches_in_one_workspace(self):
        text = """
pipeline {
  agent { label 'linux' }
  stages {
    stage('Both') {
      parallel {
        stage('Push') { steps { sh 'git push' } }
        stage('Fix') { steps { sh 'claude -p fix' } }
      }
    }
  }
}
"""
        self.assertEqual(findings(text, "OBAAF-JEN-003"), [("high", 7)])

    def test_ws_on_the_same_node_is_written_by_the_same_user(self):
        text = """
node('linux') {
  sh 'claude -p fix'
  ws("${WORKSPACE}@docs") {
    sh 'git push'
  }
}
"""
        result = [f for f in analyze(text).findings if f.rule == "OBAAF-JEN-003"]
        self.assertEqual([(f.severity, f.line) for f in result], [("high", 5)])
        self.assertIn("on the same node", result[0].message)


class StashTest(unittest.TestCase):
    STASHED = """
pipeline {
  agent none
  stages {
    stage('Fix') {
      agent { label 'sandbox' }
      steps {
        FIRST
        SECOND
      }
    }
    stage('Push') {
      agent { label 'trusted' }
      steps {
        unstash 'tree'
        sh 'git push'
      }
    }
  }
}
"""

    def case(self, first, second):
        return self.STASHED.replace("FIRST", first).replace("SECOND", second)

    def test_a_stash_taken_after_the_agent_carries_what_it_wrote(self):
        text = self.case(AGENT, "stash name: 'tree', includes: '**'")
        result = [f for f in analyze(text).findings if f.rule == "OBAAF-JEN-003"]
        self.assertEqual([(f.severity, f.line) for f in result], [("high", 16)])
        self.assertIn("stash 'tree'", result[0].message)

    def test_a_computed_stash_name_may_be_the_one_unstashed(self):
        text = self.case(AGENT, "stash name: \"tree-${env.BUILD_ID}\"")
        self.assertEqual(findings(text, "OBAAF-JEN-003"), [("high", 16)])

    def test_a_stash_taken_before_the_agent_or_under_another_name(self):
        self.assertEqual(findings(self.case("stash 'tree'", AGENT), "OBAAF-JEN-003"), [])
        self.assertEqual(findings(self.case(AGENT, "stash 'report'"), "OBAAF-JEN-003"), [])
        self.assertEqual(status(self.case(AGENT, "stash 'report'"), "OBAAF-JEN-003"), "pass")


class SeparateWorkspaceTest(unittest.TestCase):
    """Separate allocations: no finding where their agents differ, an unknown where they may not."""

    def test_nodes_with_different_labels_do_not_share(self):
        text = """
node('sandbox') { stage("${env.A}") { sh 'claude -p x' } }
node('trusted') { stage("${env.B}") { sh 'git push' } }
"""
        self.assertEqual(status(text, "OBAAF-JEN-003"), "pass")
        same_name = """
node('sandbox') { stage('Work') { sh 'claude -p x' } }
node('trusted') { stage('Work') { sh 'git push https://example.invalid/other.git' } }
"""
        self.assertEqual(status(same_name, "OBAAF-JEN-003"), "pass")
        one_stage = """
stage('Nightly') {
  node('sandbox') { sh 'claude -p x' }
  node('trusted') { sh 'git push https://example.invalid/other.git' }
}
"""
        self.assertEqual(status(one_stage, "OBAAF-JEN-003"), "pass")

    def test_closures_are_judged_where_they_are_called(self):
        text = """
def review = { sh 'claude -p review' }
def release = { sh 'git push' }
stage('Review') { node('sandbox') { review() } }
stage('Release') { node('trusted') { release() } }
"""
        self.assertEqual(status(text, "OBAAF-JEN-003"), "pass")
        # Read where it is written, it was a second OBAAF-JEN-007 finding for a stage named 'pipeline'.
        self.assertEqual(len(findings(text, "OBAAF-JEN-007")), 1)
        together = """
def fix = { sh 'claude -p fix'; sh 'git push' }
node('linux') { stage('Fix') { fix() } }
"""
        self.assertEqual(findings(together, "OBAAF-JEN-003"), [("high", 2)])
        self.assertEqual(len([f for f in analyze(together).findings if f.rule == "OBAAF-JEN-003"]), 1)

    def test_the_same_label_or_any_agent_may_be_the_same_machine(self):
        text = two_stages(AGENT, PUSH, top="agent none", first_agent="agent { label 'linux' }",
                          second_agent="agent { label 'linux' }")
        self.assertEqual(findings(text, "OBAAF-JEN-003"), [])
        self.assertEqual(status(text, "OBAAF-JEN-003"), "unknown")
        anywhere = text.replace("agent { label 'linux' }", "agent any", 1)
        self.assertEqual(status(anywhere, "OBAAF-JEN-003"), "unknown")
        apart = text.replace("agent { label 'linux' }", "agent { label 'sandbox' }", 1)
        self.assertEqual(status(apart, "OBAAF-JEN-003"), "pass")

    def test_pods_are_never_the_same_machine(self):
        pod = "agent { kubernetes { yaml 'spec: {automountServiceAccountToken: false}' } }"
        text = two_stages(AGENT, PUSH, top="agent none", first_agent=pod, second_agent=pod)
        self.assertEqual(status(text, "OBAAF-JEN-003"), "pass")


class EarlierEffectTest(unittest.TestCase):
    """An effect before the agent in the same workspace meets what the agent left there in the next build."""

    MIRROR = """
pipeline {
  AGENT
  stages {
    stage('Mirror') {
      steps {
        BEFORE
        sh 'git push mirror HEAD'
        sh 'claude -p "summarise the diff" > summary.md'
      }
    }
  }
}
"""

    def case(self, agent="agent { label 'linux' }", before=""):
        return self.MIRROR.replace("AGENT", agent).replace("BEFORE", before)

    def test_a_kept_workspace_is_medium(self):
        result = [f for f in analyze(self.case()).findings if f.rule == "OBAAF-JEN-003"]
        self.assertEqual([(f.severity, f.line) for f in result], [("medium", 8)])
        self.assertIn("next build", result[0].message)

    def test_a_fresh_pod_or_a_cleaned_workspace_is_not(self):
        pod = "agent { kubernetes { yaml 'spec: {automountServiceAccountToken: false}' } }"
        self.assertEqual(status(self.case(agent=pod), "OBAAF-JEN-003"), "pass")
        self.assertEqual(status(self.case(before="cleanWs()"), "OBAAF-JEN-003"), "pass")
        self.assertEqual(status(self.case(before="deleteDir()"), "OBAAF-JEN-003"), "pass")
        # deleteDir() inside dir() empties that folder only.
        self.assertEqual(findings(self.case(before="dir('out') { deleteDir() }"), "OBAAF-JEN-003"), [("medium", 8)])


class FallbackTest(unittest.TestCase):
    def test_steps_with_no_known_workspace_keep_the_stage_grouping(self):
        # agent none and no stage agent: Jenkins would refuse to run sh here, but the finding stays.
        text = two_stages(f"{AGENT}\n{PUSH}", "echo done", top="agent none")
        self.assertEqual(findings(text, "OBAAF-JEN-003"), [("high", 9)])

    def test_a_method_nothing_here_calls_shares_its_caller_workspace(self):
        text = """
def call() {
  sh 'claude -p fix'
  sh 'git push'
}
"""
        self.assertEqual(findings(text, "OBAAF-JEN-003"), [("high", 4)])

    def test_the_body_of_a_step_whose_code_is_elsewhere(self):
        text = """
withLibraryNode {
  sh 'claude -p fix'
  sh 'git push'
}
"""
        self.assertEqual(findings(text, "OBAAF-JEN-003"), [("high", 4)])


class ControllerTest(unittest.TestCase):
    def test_a_label_expression_that_can_select_the_built_in_node(self):
        self.assertEqual(findings("node('built-in || linux') { sh 'make' }", "OBAAF-JEN-002"), [("high", 1)])
        self.assertEqual(findings("node('(master) && x') { sh 'make' }", "OBAAF-JEN-002"), [("high", 1)])
        self.assertEqual(findings('node(\'"built-in" || linux\') { sh \'make\' }', "OBAAF-JEN-002"), [("high", 1)])
        for negated in ("!built-in && linux", "!(built-in || master)", "linux && !master"):
            self.assertEqual(findings(f"node('{negated}') {{ sh 'make' }}", "OBAAF-JEN-002"), [], negated)
        self.assertEqual(findings("node('built-in-tools') { sh 'make' }", "OBAAF-JEN-002"), [])

    def test_a_container_on_the_built_in_node(self):
        text = two_stages("sh 'make'", "sh 'make test'", top="agent { docker { image 'node:20'; label 'built-in' } }")
        self.assertEqual(findings(text, "OBAAF-JEN-002"), [("high", 3)])


class SharedLabelTest(unittest.TestCase):
    TEXT = """
pipeline {
  agent none
  stages {
    stage('Fix') {
      agent { label 'linux' }
      when { branch 'main' }
      steps { sh 'claude -p fix' }
    }
    stage('Release') {
      agent { label 'LABEL' }
      when { branch 'main' }
      steps { sh 'npm publish' }
    }
  }
}
"""

    def test_an_agent_and_a_publishing_stage_on_one_persistent_label(self):
        result = [f for f in analyze(self.TEXT.replace("LABEL", "linux")).findings if f.rule == "OBAAF-JEN-002"]
        self.assertEqual([(f.severity, f.line) for f in result], [("medium", 11)])
        self.assertIn("an AI agent (stage 'Fix')", result[0].message)
        self.assertEqual(findings(self.TEXT.replace("LABEL", "release"), "OBAAF-JEN-002"), [])

    def test_an_agent_stage_alone_is_not_paired_with_itself(self):
        text = """
pipeline {
  agent none
  stages {
    stage('Fix') {
      agent { label 'linux' }
      when { branch 'main' }
      steps {
        withCredentials([string(credentialsId: 'model-key', variable: 'KEY')]) { sh 'claude -p fix' }
      }
    }
  }
}
"""
        self.assertEqual(findings(text, "OBAAF-JEN-002"), [])


class NoNetworkTest(unittest.TestCase):
    def review(self, args):
        return f"""
pipeline {{
  agent {{ docker {{ image 'agent-image'; args '{args}' }} }}
  stages {{
    stage('Review') {{
      steps {{ sh 'claude -p review' }}
    }}
  }}
}}
"""

    def test_a_container_with_no_network_limits_the_agent(self):
        for args in ("--network none", "--network=none", "--rm --net none -e CI=1", '--network "none"'):
            self.assertEqual(status(self.review(args), "OBAAF-JEN-007"), "pass", args)
        inside = "node('linux') { docker.image('agent-image').inside('--network=none') { sh 'claude -p x' } }"
        self.assertEqual(status(inside, "OBAAF-JEN-007"), "pass")

    def test_what_can_undo_or_bypass_it(self):
        for args in ("--network none --privileged", "--network none -v /var/run/docker.sock:/var/run/docker.sock",
                     "--network none -v /run/proxy.sock:/run/proxy.sock", "--network none --network host",
                     "--network bridge", "--network ${NET}", "--cap-add SYS_ADMIN --network none"):
            self.assertEqual(findings(self.review(args), "OBAAF-JEN-007"), [("low", 6)], args)

    def test_an_agent_outside_the_container_is_not_limited(self):
        text = """
node('linux') {
  docker.image('tools').inside('--network none') { sh 'make' }
  sh 'claude -p review'
}
"""
        self.assertEqual(findings(text, "OBAAF-JEN-007"), [("low", 4)])



class ReviewTest(unittest.TestCase):
    """Ways past and false positives the independent review of slice 2d.2j found (R-numbers are its cases,
    recorded in docs/bypass-attempts.md)."""

    def test_r003_r005_retry_and_wait_until_run_the_effect_again(self):
        for wrapper in ("retry(3)", "waitUntil", "timeout(5) { retry(2)"):
            close = "}" * (2 if "timeout" in wrapper else 1)
            text = f"node('linux') {{\n  {wrapper} {{\n    sh 'git push'\n    sh 'claude -p fix'\n  {close}\n}}\n"
            self.assertEqual(findings(text, "OBAAF-JEN-003"), [("high", 3)], wrapper)
        stage_retry = two_stages(f"{PUSH}\n{AGENT}", "echo ok").replace("steps {", "options { retry(2) }\n      steps {", 1)
        self.assertEqual(findings(stage_retry, "OBAAF-JEN-003"), [("high", 9)])

    def test_r019_r021_a_pod_workspace_volume_that_outlives_the_pod(self):
        pvc = ("agent { kubernetes { yaml 'spec: {automountServiceAccountToken: false}'; workspaceVolume "
               "persistentVolumeClaimWorkspaceVolume(claimName: 'ci-ws', readOnly: false) } }")
        text = two_stages(AGENT, PUSH, top="agent none", first_agent=pvc, second_agent=pvc)
        # Two pods on one named claim share its directory (the second review: R019 is high, not unknown).
        result = [f for f in analyze(text).findings if f.rule == "OBAAF-JEN-003"]
        self.assertEqual([(f.severity, f.line) for f in result], [("high", 14)])
        self.assertIn("claim 'ci-ws'", result[0].message)
        other = text.replace("'ci-ws'", "'other-ws'", 1)
        self.assertEqual(status(other, "OBAAF-JEN-003"), "pass")
        computed = text.replace("claimName: 'ci-ws'", "claimName: params.CLAIM", 1)
        self.assertEqual(status(computed, "OBAAF-JEN-003"), "unknown")
        before = two_stages(f"{PUSH}\n{AGENT}", "echo ok", top=pvc)
        self.assertEqual(findings(before, "OBAAF-JEN-003"), [("medium", 8)])
        scripted = """
podTemplate(workspaceVolume: hostPathWorkspaceVolume(hostPath: '/srv/ws')) {
  node(POD_LABEL) {
    sh 'git push'
    sh 'claude -p fix'
  }
}
"""
        self.assertEqual(findings(scripted, "OBAAF-JEN-003"), [("medium", 4)])
        ephemeral = scripted.replace("hostPathWorkspaceVolume(hostPath: '/srv/ws')", "emptyDirWorkspaceVolume()")
        self.assertEqual(findings(ephemeral, "OBAAF-JEN-003"), [])

    def test_r028_archived_artifacts_brought_back_with_unarchive(self):
        text = StashTest.STASHED.replace("FIRST", AGENT).replace("SECOND", "archiveArtifacts artifacts: '**'") \
            .replace("unstash 'tree'", "unarchive mapping: ['**': '.']")
        result = [f for f in analyze(text).findings if f.rule == "OBAAF-JEN-003"]
        self.assertEqual([(f.severity, f.line) for f in result], [("high", 16)])
        self.assertIn("artifacts archived", result[0].message)
        # An archive is not a stash: unstash brings back only stashes.
        crossed = StashTest.STASHED.replace("FIRST", AGENT).replace("SECOND", "archiveArtifacts artifacts: '**'")
        self.assertEqual(findings(crossed, "OBAAF-JEN-003"), [])

    def test_r034_r036_a_partial_clean_keeps_git(self):
        mirror = EarlierEffectTest()
        for clean in ("cleanWs(patterns: [[pattern: 'build/**', type: 'INCLUDE']])",
                      "cleanWs(deleteDirs: false, patterns: [[pattern: '.git/**', type: 'EXCLUDE']])",
                      "cleanWs(cleanWhenSuccess: false)", "cleanWs(externalDelete: 'rm -rf %s')"):
            self.assertEqual(findings(mirror.case(before=clean), "OBAAF-JEN-003"), [("medium", 8)], clean)
        self.assertEqual(status(mirror.case(before="cleanWs(notFailBuild: true)"), "OBAAF-JEN-003"), "pass")

    def test_r014_r107_r108_labels_and_paths_that_may_be_one_machine(self):
        overlap = two_stages(AGENT, PUSH, top="agent none", first_agent="agent { label 'linux && docker' }",
                             second_agent="agent { label ' (linux) ' }")
        self.assertEqual(status(overlap, "OBAAF-JEN-003"), "unknown")
        apart = overlap.replace("' (linux) '", "'windows'")
        self.assertEqual(status(apart, "OBAAF-JEN-003"), "pass")
        same_path = """
node('sandbox') { ws('/srv/ci/shared') { sh 'claude -p fix' } }
node('trusted') { ws('/srv/ci/shared') { sh 'git push' } }
"""
        self.assertEqual(status(same_path, "OBAAF-JEN-003"), "unknown")
        self.assertEqual(status(same_path.replace("/srv/ci/shared') { sh 'git", "/srv/ci/other') { sh 'git"),
                                "OBAAF-JEN-003"), "pass")

    def test_r091_r092_labels_that_reach_the_controller(self):
        self.assertEqual(findings("def where = 'built-in'\nnode(where) { sh 'make' }", "OBAAF-JEN-002"), [("high", 2)])
        negated = analyze("node('!windows') { sh 'make' }")
        reasons = [u.reason for u in negated.unknowns if u.rule == "OBAAF-JEN-002"]
        self.assertTrue(any("requires none" in r for r in reasons), reasons)

    def test_r075_r085_r100_a_stage_with_agent_none_stays_in_the_enclosing_container(self):
        top = "agent { docker { image 'agent-image'; args 'ARGS' } }"
        text = two_stages(AGENT, "echo ok", top=top.replace("ARGS", "--network none"), first_agent="agent none")
        self.assertEqual(status(text, "OBAAF-JEN-007"), "pass")
        privileged = two_stages(AGENT, "echo ok", top=top.replace("ARGS", "--privileged"), first_agent="agent none")
        self.assertEqual(findings(privileged, "OBAAF-JEN-006"), [("high", 3)])
        controller = two_stages(AGENT, "echo ok", top="agent { label 'built-in' }", first_agent="agent none")
        self.assertEqual(findings(controller, "OBAAF-JEN-002"), [("high", 3)])

    def test_r073_a_step_the_plugin_runs_itself_is_not_in_the_container(self):
        text = NoNetworkTest().review("--network none").replace("sh 'claude -p review'", "aiAgent(prompt: 'review')")
        self.assertEqual(status(text, "OBAAF-JEN-007"), "fail")

    def test_r054_r072_docker_options_read_as_docker_reads_them(self):
        review = NoNetworkTest().review
        reaching = ("-v /var/run:/var/run", "--mount type=bind,source=/,target=/host", "-v/var/run/docker.sock:/s",
                    "--cap-add CAP_SYS_ADMIN", "--cap-add=sys_module", "--device /dev/sda", "--volume \"/:/host\"",
                    "-itv /var/run/docker.sock:/s", "-v /run/containerd/containerd.sock:/c", '--network "host"',
                    "--privileged=true", "--security-opt label=disable", "--pid=host")
        for args in reaching:
            self.assertEqual([s for s, _ in findings(review(args), "OBAAF-JEN-006")], ["high"], args)
            self.assertEqual(status(review(f"--network none {args}"), "OBAAF-JEN-007"), "fail", args)
        for args in ("--privileged=false", "-v /home/ci/.m2:/root/.m2", "-e CI=1 -v cache:/cache", "--rm -it"):
            self.assertEqual(findings(review(args), "OBAAF-JEN-006"), [], args)
        self.assertEqual(status(review("--volumes-from jenkins"), "OBAAF-JEN-006"), "unknown")
        self.assertEqual(status(review("--network none --privileged=false"), "OBAAF-JEN-007"), "pass")

    def test_r111_host_paths_under_no_network_are_named(self):
        result = [f for f in analyze(NoNetworkTest().review("--network none -v /opt/socks5:/socks5")).findings
                  if f.rule == "OBAAF-JEN-007"]
        self.assertEqual(len(result), 1)
        self.assertIn("/opt/socks5", result[0].message)
        self.assertIn("--network none", result[0].message)

    def test_r083_r090_pod_settings_from_template_arguments_and_json(self):
        template = """
podTemplate(ARGS) {
  node(POD_LABEL) {
    container('agent') { sh 'claude -p fix' }
  }
}
"""
        for args, setting in (
                ("containers: [containerTemplate(name: 'agent', image: 'x')]", "service account token"),
                ("volumes: [hostPathVolume(hostPath: '/var/run/docker.sock', mountPath: '/s')]", "Docker socket"),
                ("containers: [containerTemplate(name: 'agent', image: 'x', privileged: true)]", "privileged")):
            result = [f for f in analyze(template.replace("ARGS", args)).findings if f.rule == "OBAAF-JEN-006"]
            self.assertEqual(len(result), 1, args)
            self.assertIn(setting, result[0].message)
        json_spec = ('agent { kubernetes { yaml \'{"spec": {"automountServiceAccountToken": false, "containers": '
                     '[{"name": "a", "image": "x", "securityContext": {"privileged": true}}]}}\' } }')
        result = [f for f in analyze(two_stages(AGENT, "echo ok", top=json_spec)).findings if f.rule == "OBAAF-JEN-006"]
        self.assertEqual(len(result), 1)
        self.assertIn("a privileged container", result[0].message)
        self.assertNotIn("token", result[0].message)
        # node(POD_LABEL) is the pod: no "agent selection" unknown for a label computed at run time.
        self.assertEqual(status(template.replace("ARGS", "yaml: 'spec: {automountServiceAccountToken: false}'"),
                                "OBAAF-JEN-002"), "pass")

    def test_large_inputs_stay_fast(self):
        import time
        steps = "\n".join(f"sh 'git push origin b{i}'\nsh 'claude -p step{i}'" for i in range(400))
        start = time.monotonic()
        analyze(f"node('linux') {{\n{steps}\n}}")
        self.assertLess(time.monotonic() - start, 3.0)



class SecondReviewTest(unittest.TestCase):
    """The second review pass on the fixes (cases R116 to R177)."""

    def test_r116_r126_docker_options_as_docker_and_jenkins_read_them(self):
        review = NoNetworkTest().review
        for args in ("--privileged=t", "--privileged=True", "-v //var/run://var/run",
                     "--mount type=bind,Source=/var/run,target=/r", '--mount type=bind,"src=/var/run",target=/r',
                     "--mount type=bind,src=../../../../../..,target=/h", "--use-api-socket",
                     "--device-cgroup-rule=b_*:*_rwm", r"-v C:\\:C:\\host", r"-v \\\\.\\pipe\\docker_engine:/p",
                     "-v /var/lib/docker:/d:ro", "-v /proc:/host/proc:ro"):
            self.assertNotEqual(status(review(args), "OBAAF-JEN-006"), "pass", args)
            self.assertEqual(status(review(f"--network none {args}"), "OBAAF-JEN-007"), "fail", args)
        # Jenkins splits `args` itself; a backslash makes the split uncertain, so both readings count.
        self.assertEqual(status(review(r"-e A=\\ --privileged"), "OBAAF-JEN-006"), "fail")

    def test_r127_r137_ordinary_mounts_are_not_host_access(self):
        review = NoNetworkTest().review
        for args in ("-v /root/.m2:/root/.m2", "-v /etc/localtime:/etc/localtime:ro", "-v /etc/passwd:/etc/passwd:ro",
                     "-v /dev/shm:/dev/shm", "-v /var/run/docker.sock", "-v $HOME/.m2:/root/.m2",
                     "-v /home/jenkins/.gradle:/root/.gradle"):
            self.assertEqual(findings(review(args), "OBAAF-JEN-006"), [], args)
        # A whole system folder still is, and so is a socket's folder read-only.
        for args in ("-v /etc:/host-etc", "-v /run:/run:ro", "-v /root:/root"):
            self.assertEqual([s for s, _ in findings(review(args), "OBAAF-JEN-006")], ["high"], args)

    def test_r143_r151_pod_specs(self):
        def pod(spec):
            return two_stages(AGENT, "echo ok", top="agent { kubernetes { yaml '''" + spec + "''' } }")

        def problems(spec):
            return " ".join(f.message for f in analyze(pod(spec)).findings if f.rule == "OBAAF-JEN-006")
        safe = "spec:\n  automountServiceAccountToken: false\n  containers:\n  - name: a\n    image: x\n"
        self.assertEqual(problems(safe), "")
        self.assertIn("privileged", problems(safe.replace("image: x", "image: x\n    securityContext:\n"
                                                                        "      privileged: 'true'")))
        self.assertEqual(problems(safe.replace("spec:\n", "spec:\n  hostUsers: false\n")), "")
        projected = safe + ("  volumes:\n  - name: t\n    projected:\n      sources:\n"
                            "      - serviceAccountToken:\n          path: token\n")
        self.assertIn("service account token", problems(projected))
        second = "spec:\n  containers:\n  - name: a\n    image: x\n---\nspec:\n  automountServiceAccountToken: false\n"
        self.assertIn("service account token", problems(second))
        env = safe.replace("image: x", "image: x\n    env:\n    - name: NOTE\n      value: no docker.sock here")
        self.assertEqual(problems(env), "")
        aliases = ("spec:\n  automountServiceAccountToken: false\n  hostAliases: &h\n"
                   + "".join(f"  - ip: 10.0.0.{i % 250}\n    hostnames: [h{i}]\n" for i in range(520))
                   + "  x: [" + ", ".join(["*h"] * 40) + "]\n  containers:\n  - name: a\n    image: x\n"
                   "    securityContext: {privileged: true}\n")
        self.assertNotEqual(status(pod(aliases), "OBAAF-JEN-006"), "pass")

    def test_r157_r159_pods_and_their_workspace_volumes(self):
        for node in ("node(label)", 'node("${POD_LABEL}")', "node(env.POD_LABEL)"):
            text = ('def label = "agent-${UUID.randomUUID()}"\npodTemplate(label: label, containers: '
                    f"[containerTemplate(name: 'a', image: 'x')]) {{\n  {node} {{ sh 'claude -p fix' }}\n}}\n")
            self.assertIn("service account token",
                          " ".join(f.message for f in analyze(text).findings if f.rule == "OBAAF-JEN-006"), node)
        root = ("podTemplate(yaml: 'spec: {automountServiceAccountToken: false}', workspaceVolume: "
                "hostPathWorkspaceVolume(hostPath: '/')) {\n  node(POD_LABEL) { sh 'make' }\n}\n")
        self.assertIn("host root", " ".join(f.message for f in analyze(root).findings if f.rule == "OBAAF-JEN-006"))

    def test_r101_r153_r155_r171_label_expressions(self):
        self.assertEqual(status("node('docker -> linux') { sh 'make' }", "OBAAF-JEN-002"), "unknown")
        reasons = [u.reason for u in analyze("node('docker -> linux') { sh 'make' }").unknowns]
        self.assertTrue(any("requires none" in r for r in reasons), reasons)
        self.assertEqual(findings("node('linux -> built-in') { sh 'make' }", "OBAAF-JEN-002"), [("high", 1)])
        for left in ("sandbox -> gpu", "linux <-> sandbox"):
            text = two_stages(AGENT, PUSH, top="agent none", first_agent=f"agent {{ label '{left}' }}",
                              second_agent="agent { label 'trusted' }")
            self.assertEqual(status(text, "OBAAF-JEN-003"), "unknown", left)
        shared = SharedLabelTest.TEXT.replace("label 'linux'", "label 'linux && docker'").replace("LABEL", "linux")
        result = [f for f in analyze(shared).findings if f.rule == "OBAAF-JEN-002"]
        self.assertEqual([(f.severity, f.line) for f in result], [("medium", 11)])
        self.assertIn("both require 'linux'", result[0].message)

    def test_r138_r139_other_ways_to_wipe_the_workspace(self):
        mirror = EarlierEffectTest()
        for clean in ("step([$class: 'WsCleanup'])",
                      "checkout([$class: 'GitSCM', branches: [[name: 'main']], extensions: [[$class: 'WipeWorkspace']], "
                      "userRemoteConfigs: [[url: 'https://example.invalid/r.git']]])"):
            self.assertEqual(status(mirror.case(before=clean), "OBAAF-JEN-003"), "pass", clean)
        keeps_git = ("checkout([$class: 'GitSCM', extensions: [[$class: 'CleanBeforeCheckout']], "
                     "userRemoteConfigs: [[url: 'https://example.invalid/r.git']]])")
        self.assertEqual(findings(mirror.case(before=keeps_git), "OBAAF-JEN-003"), [("medium", 8)])


class ThirdReviewTest(unittest.TestCase):
    """The third review pass (cases R178 to R212)."""

    def test_r191_the_built_in_node_carries_one_of_its_labels(self):
        self.assertEqual(findings("node('built-in && !master') { sh 'claude -p x' }", "OBAAF-JEN-002"), [("high", 1)])
        self.assertEqual(findings("node('master && !built-in') { sh 'make' }", "OBAAF-JEN-002"), [("high", 1)])
        for elsewhere in ("linux && !master", "!built-in", "!(built-in || master) && linux"):
            self.assertEqual(findings(f"node('{elsewhere}') {{ sh 'make' }}", "OBAAF-JEN-002"), [], elsewhere)

    def test_r205_r206_a_computed_label_in_a_pod_template_is_not_always_the_pod(self):
        text = ("podTemplate(yaml: 'spec: {automountServiceAccountToken: false}') {\n"
                "  node(params.TARGET ?: 'built-in') { sh 'claude -p fix' }\n}\n")
        self.assertEqual(status(text, "OBAAF-JEN-002"), "unknown")
        static = ("podTemplate(yaml: 'spec: {automountServiceAccountToken: false}') {\n"
                  "  node(params.STATIC_AGENT) {\n    sh 'git push'\n    sh 'claude -p fix'\n  }\n}\n")
        self.assertEqual(findings(static, "OBAAF-JEN-003"), [("medium", 3)])

    def test_r183_r188_homes_credentials_and_runtime_folders(self):
        review = NoNetworkTest().review
        for args in ("-v /home/jenkins:/home/jenkins", "-v /run/user/1000:/run/user/1000", "-v /root/.ssh:/root/.ssh:ro",
                     "-v /etc:/host/etc:ro", "-v /home/ci/.docker:/root/.docker"):
            self.assertEqual([s for s, _ in findings(review(args), "OBAAF-JEN-006")], ["high"], args)
            self.assertEqual(status(review(f"--network none {args}"), "OBAAF-JEN-007"), "fail", args)
        for args in ("-v /var/lib/jenkins/.m2:/root/.m2", "-v /sys/fs/cgroup:/sys/fs/cgroup:ro",
                     "-v /usr/share/zoneinfo:/usr/share/zoneinfo:ro", "-v /opt:/opt:ro"):
            self.assertEqual(findings(review(args), "OBAAF-JEN-006"), [], args)
        self.assertEqual([s for s, _ in findings(review("-v /var/lib/jenkins/secrets:/s"), "OBAAF-JEN-006")], ["high"])

    def test_r201_r204_nfs_and_host_path_workspaces(self):
        def nfs(server, path):
            return ("agent { kubernetes { yaml 'spec: {automountServiceAccountToken: false}'; workspaceVolume "
                    f"nfsWorkspaceVolume(serverAddress: '{server}', serverPath: '{path}', readOnly: false) }} }}")
        same = two_stages(AGENT, PUSH, top="agent none", first_agent=nfs("nfs1", "/exports/ws"),
                          second_agent=nfs("nfs1", "/exports/ws/"))
        self.assertEqual(findings(same, "OBAAF-JEN-003"), [("high", 14)])
        apart = two_stages(AGENT, PUSH, top="agent none", first_agent=nfs("nfs1", "/exports/ws"),
                           second_agent=nfs("nfs2.example", "/exports/ws"))
        self.assertEqual(findings(apart, "OBAAF-JEN-003"), [])

        def host(path):
            return ("agent { kubernetes { yaml 'spec: {automountServiceAccountToken: false}'; workspaceVolume "
                    f"hostPathWorkspaceVolume(hostPath: '{path}') }} }}")
        node_dirs = two_stages(AGENT, PUSH, top="agent none", first_agent=host("/srv/ws"), second_agent=host("/srv/ws/"))
        self.assertEqual(status(node_dirs, "OBAAF-JEN-003"), "unknown")

    def test_r208_privileged_written_as_one(self):
        spec = "spec:\n  automountServiceAccountToken: false\n  containers:\n  - name: a\n    image: x\n    " \
               "securityContext:\n      privileged: 1\n"
        text = two_stages(AGENT, "echo ok", top="agent { kubernetes { yaml '''" + spec + "''' } }")
        self.assertEqual([s for s, _ in findings(text, "OBAAF-JEN-006")], ["high"])

if __name__ == "__main__":
    unittest.main()
