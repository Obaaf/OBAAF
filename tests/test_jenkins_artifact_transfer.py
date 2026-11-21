"""Flagship slice 2d.2m: bypass attempts on OBAAF-JEN-010, artifacts from another build fetched by a reference that
moves and published without a check that ties them to a build record.

Each case is one attempt by a reviewer that did not write the rule, run as a Jenkinsfile. `expected` is what OBAAF-JEN-010
says after the slice ("finding-high", "finding-medium", "unknown" for cannot tell, or "quiet"); `before` is what it said at
`651cb4e`. LIMITS names the cases whose answer is a stated limit, with the reason; the record is docs/bypass-attempts.md.
"""
import textwrap
import time
import unittest

from obaaf.catalog import load
from obaaf.checker import jenkins

CASES = [
    ('C01_default_selector_same_stage', 'finding-high', 'finding-high',
     "pipeline {\n  agent any\n  stages {\n    stage('Release') {\n      steps {\n        copyArtifacts(projectName: 'b')\n        sh 'aws s3 cp out s3://r/'\n      }\n    }\n  }\n}\n"),
    ('C02_default_selector_later_stage', 'finding-medium', 'finding-medium',
     "pipeline {\n  agent any\n  stages {\n    stage('Release') {\n      steps {\n        copyArtifacts(projectName: 'b')\n      }\n    }\n    stage('Publish') {\n      steps {\n        sh 'aws s3 cp out s3://r/'\n      }\n    }\n  }\n}\n"),
    ('C03_specific_literal', 'quiet', 'quiet',
     "pipeline {\n  agent any\n  stages {\n    stage('Release') {\n      steps {\n        copyArtifacts(projectName: 'b', selector: specific('42'))\n        sh 'aws s3 cp out s3://r/'\n      }\n    }\n  }\n}\n"),
    ('C04_obaaf_verify_between', 'quiet', 'quiet',
     "pipeline {\n  agent any\n  stages {\n    stage('Release') {\n      steps {\n        copyArtifacts(projectName: 'b')\n        sh 'obaaf verify release --policy p --artifacts out'\n        sh 'aws s3 cp out s3://r/'\n      }\n    }\n  }\n}\n"),
    ('C05_copy_no_publish', 'quiet', 'quiet',
     "pipeline {\n  agent any\n  stages {\n    stage('Release') {\n      steps {\n        copyArtifacts(projectName: 'b')\n        sh 'make'\n      }\n    }\n  }\n}\n"),
    ('C06_lastSuccessful', 'finding-high', 'finding-high',
     "pipeline {\n  agent any\n  stages {\n    stage('Release') {\n      steps {\n        copyArtifacts(projectName: 'b', selector: lastSuccessful())\n        sh 'aws s3 cp out s3://r/'\n      }\n    }\n  }\n}\n"),
    ('C07_build_then_specific_number', 'quiet', 'quiet',
     'pipeline {\n  agent any\n  stages {\n    stage(\'Release\') {\n      steps {\n        script {\n          def r = build job: \'b\', wait: true\n          copyArtifacts(projectName: \'b\', selector: specific("${r.number}"))\n        }\n        sh \'aws s3 cp out s3://r/\'\n      }\n    }\n  }\n}\n'),
    ('C08_upstream_no_fallback', 'quiet', 'quiet',
     "pipeline {\n  agent any\n  stages {\n    stage('Release') {\n      steps {\n        copyArtifacts(projectName: 'b', selector: upstream())\n        sh 'aws s3 cp out s3://r/'\n      }\n    }\n  }\n}\n"),
    ('C09_selector_variable_specific', 'quiet', 'unknown',
     "pipeline {\n  agent any\n  stages {\n    stage('Release') {\n      steps {\n        script {\n          def s = specific('42')\n          copyArtifacts(projectName: 'b', selector: s)\n        }\n        sh 'aws s3 cp out s3://r/'\n      }\n    }\n  }\n}\n"),
    ('C10_sha256sum_print_only', 'finding-high', 'finding-high',
     "pipeline {\n  agent any\n  stages {\n    stage('Release') {\n      steps {\n        copyArtifacts(projectName: 'b')\n        sh 'sha256sum out/app.jar'\n        sh 'aws s3 cp out s3://r/'\n      }\n    }\n  }\n}\n"),
    ('C11_build_then_default_selector', 'finding-high', 'finding-high',
     "pipeline {\n  agent any\n  stages {\n    stage('Release') {\n      steps {\n        build job: 'b', wait: true\n        copyArtifacts(projectName: 'b')\n        sh 'aws s3 cp out s3://r/'\n      }\n    }\n  }\n}\n"),
    ('C12_two_copies_one_fixed_one_moving', 'finding-high', 'finding-high',
     "pipeline {\n  agent any\n  stages {\n    stage('Release') {\n      steps {\n        copyArtifacts(projectName: 'a', selector: specific('7'))\n        copyArtifacts(projectName: 'b', selector: lastCompleted())\n        sh 'aws s3 cp out s3://r/'\n      }\n    }\n  }\n}\n"),
    ('C13_unarchive_own_build', 'quiet', 'quiet',
     "pipeline {\n  agent any\n  stages {\n    stage('Release') {\n      steps {\n        unarchive mapping: ['app.jar': 'out/app.jar']\n        sh 'aws s3 cp out s3://r/'\n      }\n    }\n  }\n}\n"),
    ('C14_scripted_no_stage', 'finding-high', 'finding-high',
     "node {\n  copyArtifacts(projectName: 'b')\n  sh 'aws s3 cp out s3://r/'\n}\n"),
    ('S01_step_class_CopyArtifact_list', 'finding-high', 'quiet',
     "pipeline {\n  agent any\n  stages {\n    stage('Release') {\n      steps {\n        step([$class: 'CopyArtifact', projectName: 'b'])\n        sh 'aws s3 cp out s3://r/'\n      }\n    }\n  }\n}\n"),
    ('S02_step_class_named_status_selector', 'finding-high', 'quiet',
     "pipeline {\n  agent any\n  stages {\n    stage('Release') {\n      steps {\n        step $class: 'CopyArtifact', projectName: 'b', selector: [$class: 'StatusBuildSelector']\n        sh 'aws s3 cp out s3://r/'\n      }\n    }\n  }\n}\n"),
    ('S03_step_class_fqcn_lastcompleted', 'finding-high', 'quiet',
     "pipeline {\n  agent any\n  stages {\n    stage('Release') {\n      steps {\n        step([$class: 'hudson.plugins.copyartifact.CopyArtifact', projectName: 'b',\n              selector: [$class: 'LastCompletedBuildSelector']])\n        sh 'aws s3 cp out s3://r/'\n      }\n    }\n  }\n}\n"),
    ('S04_step_class_specific_fixed', 'quiet', 'quiet',
     "pipeline {\n  agent any\n  stages {\n    stage('Release') {\n      steps {\n        step([$class: 'CopyArtifact', projectName: 'b', selector: [$class: 'SpecificBuildSelector', buildNumber: '42']])\n        sh 'aws s3 cp out s3://r/'\n      }\n    }\n  }\n}\n"),
    ('S05_no_parens', 'finding-high', 'finding-high',
     "pipeline {\n  agent any\n  stages {\n    stage('Release') {\n      steps {\n        copyArtifacts projectName: 'b', filter: 'out/**'\n        sh 'aws s3 cp out s3://r/'\n      }\n    }\n  }\n}\n"),
    ('S06_positional_project', 'finding-high', 'finding-high',
     "pipeline {\n  agent any\n  stages {\n    stage('Release') {\n      steps {\n        copyArtifacts 'b'\n        sh 'aws s3 cp out s3://r/'\n      }\n    }\n  }\n}\n"),
    ('S07_map_arg_specific', 'quiet', 'finding-high',
     "pipeline {\n  agent any\n  stages {\n    stage('Release') {\n      steps {\n        copyArtifacts([projectName: 'b', selector: specific('42')])\n        sh 'aws s3 cp out s3://r/'\n      }\n    }\n  }\n}\n"),
    ('S08_map_arg_quoted_keys_specific', 'quiet', 'finding-high',
     "pipeline {\n  agent any\n  stages {\n    stage('Release') {\n      steps {\n        copyArtifacts(['projectName': 'b', 'selector': specific('42')])\n        sh 'aws s3 cp out s3://r/'\n      }\n    }\n  }\n}\n"),
    ('S09_map_variable_specific', 'quiet', 'finding-high',
     "pipeline {\n  agent any\n  stages {\n    stage('Release') {\n      steps {\n        script {\n          def a = [projectName: 'b', selector: specific('42')]\n          copyArtifacts(a)\n        }\n        sh 'aws s3 cp out s3://r/'\n      }\n    }\n  }\n}\n"),
    ('S10_map_variable_default', 'finding-high', 'finding-high',
     "pipeline {\n  agent any\n  stages {\n    stage('Release') {\n      steps {\n        script {\n          def a = [projectName: 'b']\n          copyArtifacts(a)\n        }\n        sh 'aws s3 cp out s3://r/'\n      }\n    }\n  }\n}\n"),
    ('S11_gstring_project', 'finding-high', 'finding-high',
     'pipeline {\n  agent any\n  stages {\n    stage(\'Release\') {\n      steps {\n        copyArtifacts(projectName: "${env.UPSTREAM_JOB}")\n        sh \'aws s3 cp out s3://r/\'\n      }\n    }\n  }\n}\n'),
    ('S12_inside_script', 'finding-high', 'finding-high',
     "pipeline {\n  agent any\n  stages {\n    stage('Release') {\n      steps {\n        script {\n          copyArtifacts(projectName: 'b')\n        }\n        sh 'aws s3 cp out s3://r/'\n      }\n    }\n  }\n}\n"),
    ('S13_helper_method', 'finding-high', 'finding-high',
     "def fetch() {\n  copyArtifacts(projectName: 'b')\n}\npipeline {\n  agent any\n  stages {\n    stage('Release') {\n      steps {\n        script { fetch() }\n        sh 'aws s3 cp out s3://r/'\n      }\n    }\n  }\n}\n"),
    ('S14_closure_called_later', 'finding-high', 'finding-high',
     "pipeline {\n  agent any\n  stages {\n    stage('Release') {\n      steps {\n        script {\n          def fetch = { copyArtifacts(projectName: 'b') }\n          fetch()\n        }\n        sh 'aws s3 cp out s3://r/'\n      }\n    }\n  }\n}\n"),
    ('S15_dir_withEnv_timeout_retry', 'finding-high', 'finding-high',
     "pipeline {\n  agent any\n  stages {\n    stage('Release') {\n      steps {\n        dir('in') {\n          withEnv(['X=1']) {\n            timeout(time: 5, unit: 'MINUTES') {\n              retry(2) {\n                copyArtifacts(projectName: 'b')\n              }\n            }\n          }\n        }\n        sh 'aws s3 cp out s3://r/'\n      }\n    }\n  }\n}\n"),
    ('S16_parallel_branch_publish_later', 'finding-medium', 'finding-medium',
     "pipeline {\n  agent any\n  stages {\n    stage('Fetch') {\n      parallel {\n        stage('A') { steps { copyArtifacts(projectName: 'b') } }\n        stage('B') { steps { echo 'x' } }\n      }\n    }\n    stage('Publish') { steps { sh 'aws s3 cp out s3://r/' } }\n  }\n}\n"),
    ('S17_matrix_cell', 'finding-high', 'finding-high',
     "pipeline {\n  agent any\n  stages {\n    stage('Release') {\n      matrix {\n        axes { axis { name 'OS'; values 'linux', 'mac' } }\n        stages {\n          stage('Ship') { steps { copyArtifacts(projectName: 'b')\n sh 'aws s3 cp out s3://r/' } }\n        }\n      }\n    }\n  }\n}\n"),
    ('S18_pipeline_post_success', 'finding-high', 'finding-high',
     "pipeline {\n  agent any\n  stages { stage('Build') { steps { sh 'make' } } }\n  post { success { copyArtifacts(projectName: 'b')\n sh 'aws s3 cp out s3://r/' } }\n}\n"),
    ('S19_this_prefix', 'finding-high', 'finding-high',
     "pipeline {\n  agent any\n  stages {\n    stage('Release') {\n      steps {\n        script { this.copyArtifacts(projectName: 'b') }\n        sh 'aws s3 cp out s3://r/'\n      }\n    }\n  }\n}\n"),
    ('S20_steps_prefix', 'finding-high', 'finding-high',
     "pipeline {\n  agent any\n  stages {\n    stage('Release') {\n      steps {\n        script { steps.copyArtifacts(projectName: 'b') }\n        sh 'aws s3 cp out s3://r/'\n      }\n    }\n  }\n}\n"),
    ('S21_helper_with_script_param', 'finding-high', 'quiet',
     "def fetch(script) {\n  script.copyArtifacts(projectName: 'b')\n}\npipeline {\n  agent any\n  stages {\n    stage('Release') {\n      steps {\n        script { fetch(this) }\n        sh 'aws s3 cp out s3://r/'\n      }\n    }\n  }\n}\n"),
    ('S22_helper_with_ctx_param', 'finding-high', 'quiet',
     "def fetch(ctx) {\n  ctx.copyArtifacts(projectName: 'b')\n}\npipeline {\n  agent any\n  stages {\n    stage('Release') {\n      steps {\n        script { fetch(this) }\n        sh 'aws s3 cp out s3://r/'\n      }\n    }\n  }\n}\n"),
    ('S23_class_helper_steps_field', 'unknown', 'finding-medium',
     "class Fetcher implements Serializable {\n  def steps\n  Fetcher(steps) { this.steps = steps }\n  def get() { steps.copyArtifacts(projectName: 'b') }\n}\npipeline {\n  agent any\n  stages {\n    stage('Release') {\n      steps {\n        script { new Fetcher(this).get() }\n        sh 'aws s3 cp out s3://r/'\n      }\n    }\n  }\n}\n"),
    ('S24_this_steps_chain', 'finding-high', 'quiet',
     "pipeline {\n  agent any\n  stages {\n    stage('Release') {\n      steps {\n        script { this.steps.copyArtifacts(projectName: 'b') }\n        sh 'aws s3 cp out s3://r/'\n      }\n    }\n  }\n}\n"),
    ('S25_invokeMethod', 'unknown', 'unknown',
     "pipeline {\n  agent any\n  stages {\n    stage('Release') {\n      steps {\n        script { invokeMethod('copyArtifacts', [projectName: 'b']) }\n        sh 'aws s3 cp out s3://r/'\n      }\n    }\n  }\n}\n"),
    ('S26_method_pointer', 'unknown', 'quiet',
     "pipeline {\n  agent any\n  stages {\n    stage('Release') {\n      steps {\n        script {\n          def ca = this.&copyArtifacts\n          ca(projectName: 'b')\n        }\n        sh 'aws s3 cp out s3://r/'\n      }\n    }\n  }\n}\n"),
    ('S27_assigned_result', 'finding-high', 'finding-high',
     "pipeline {\n  agent any\n  stages {\n    stage('Release') {\n      steps {\n        script { def x = copyArtifacts(projectName: 'b') }\n        sh 'aws s3 cp out s3://r/'\n      }\n    }\n  }\n}\n"),
    ('S28_each_loop', 'finding-high', 'finding-high',
     "pipeline {\n  agent any\n  stages {\n    stage('Release') {\n      steps {\n        script { ['b', 'c'].each { p -> copyArtifacts(projectName: p) } }\n        sh 'aws s3 cp out s3://r/'\n      }\n    }\n  }\n}\n"),
    ('S30_quoted_method_name', 'finding-high', 'finding-high',
     'pipeline {\n  agent any\n  stages {\n    stage(\'Release\') {\n      steps {\n        script { this."copyArtifacts"(projectName: \'b\') }\n        sh \'aws s3 cp out s3://r/\'\n      }\n    }\n  }\n}\n'),
    ('S31_gstring_method_name', 'unknown', 'quiet',
     'pipeline {\n  agent any\n  stages {\n    stage(\'Release\') {\n      steps {\n        script {\n          def s = \'copyArtifacts\'\n          "$s"(projectName: \'b\')\n        }\n        sh \'aws s3 cp out s3://r/\'\n      }\n    }\n  }\n}\n'),
    ('S29_spread_map_specific', 'unknown', 'finding-high',
     "pipeline {\n  agent any\n  stages {\n    stage('Release') {\n      steps {\n        copyArtifacts(projectName: 'b', *: [selector: specific('42')])\n        sh 'aws s3 cp out s3://r/'\n      }\n    }\n  }\n}\n"),
    ('L01_lastSuccessful', 'finding-high', 'finding-high',
     "pipeline {\n  agent any\n  stages {\n    stage('Release') {\n      steps {\n        copyArtifacts(projectName: 'b', selector: lastSuccessful(stable: true))\n        sh 'aws s3 cp out s3://r/'\n      }\n    }\n  }\n}\n"),
    ('L02_lastCompleted', 'finding-high', 'finding-high',
     "pipeline {\n  agent any\n  stages {\n    stage('Release') {\n      steps {\n        copyArtifacts(projectName: 'b', selector: lastCompleted())\n        sh 'aws s3 cp out s3://r/'\n      }\n    }\n  }\n}\n"),
    ('L03_latestSavedBuild', 'finding-high', 'finding-high',
     "pipeline {\n  agent any\n  stages {\n    stage('Release') {\n      steps {\n        copyArtifacts(projectName: 'b', selector: latestSavedBuild())\n        sh 'aws s3 cp out s3://r/'\n      }\n    }\n  }\n}\n"),
    ('L04_permalink', 'finding-high', 'finding-high',
     "pipeline {\n  agent any\n  stages {\n    stage('Release') {\n      steps {\n        copyArtifacts(projectName: 'b', selector: permalink('lastStableBuild'))\n        sh 'aws s3 cp out s3://r/'\n      }\n    }\n  }\n}\n"),
    ('L05_lastWithArtifacts', 'finding-high', 'finding-high',
     "pipeline {\n  agent any\n  stages {\n    stage('Release') {\n      steps {\n        copyArtifacts(projectName: 'b', selector: lastWithArtifacts())\n        sh 'aws s3 cp out s3://r/'\n      }\n    }\n  }\n}\n"),
    ('L06_workspace', 'finding-high', 'finding-high',
     "pipeline {\n  agent any\n  stages {\n    stage('Release') {\n      steps {\n        copyArtifacts(projectName: 'b', selector: workspace())\n        sh 'aws s3 cp out s3://r/'\n      }\n    }\n  }\n}\n"),
    ('L07_buildParameter', 'finding-high', 'finding-high',
     "pipeline {\n  agent any\n  stages {\n    stage('Release') {\n      steps {\n        copyArtifacts(projectName: 'b', selector: buildParameter('SEL'))\n        sh 'aws s3 cp out s3://r/'\n      }\n    }\n  }\n}\n"),
    ('L08_specific_permalink_literal', 'finding-high', 'quiet',
     "pipeline {\n  agent any\n  stages {\n    stage('Release') {\n      steps {\n        copyArtifacts(projectName: 'b', selector: specific('lastSuccessfulBuild'))\n        sh 'aws s3 cp out s3://r/'\n      }\n    }\n  }\n}\n"),
    ('L09_specific_named_permalink', 'finding-high', 'quiet',
     "pipeline {\n  agent any\n  stages {\n    stage('Release') {\n      steps {\n        copyArtifacts(projectName: 'b', selector: specific(buildNumber: 'lastStableBuild'))\n        sh 'aws s3 cp out s3://r/'\n      }\n    }\n  }\n}\n"),
    ('L10_specific_params', 'unknown', 'quiet',
     "pipeline {\n  agent any\n  stages {\n    stage('Release') {\n      steps {\n        copyArtifacts(projectName: 'b', selector: specific(params.BUILD))\n        sh 'aws s3 cp out s3://r/'\n      }\n    }\n  }\n}\n"),
    ('L11_specific_gstring_params', 'unknown', 'quiet',
     'pipeline {\n  agent any\n  stages {\n    stage(\'Release\') {\n      steps {\n        copyArtifacts(projectName: \'b\', selector: specific("${params.BUILD}"))\n        sh \'aws s3 cp out s3://r/\'\n      }\n    }\n  }\n}\n'),
    ('L12_specific_env', 'unknown', 'quiet',
     "pipeline {\n  agent any\n  stages {\n    stage('Release') {\n      steps {\n        copyArtifacts(projectName: 'b', selector: specific(env.UPSTREAM_BUILD))\n        sh 'aws s3 cp out s3://r/'\n      }\n    }\n  }\n}\n"),
    ('L13_specific_single_quoted_dollar', 'unknown', 'quiet',
     "pipeline {\n  agent any\n  stages {\n    stage('Release') {\n      steps {\n        copyArtifacts(projectName: 'b', selector: specific('${BUILD_SEL}'))\n        sh 'aws s3 cp out s3://r/'\n      }\n    }\n  }\n}\n"),
    ('L14_specific_elvis_permalink', 'unknown', 'quiet',
     "pipeline {\n  agent any\n  stages {\n    stage('Release') {\n      steps {\n        copyArtifacts(projectName: 'b', selector: specific(params.BUILD ?: 'lastSuccessfulBuild'))\n        sh 'aws s3 cp out s3://r/'\n      }\n    }\n  }\n}\n"),
    ('L15_upstream_fallback', 'finding-high', 'quiet',
     "pipeline {\n  agent any\n  stages {\n    stage('Release') {\n      steps {\n        copyArtifacts(projectName: 'b', selector: upstream(fallbackToLastSuccessful: true))\n        sh 'aws s3 cp out s3://r/'\n      }\n    }\n  }\n}\n"),
    ('L16_status_selector_map', 'finding-high', 'unknown',
     "pipeline {\n  agent any\n  stages {\n    stage('Release') {\n      steps {\n        copyArtifacts(projectName: 'b', selector: [$class: 'StatusBuildSelector', stable: true])\n        sh 'aws s3 cp out s3://r/'\n      }\n    }\n  }\n}\n"),
    ('L17_specific_selector_map', 'quiet', 'unknown',
     "pipeline {\n  agent any\n  stages {\n    stage('Release') {\n      steps {\n        copyArtifacts(projectName: 'b', selector: [$class: 'SpecificBuildSelector', buildNumber: '42'])\n        sh 'aws s3 cp out s3://r/'\n      }\n    }\n  }\n}\n"),
    ('L18_selector_variable_moving', 'finding-high', 'unknown',
     "pipeline {\n  agent any\n  stages {\n    stage('Release') {\n      steps {\n        script {\n          def s = lastSuccessful()\n          copyArtifacts(projectName: 'b', selector: s)\n        }\n        sh 'aws s3 cp out s3://r/'\n      }\n    }\n  }\n}\n"),
    ('L19_ternary_selector', 'unknown', 'unknown',
     "pipeline {\n  agent any\n  stages {\n    stage('Release') {\n      steps {\n        copyArtifacts(projectName: 'b', selector: params.PIN ? specific(params.PIN) : lastSuccessful())\n        sh 'aws s3 cp out s3://r/'\n      }\n    }\n  }\n}\n"),
    ('L21_spread_after_specific', 'unknown', 'quiet',
     "pipeline {\n  agent any\n  stages {\n    stage('Release') {\n      steps {\n        copyArtifacts(projectName: 'b', selector: specific('42'), *: [selector: lastCompleted()])\n        sh 'aws s3 cp out s3://r/'\n      }\n    }\n  }\n}\n"),
    ('L22_case_changed_selector', 'unknown', 'unknown',
     "pipeline {\n  agent any\n  stages {\n    stage('Release') {\n      steps {\n        copyArtifacts(projectName: 'b', selector: LastSuccessful())\n        sh 'aws s3 cp out s3://r/'\n      }\n    }\n  }\n}\n"),
    ('L23_downstream_literal', 'unknown', 'unknown',
     "pipeline {\n  agent any\n  stages {\n    stage('Release') {\n      steps {\n        copyArtifacts(projectName: 'b', selector: downstream(upstreamProjectName: 'a', upstreamBuildNumber: '7'))\n        sh 'aws s3 cp out s3://r/'\n      }\n    }\n  }\n}\n"),
    ('L25_specific_display_name_literal', 'finding-high', 'quiet',
     "pipeline {\n  agent any\n  stages {\n    stage('Release') {\n      steps {\n        copyArtifacts(projectName: 'b', selector: specific('release-1.4.2'))\n        sh 'aws s3 cp out s3://r/'\n      }\n    }\n  }\n}\n"),
    ('L26_specific_number_but_project_from_param', 'unknown', 'quiet',
     "pipeline {\n  agent any\n  stages {\n    stage('Release') {\n      steps {\n        copyArtifacts(projectName: params.JOB, selector: specific('42'))\n        sh 'aws s3 cp out s3://r/'\n      }\n    }\n  }\n}\n"),
    ('T01_curl_permalink_url', 'finding-high', 'quiet',
     'pipeline {\n  agent any\n  stages {\n    stage(\'Release\') {\n      steps {\n        sh \'curl -fsSLo out/app.jar "$JENKINS_URL/job/b/lastSuccessfulBuild/artifact/app.jar"\'\n        sh \'aws s3 cp out s3://r/\'\n      }\n    }\n  }\n}\n'),
    ('T02_wget_laststable', 'finding-high', 'quiet',
     "pipeline {\n  agent any\n  stages {\n    stage('Release') {\n      steps {\n        sh 'wget -O out/app.jar https://ci.example.com/job/b/lastStableBuild/artifact/dist/app.jar'\n        sh 'aws s3 cp out s3://r/'\n      }\n    }\n  }\n}\n"),
    ('T03_httpRequest_permalink', 'finding-high', 'quiet',
     'pipeline {\n  agent any\n  stages {\n    stage(\'Release\') {\n      steps {\n        httpRequest url: "${env.JENKINS_URL}job/b/lastSuccessfulBuild/artifact/app.jar", outputFile: \'out/app.jar\'\n        sh \'aws s3 cp out s3://r/\'\n      }\n    }\n  }\n}\n'),
    ('T04_curl_numeric_build_url', 'quiet', 'quiet',
     "pipeline {\n  agent any\n  stages {\n    stage('Release') {\n      steps {\n        sh 'curl -fsSLo out/app.jar https://ci.example.com/job/b/42/artifact/app.jar'\n        sh 'aws s3 cp out s3://r/'\n      }\n    }\n  }\n}\n"),
    ('T05_jf_rt_dl_latest_build', 'quiet', 'quiet',
     'pipeline {\n  agent any\n  stages {\n    stage(\'Release\') {\n      steps {\n        sh \'jf rt dl --build=b/LATEST "libs-release/app/*.jar" out/\'\n        sh \'aws s3 cp out s3://r/\'\n      }\n    }\n  }\n}\n'),
    ('T06_s3_latest_key_then_publish', 'quiet', 'quiet',
     "pipeline {\n  agent any\n  stages {\n    stage('Release') {\n      steps {\n        sh 'aws s3 cp s3://ci-builds/b/latest/app.jar out/app.jar'\n        sh 'twine upload out/*'\n      }\n    }\n  }\n}\n"),
    ('K01_check_after_publish', 'finding-high', 'quiet',
     "pipeline {\n  agent any\n  stages {\n    stage('Release') {\n      steps {\n        copyArtifacts(projectName: 'b')\n        sh 'aws s3 cp out s3://r/'\n        sh 'sha256sum -c SHA256SUMS'\n      }\n    }\n  }\n}\n"),
    ('K02_check_or_true', 'finding-high', 'quiet',
     "pipeline {\n  agent any\n  stages {\n    stage('Release') {\n      steps {\n        copyArtifacts(projectName: 'b')\n        sh 'sha256sum -c SHA256SUMS || true'\n        sh 'aws s3 cp out s3://r/'\n      }\n    }\n  }\n}\n"),
    ('K03_catchError', 'finding-high', 'quiet',
     "pipeline {\n  agent any\n  stages {\n    stage('Release') {\n      steps {\n        copyArtifacts(projectName: 'b')\n        catchError(buildResult: 'SUCCESS') {\n          sh 'sha256sum -c SHA256SUMS'\n        }\n        sh 'aws s3 cp out s3://r/'\n      }\n    }\n  }\n}\n"),
    ('K04_returnStatus', 'finding-high', 'quiet',
     "pipeline {\n  agent any\n  stages {\n    stage('Release') {\n      steps {\n        copyArtifacts(projectName: 'b')\n        sh(script: 'sha256sum -c SHA256SUMS', returnStatus: true)\n        sh 'aws s3 cp out s3://r/'\n      }\n    }\n  }\n}\n"),
    ('K05_try_catch', 'finding-high', 'quiet',
     "pipeline {\n  agent any\n  stages {\n    stage('Release') {\n      steps {\n        copyArtifacts(projectName: 'b')\n        script {\n          try {\n            sh 'sha256sum -c SHA256SUMS'\n          } catch (e) {\n            echo 'mismatch'\n          }\n        }\n        sh 'aws s3 cp out s3://r/'\n      }\n    }\n  }\n}\n"),
    ('K06_if_param', 'finding-high', 'quiet',
     "pipeline {\n  agent any\n  stages {\n    stage('Release') {\n      steps {\n        copyArtifacts(projectName: 'b')\n        script {\n          if (params.VERIFY) {\n            sh 'sha256sum -c SHA256SUMS'\n          }\n        }\n        sh 'aws s3 cp out s3://r/'\n      }\n    }\n  }\n}\n"),
    ('K07_echo_in_shell', 'finding-high', 'quiet',
     'pipeline {\n  agent any\n  stages {\n    stage(\'Release\') {\n      steps {\n        copyArtifacts(projectName: \'b\')\n        sh \'echo "TODO: sha256sum -c SHA256SUMS"\'\n        sh \'aws s3 cp out s3://r/\'\n      }\n    }\n  }\n}\n'),
    ('K08_shell_comment', 'finding-high', 'quiet',
     "pipeline {\n  agent any\n  stages {\n    stage('Release') {\n      steps {\n        copyArtifacts(projectName: 'b')\n        sh '# sha256sum -c SHA256SUMS (disabled)'\n        sh 'aws s3 cp out s3://r/'\n      }\n    }\n  }\n}\n"),
    ('K09_echo_obaaf_verify', 'finding-high', 'quiet',
     "pipeline {\n  agent any\n  stages {\n    stage('Release') {\n      steps {\n        copyArtifacts(projectName: 'b')\n        sh 'echo obaaf verify release is not wired up yet'\n        sh 'aws s3 cp out s3://r/'\n      }\n    }\n  }\n}\n"),
    ('K10_cosign_verify_other_image', 'unknown', 'quiet',
     "pipeline {\n  agent any\n  stages {\n    stage('Release') {\n      steps {\n        copyArtifacts(projectName: 'b')\n        sh 'cosign verify --key cosign.pub registry.example.com/base:1.0'\n        sh 'aws s3 cp out s3://r/'\n      }\n    }\n  }\n}\n"),
    ('K11_sums_from_same_copy', 'finding-high', 'quiet',
     "pipeline {\n  agent any\n  stages {\n    stage('Release') {\n      steps {\n        copyArtifacts(projectName: 'b', filter: 'dist/**')\n        sh 'cd dist && sha256sum -c SHA256SUMS'\n        sh 'aws s3 cp dist s3://r/ --recursive'\n      }\n    }\n  }\n}\n"),
    ('K12_ignore_missing', 'unknown', 'quiet',
     "pipeline {\n  agent any\n  stages {\n    stage('Release') {\n      steps {\n        copyArtifacts(projectName: 'b')\n        sh 'sha256sum -c --ignore-missing SHA256SUMS'\n        sh 'aws s3 cp out s3://r/'\n      }\n    }\n  }\n}\n"),
    ('K13_closure_never_called', 'finding-high', 'quiet',
     "pipeline {\n  agent any\n  stages {\n    stage('Release') {\n      steps {\n        copyArtifacts(projectName: 'b')\n        script {\n          def verify = { sh 'sha256sum -c SHA256SUMS' }\n        }\n        sh 'aws s3 cp out s3://r/'\n      }\n    }\n  }\n}\n"),
    ('K14_parallel_sibling', 'finding-high', 'quiet',
     "node {\n  stage('Release') {\n    copyArtifacts(projectName: 'b')\n    parallel(\n      verify: { sh 'sha256sum -c SHA256SUMS' },\n      ship: { sh 'aws s3 cp out s3://r/' }\n    )\n  }\n}\n"),
    ('K15_short_circuit_never_runs', 'finding-high', 'quiet',
     "pipeline {\n  agent any\n  stages {\n    stage('Release') {\n      steps {\n        copyArtifacts(projectName: 'b')\n        sh 'true || sha256sum -c SHA256SUMS'\n        sh 'aws s3 cp out s3://r/'\n      }\n    }\n  }\n}\n"),
    ('K16_background', 'finding-high', 'quiet',
     "pipeline {\n  agent any\n  stages {\n    stage('Release') {\n      steps {\n        copyArtifacts(projectName: 'b')\n        sh 'sha256sum -c SHA256SUMS &'\n        sh 'aws s3 cp out s3://r/'\n      }\n    }\n  }\n}\n"),
    ('K17_set_plus_e', 'finding-high', 'quiet',
     "pipeline {\n  agent any\n  stages {\n    stage('Release') {\n      steps {\n        copyArtifacts(projectName: 'b')\n        sh '''set +e\n        sha256sum -c SHA256SUMS\n        aws s3 cp out s3://r/'''\n      }\n    }\n  }\n}\n"),
    ('K18_shebang_no_e', 'finding-high', 'quiet',
     "pipeline {\n  agent any\n  stages {\n    stage('Release') {\n      steps {\n        copyArtifacts(projectName: 'b')\n        sh '''#!/bin/bash\n        sha256sum -c SHA256SUMS\n        echo checked'''\n        sh 'aws s3 cp out s3://r/'\n      }\n    }\n  }\n}\n"),
    ('K19_pipe_tee', 'finding-high', 'quiet',
     "pipeline {\n  agent any\n  stages {\n    stage('Release') {\n      steps {\n        copyArtifacts(projectName: 'b')\n        sh 'sha256sum -c SHA256SUMS | tee check.log'\n        sh 'aws s3 cp out s3://r/'\n      }\n    }\n  }\n}\n"),
    ('K20_check_in_later_stage_before_publish', 'quiet', 'finding-medium',
     "pipeline {\n  agent any\n  stages {\n    stage('Release') {\n      steps {\n        copyArtifacts(projectName: 'b')\n      }\n    }\n    stage('Verify') {\n      steps {\n        sh 'obaaf verify release --policy p --artifacts out'\n      }\n    }\n    stage('Publish') {\n      steps {\n        sh 'aws s3 cp out s3://r/'\n      }\n    }\n  }\n}\n"),
    ('K29_check_in_publish_stage_before_publish', 'quiet', 'finding-medium',
     "pipeline {\n  agent any\n  stages {\n    stage('Release') {\n      steps {\n        copyArtifacts(projectName: 'b')\n      }\n    }\n    stage('Publish') {\n      steps {\n        sh 'obaaf verify release --policy p --artifacts out'\n        sh 'aws s3 cp out s3://r/'\n      }\n    }\n  }\n}\n"),
    ('K21_check_after_exit', 'finding-high', 'quiet',
     "pipeline {\n  agent any\n  stages {\n    stage('Release') {\n      steps {\n        copyArtifacts(projectName: 'b')\n        sh '''exit 0\n        sha256sum -c SHA256SUMS'''\n        sh 'aws s3 cp out s3://r/'\n      }\n    }\n  }\n}\n"),
    ('K22_check_other_dir_than_copy', 'unknown', 'quiet',
     "pipeline {\n  agent any\n  stages {\n    stage('Release') {\n      steps {\n        copyArtifacts(projectName: 'b', target: 'incoming')\n        dir('vendor') {\n          sh 'sha256sum -c SHA256SUMS'\n        }\n        sh 'aws s3 cp incoming s3://r/ --recursive'\n      }\n    }\n  }\n}\n"),
    ('K23_check_on_other_node', 'unknown', 'quiet',
     "node('linux') {\n  stage('Release') {\n    copyArtifacts(projectName: 'b')\n    node('checker') { sh 'sha256sum -c SHA256SUMS' }\n    sh 'aws s3 cp out s3://r/'\n  }\n}\n"),
    ('K24_check_for_other_copy', 'unknown', 'quiet',
     "pipeline {\n  agent any\n  stages {\n    stage('Release') {\n      steps {\n        copyArtifacts(projectName: 'a', filter: 'a.jar')\n        copyArtifacts(projectName: 'b', filter: 'b.jar')\n        sh 'sha256sum -c a.jar.sha256'\n        sh 'aws s3 cp out s3://r/'\n      }\n    }\n  }\n}\n"),
    ('K25_same_name_stage_check_after', 'finding-high', 'quiet',
     "node {\n  stage('Release') {\n    copyArtifacts(projectName: 'b')\n    sh 'aws s3 cp out s3://r/'\n  }\n  stage('Release') {\n    sh 'sha256sum -c SHA256SUMS'\n  }\n}\n"),
    ('K26_uncalled_method_check', 'finding-high', 'finding-high',
     "def verify() {\n  sh 'sha256sum -c SHA256SUMS'\n}\npipeline {\n  agent any\n  stages {\n    stage('Release') {\n      steps {\n        copyArtifacts(projectName: 'b')\n        sh 'aws s3 cp out s3://r/'\n      }\n    }\n  }\n}\n"),
    ('K27_check_then_copy_again', 'finding-high', 'finding-high',
     "pipeline {\n  agent any\n  stages {\n    stage('Release') {\n      steps {\n        copyArtifacts(projectName: 'b')\n        sh 'sha256sum -c SHA256SUMS'\n        copyArtifacts(projectName: 'b', filter: 'extra/**')\n        sh 'aws s3 cp out s3://r/'\n      }\n    }\n  }\n}\n"),
    ('K28_verify_in_warnError', 'finding-high', 'quiet',
     "pipeline {\n  agent any\n  stages {\n    stage('Release') {\n      steps {\n        copyArtifacts(projectName: 'b')\n        warnError('mismatch') {\n          sh 'sha256sum -c SHA256SUMS'\n        }\n        sh 'aws s3 cp out s3://r/'\n      }\n    }\n  }\n}\n"),
    ('P01_publish_in_stage_post_success', 'finding-high', 'finding-medium',
     "pipeline {\n  agent any\n  stages {\n    stage('Release') {\n      steps { copyArtifacts(projectName: 'b') }\n      post { success { sh 'aws s3 cp out s3://r/' } }\n    }\n  }\n}\n"),
    ('P02_publish_before_copy_same_stage', 'finding-medium', 'finding-high',
     "pipeline {\n  agent any\n  stages {\n    stage('Release') {\n      steps {\n        sh 'aws s3 cp out s3://r/'\n        copyArtifacts(projectName: 'docs')\n      }\n    }\n    stage('Later') {\n      steps {\n        sh 'aws s3 cp out2 s3://r2/'\n      }\n    }\n  }\n}\n"),
    ('P03_same_named_scripted_stages', 'finding-high', 'finding-high',
     "node {\n  stage('Release') {\n    copyArtifacts(projectName: 'b')\n  }\n  stage('Release') {\n    sh 'aws s3 cp out s3://r/'\n  }\n}\n"),
    ('P04_computed_stage_names', 'finding-high', 'finding-high',
     "node {\n  def a = 'Fetch'\n  def b = 'Ship'\n  stage(a) {\n    copyArtifacts(projectName: 'b')\n  }\n  stage(b) {\n    sh 'aws s3 cp out s3://r/'\n  }\n}\n"),
    ('P05_publish_by_method_same_stage', 'finding-high', 'finding-high',
     "def ship() {\n  sh 'aws s3 cp out s3://r/'\n}\npipeline {\n  agent any\n  stages {\n    stage('Release') {\n      steps {\n        copyArtifacts(projectName: 'b')\n        script { ship() }\n      }\n    }\n  }\n}\n"),
    ('P06_s3Upload_step_same_stage', 'finding-high', 'finding-high',
     "pipeline {\n  agent any\n  stages {\n    stage('Release') {\n      steps {\n        copyArtifacts(projectName: 'b')\n        s3Upload(bucket: 'r', file: 'out/app.jar')\n      }\n    }\n  }\n}\n"),
    ('P07_publish_curl_data_binary', 'quiet', 'quiet',
     "pipeline {\n  agent any\n  stages {\n    stage('Release') {\n      steps {\n        copyArtifacts(projectName: 'b')\n        sh 'curl -u u:p -X PUT --data-binary @out/app.jar https://nexus.example.com/repository/releases/app.jar'\n      }\n    }\n  }\n}\n"),
    ('P08_publish_scp_downloads', 'quiet', 'quiet',
     "pipeline {\n  agent any\n  stages {\n    stage('Release') {\n      steps {\n        copyArtifacts(projectName: 'b')\n        sh 'scp out/app.jar deploy@downloads.example.com:/srv/www/releases/'\n      }\n    }\n  }\n}\n"),
    ('D01_copy_in_uncalled_method', 'unknown', 'finding-medium',
     "def fetch() {\n  copyArtifacts(projectName: 'b')\n}\npipeline {\n  agent any\n  stages {\n    stage('Release') {\n      steps {\n        sh 'aws s3 cp out s3://r/'\n      }\n    }\n  }\n}\n"),
    ('D02_copy_in_uncalled_closure', 'unknown', 'finding-high',
     "pipeline {\n  agent any\n  stages {\n    stage('Release') {\n      steps {\n        script {\n          def fetch = { copyArtifacts(projectName: 'b') }\n        }\n        sh 'aws s3 cp out s3://r/'\n      }\n    }\n  }\n}\n"),
    ('Z01_many_copies_long_shasum_line', 'finding-high', 'finding-high',
     "pipeline {\n  agent any\n  stages {\n    stage('Release') {\n      steps {\n        copyArtifacts(projectName: 'b0')\n        copyArtifacts(projectName: 'b1')\n        copyArtifacts(projectName: 'b2')\n        copyArtifacts(projectName: 'b3')\n        copyArtifacts(projectName: 'b4')\n        copyArtifacts(projectName: 'b5')\n        copyArtifacts(projectName: 'b6')\n        copyArtifacts(projectName: 'b7')\n        copyArtifacts(projectName: 'b8')\n        copyArtifacts(projectName: 'b9')\n        copyArtifacts(projectName: 'b10')\n        copyArtifacts(projectName: 'b11')\n        copyArtifacts(projectName: 'b12')\n        copyArtifacts(projectName: 'b13')\n        copyArtifacts(projectName: 'b14')\n        copyArtifacts(projectName: 'b15')\n        copyArtifacts(projectName: 'b16')\n        copyArtifacts(projectName: 'b17')\n        copyArtifacts(projectName: 'b18')\n        copyArtifacts(projectName: 'b19')\n        copyArtifacts(projectName: 'b20')\n        copyArtifacts(projectName: 'b21')\n        copyArtifacts(projectName: 'b22')\n        copyArtifacts(projectName: 'b23')\n        copyArtifacts(projectName: 'b24')\n        copyArtifacts(projectName: 'b25')\n        copyArtifacts(projectName: 'b26')\n        copyArtifacts(projectName: 'b27')\n        copyArtifacts(projectName: 'b28')\n        copyArtifacts(projectName: 'b29')\n        copyArtifacts(projectName: 'b30')\n        copyArtifacts(projectName: 'b31')\n        copyArtifacts(projectName: 'b32')\n        copyArtifacts(projectName: 'b33')\n        copyArtifacts(projectName: 'b34')\n        copyArtifacts(projectName: 'b35')\n        copyArtifacts(projectName: 'b36')\n        copyArtifacts(projectName: 'b37')\n        copyArtifacts(projectName: 'b38')\n        copyArtifacts(projectName: 'b39')\n        copyArtifacts(projectName: 'b40')\n        copyArtifacts(projectName: 'b41')\n        copyArtifacts(projectName: 'b42')\n        copyArtifacts(projectName: 'b43')\n        copyArtifacts(projectName: 'b44')\n        copyArtifacts(projectName: 'b45')\n        copyArtifacts(projectName: 'b46')\n        copyArtifacts(projectName: 'b47')\n        copyArtifacts(projectName: 'b48')\n        copyArtifacts(projectName: 'b49')\n        copyArtifacts(projectName: 'b50')\n        copyArtifacts(projectName: 'b51')\n        copyArtifacts(projectName: 'b52')\n        copyArtifacts(projectName: 'b53')\n        copyArtifacts(projectName: 'b54')\n        copyArtifacts(projectName: 'b55')\n        copyArtifacts(projectName: 'b56')\n        copyArtifacts(projectName: 'b57')\n        copyArtifacts(projectName: 'b58')\n        copyArtifacts(projectName: 'b59')\n        sh 'x shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum shasum '\n        sh 'aws s3 cp out s3://r/'\n      }\n    }\n  }\n}\n"),
    ('Z02_helper_called_many_times', 'finding-high', 'finding-high',
     "def f() {\n  copyArtifacts(projectName: 'b')\n  sh 'make'\n}\npipeline {\n  agent any\n  stages {\n    stage('Release') {\n      steps {\n        script {\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n          f()\n        }\n        sh 'aws s3 cp out s3://r/'\n      }\n    }\n  }\n}\n"),
    ('Z03_many_copies_dash_line', 'finding-high', 'finding-high',
     "pipeline {\n  agent any\n  stages {\n    stage('Release') {\n      steps {\n        copyArtifacts(projectName: 'b0')\n        copyArtifacts(projectName: 'b1')\n        copyArtifacts(projectName: 'b2')\n        copyArtifacts(projectName: 'b3')\n        copyArtifacts(projectName: 'b4')\n        copyArtifacts(projectName: 'b5')\n        copyArtifacts(projectName: 'b6')\n        copyArtifacts(projectName: 'b7')\n        copyArtifacts(projectName: 'b8')\n        copyArtifacts(projectName: 'b9')\n        copyArtifacts(projectName: 'b10')\n        copyArtifacts(projectName: 'b11')\n        copyArtifacts(projectName: 'b12')\n        copyArtifacts(projectName: 'b13')\n        copyArtifacts(projectName: 'b14')\n        copyArtifacts(projectName: 'b15')\n        copyArtifacts(projectName: 'b16')\n        copyArtifacts(projectName: 'b17')\n        copyArtifacts(projectName: 'b18')\n        copyArtifacts(projectName: 'b19')\n        copyArtifacts(projectName: 'b20')\n        copyArtifacts(projectName: 'b21')\n        copyArtifacts(projectName: 'b22')\n        copyArtifacts(projectName: 'b23')\n        copyArtifacts(projectName: 'b24')\n        copyArtifacts(projectName: 'b25')\n        copyArtifacts(projectName: 'b26')\n        copyArtifacts(projectName: 'b27')\n        copyArtifacts(projectName: 'b28')\n        copyArtifacts(projectName: 'b29')\n        copyArtifacts(projectName: 'b30')\n        copyArtifacts(projectName: 'b31')\n        copyArtifacts(projectName: 'b32')\n        copyArtifacts(projectName: 'b33')\n        copyArtifacts(projectName: 'b34')\n        copyArtifacts(projectName: 'b35')\n        copyArtifacts(projectName: 'b36')\n        copyArtifacts(projectName: 'b37')\n        copyArtifacts(projectName: 'b38')\n        copyArtifacts(projectName: 'b39')\n        copyArtifacts(projectName: 'b40')\n        copyArtifacts(projectName: 'b41')\n        copyArtifacts(projectName: 'b42')\n        copyArtifacts(projectName: 'b43')\n        copyArtifacts(projectName: 'b44')\n        copyArtifacts(projectName: 'b45')\n        copyArtifacts(projectName: 'b46')\n        copyArtifacts(projectName: 'b47')\n        copyArtifacts(projectName: 'b48')\n        copyArtifacts(projectName: 'b49')\n        copyArtifacts(projectName: 'b50')\n        copyArtifacts(projectName: 'b51')\n        copyArtifacts(projectName: 'b52')\n        copyArtifacts(projectName: 'b53')\n        copyArtifacts(projectName: 'b54')\n        copyArtifacts(projectName: 'b55')\n        copyArtifacts(projectName: 'b56')\n        copyArtifacts(projectName: 'b57')\n        copyArtifacts(projectName: 'b58')\n        copyArtifacts(projectName: 'b59')\n        sh 'x sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -sha256sum -'\n        sh 'aws s3 cp out s3://r/'\n      }\n    }\n  }\n}\n"),
    ('Z04_nested_helpers_copy_4_steps', 'finding-high', 'finding-high',
     "def f12() {\n  copyArtifacts(projectName: 'b')\n  sh 'make'\n  sh 'make'\n  sh 'make'\n  sh 'make'\n}\ndef f11() { f12(); f12() }\ndef f10() { f11(); f11() }\ndef f9() { f10(); f10() }\ndef f8() { f9(); f9() }\ndef f7() { f8(); f8() }\ndef f6() { f7(); f7() }\ndef f5() { f6(); f6() }\ndef f4() { f5(); f5() }\ndef f3() { f4(); f4() }\ndef f2() { f3(); f3() }\ndef f1() { f2(); f2() }\ndef f0() { f1(); f1() }\nnode {\n  stage('Release') {\n    f0()\n    sh 'aws s3 cp out s3://r/'\n  }\n}\n"),
    ('Z05_nested_helpers_copy_8_steps', 'finding-high', 'finding-high',
     "def f12() {\n  copyArtifacts(projectName: 'b')\n  sh 'make'\n  sh 'make'\n  sh 'make'\n  sh 'make'\n  sh 'make'\n  sh 'make'\n  sh 'make'\n  sh 'make'\n}\ndef f11() { f12(); f12() }\ndef f10() { f11(); f11() }\ndef f9() { f10(); f10() }\ndef f8() { f9(); f9() }\ndef f7() { f8(); f8() }\ndef f6() { f7(); f7() }\ndef f5() { f6(); f6() }\ndef f4() { f5(); f5() }\ndef f3() { f4(); f4() }\ndef f2() { f3(); f3() }\ndef f1() { f2(); f2() }\ndef f0() { f1(); f1() }\nnode {\n  stage('Release') {\n    f0()\n    sh 'aws s3 cp out s3://r/'\n  }\n}\n"),
    ('Z06_nested_helpers_within_budget', 'finding-high', 'finding-high',
     "def f11() {\n  copyArtifacts(projectName: 'b')\n  sh 'make'\n  sh 'make'\n  sh 'make'\n  sh 'make'\n  sh 'make'\n  sh 'make'\n  sh 'make'\n  sh 'make'\n  sh 'make'\n  sh 'make'\n}\ndef f10() { f11(); f11() }\ndef f9() { f10(); f10() }\ndef f8() { f9(); f9() }\ndef f7() { f8(); f8() }\ndef f6() { f7(); f7() }\ndef f5() { f6(); f6() }\ndef f4() { f5(); f5() }\ndef f3() { f4(); f4() }\ndef f2() { f3(); f3() }\ndef f1() { f2(); f2() }\ndef f0() { f1(); f1() }\nnode {\n  stage('Release') {\n    f0()\n    sh 'aws s3 cp out s3://r/'\n  }\n}\n"),
]

# The answers that are a stated limit rather than what the file decides, with the reason (docs/bypass-attempts.md).
LIMITS = {
    "T05_jf_rt_dl_latest_build": "Downloads by other tools (JFrog CLI, Artifactory or Nexus plugins, an object store's "
                                 "'latest' key) are not read as another job's artifacts; only copyArtifacts and Jenkins "
                                 "artifact URLs are.",
    "T06_s3_latest_key_then_publish": "As T05: a 'latest' key in an object store is not read as a moving reference.",
    "P03_same_named_scripted_stages": "Stages are compared by name: two Scripted stages with one name are one stage, "
                                      "so a publish in the second makes a copy in the first high.",
    "P04_computed_stage_names": "Computed stage names all read as '?', so they are one stage for the severity.",
    "P07_publish_curl_data_binary": "What counts as publishing is the shared detector's (`curl -X PUT --data-binary`, "
                                    "`scp` to a downloads host are not publishes); outside this rule.",
    "P08_publish_scp_downloads": "As P07.",
    "D01_copy_in_uncalled_method": "A copy in a method nothing in the file calls is cannot tell, not quiet: the model "
                                   "reads it where it is written and does not know it never runs.",
    "D02_copy_in_uncalled_closure": "As D01, for a closure that is never seen called.",
    "S23_class_helper_steps_field": "Methods of a class the file defines are not expanded where they are called; a copy "
                                    "in one is cannot tell.",
    "S29_spread_map_specific": "A spread map (`*: m`) is not read; the selector it may hold is cannot tell.",
    "L21_spread_after_specific": "As S29: a spread map after `selector:` may replace it, so the selector is cannot tell "
                                 "even when the map is written beside it.",
    "L23_downstream_literal": "`downstream(...)` is not judged; it is cannot tell.",
    "K10_cosign_verify_other_image": "A digest or signature check before the publish makes the copy cannot tell, "
                                     "whatever it checks: only `obaaf verify release` ties the artifacts to the signed "
                                     "build record.",
    "K12_ignore_missing": "As K10.",
}


def verdict(text: str) -> str:
    result = jenkins.analyze("Jenkinsfile", textwrap.dedent(text).encode(), load(), None)
    severities = {f.severity for f in result.findings if f.rule == "OBAAF-JEN-010"}
    if severities:
        return "finding-high" if "high" in severities else "finding-medium"
    row = next(row for row in jenkins.coverage(result, result.findings) if row["rule"] == "OBAAF-JEN-010")
    return "unknown" if row["status"] == "unknown" else "quiet"


class ArtifactTransferBypassTest(unittest.TestCase):
    def test_every_attempt(self):
        for name, expected, _before, text in CASES:
            with self.subTest(case=name):
                self.assertEqual(verdict(text), expected)

    def test_limits_name_real_cases(self):
        names = {c[0] for c in CASES}
        self.assertLessEqual(set(LIMITS), names)

    def test_no_attempt_is_slow(self):
        # Before the slice, 744 bytes of nested helpers took 11.7 seconds in this rule alone.
        for name, _expected, _before, text in CASES:
            started = time.monotonic()
            verdict(text)
            with self.subTest(case=name):
                self.assertLess(time.monotonic() - started, 3.0)

    def test_old_message_kept_for_a_baseline(self):
        text = ("pipeline {\n  agent any\n  stages {\n    stage('Release') {\n      steps {\n"
                "        copyArtifacts(projectName: 'b')\n        sh 'aws s3 cp out s3://r/'\n      }\n    }\n  }\n}\n")
        result = jenkins.analyze("Jenkinsfile", text.encode(), load(), None)
        messages = [f.message for f in result.findings if f.rule == "OBAAF-JEN-010"]
        self.assertEqual(messages, ["Stage 'Release' copies artifacts from b by the default selector (last successful "
                                    "build), a reference that moves, and does not check their digests before "
                                    "publishing them in the same stage."])


if __name__ == "__main__":
    unittest.main()
