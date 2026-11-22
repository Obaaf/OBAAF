"""Flagship slice 2d.2i: which Jenkinsfiles are read, and OBAAF-JEN-001, 013, 014 and 015.

Most cases are ones that got past the adapter in the attacks recorded in docs/bypass-attempts.md,
section 2d.2i, under their ids there (A: files and line ends; B: OBAAF-JEN-013 to 015; C:
OBAAF-JEN-001); a few are the safe forms beside them. The Jenkinsfiles are kept here as text, not as
files, so `obaaf check` on this repository does not read them as pipelines.
"""

import json
import os
import time
import unittest
from pathlib import Path
from unittest import mock

from helpers import TempDir, git, init_repo, run_cli

from obaaf.catalog import load
from obaaf.checker import jenkins

CASES = {
 "B013": "pipeline {\n  agent any\n  stages {\n    stage('Deploy') {\n      when { branch 'main' }\n      steps {\n        withCredentials([string(credentialsId: 'api-token', variable: 'TOKEN')]) {\n          script {\n            def t = TOKEN\n            sh \"curl -H Authorization:${t} https://example.com\"\n          }\n        }\n      }\n    }\n  }\n}\n",
 "B014": "pipeline {\n  agent any\n  stages {\n    stage('Deploy') {\n      when { branch 'main' }\n      steps {\n        withCredentials([string(credentialsId: 'api-token', variable: 'TOKEN')]) {\n          script {\n            def cmd = \"curl -H Authorization:${TOKEN} https://example.com\"\n            sh cmd\n          }\n        }\n      }\n    }\n  }\n}\n",
 "B018": "pipeline {\n  agent any\n  stages {\n    stage('Deploy') {\n      when { branch 'main' }\n      steps {\n        withCredentials([string(credentialsId: 'api-token', variable: 'TOKEN')]) {\n          withEnv([\"T2=${TOKEN}\"]) {\n            sh \"curl -H Authorization:${env.T2} https://example.com\"\n          }\n        }\n      }\n    }\n  }\n}\n",
 "B022": "pipeline {\n  agent any\n  stages {\n    stage('Deploy') {\n      when { branch 'main' }\n      steps {\n        withCredentials([[$class: 'FileBinding', credentialsId: 'kubeconfig', variable: 'KCFG']]) {\n          sh \"kubectl --kubeconfig ${KCFG} get pods\"\n        }\n      }\n    }\n  }\n}\n",
 "B023": "pipeline {\n  agent any\n  stages {\n    stage('Deploy') {\n      when { branch 'main' }\n      steps {\n        withCredentials([string(credentialsId: 'api-token', variable: 'TOKEN')], {\n          sh \"curl -H Authorization:${TOKEN} https://example.com\"\n        })\n      }\n    }\n  }\n}\n",
 "B024": "pipeline {\n  agent any\n  stages {\n    stage('Deploy') {\n      when { branch 'main' }\n      steps {\n        script {\n          def b = [string(credentialsId: 'api-token', variable: 'TOKEN')]\n          withCredentials(b) {\n            sh \"curl -H Authorization:${TOKEN} https://example.com\"\n          }\n        }\n      }\n    }\n  }\n}\n",
 "B025": "pipeline {\n  agent any\n  stages {\n    stage('Deploy') {\n      when { branch 'main' }\n      steps {\n        withCredentials([string([credentialsId: 'api-token', variable: 'TOKEN'])]) {\n          sh \"curl -H Authorization:${TOKEN} https://example.com\"\n        }\n      }\n    }\n  }\n}\n",
 "B026": "pipeline {\n  agent any\n  stages {\n    stage('Deploy') {\n      when { branch 'main' }\n      steps {\n        withCredentials([[$class: 'AmazonWebServicesCredentialsBinding', credentialsId: 'aws']]) {\n          sh \"AWS_SECRET_ACCESS_KEY=${AWS_SECRET_ACCESS_KEY} ./upload.sh\"\n        }\n      }\n    }\n  }\n}\n",
 "B027": "pipeline {\n  agent any\n  stages {\n    stage('Deploy') {\n      when { branch 'main' }\n      steps {\n        withCredentials([azureServicePrincipal('sp')]) {\n          sh \"az login --service-principal -u ${AZURE_CLIENT_ID} -p ${AZURE_CLIENT_SECRET} --tenant ${AZURE_TENANT_ID}\"\n        }\n      }\n    }\n  }\n}\n",
 "B028": "pipeline {\n  agent any\n  stages {\n    stage('Deploy') {\n      when { branch 'main' }\n      steps {\n        withAWS(credentials: 'aws', region: 'eu-west-1') {\n          sh \"curl --aws-sigv4 aws:amz:eu-west-1:s3 --user ${env.AWS_ACCESS_KEY_ID}:${env.AWS_SECRET_ACCESS_KEY} https://example.com\"\n        }\n      }\n    }\n  }\n}\n",
 "B029": "pipeline {\n  agent any\n  stages {\n    stage('Deploy') {\n      when { branch 'main' }\n      steps {\n        withVault(configuration: [vaultUrl: 'https://vault.example.com', vaultCredentialId: 'vault-approle'],\n                  vaultSecrets: [[path: 'secret/deploy', secretValues: [[envVar: 'TOKEN', vaultKey: 'token']]]]) {\n          sh \"curl -H Authorization:${TOKEN} https://example.com\"\n        }\n      }\n    }\n  }\n}\n",
 "B030": "pipeline {\n  agent any\n  stages {\n    stage('Deploy') {\n      when { branch 'main' }\n      steps {\n        withCredentials([string(credentialsId: 'api-token', variable: 'TOKEN')]) {\n          script {\n            def n = 'TOK' + 'EN'\n            sh \"curl -H Authorization:${env[n]} https://example.com\"\n          }\n        }\n      }\n    }\n  }\n}\n",
 "B033": "def callApi(t) {\n  sh \"curl -H Authorization:${t} https://example.com\"\n}\npipeline {\n  agent any\n  stages {\n    stage('Deploy') {\n      when { branch 'main' }\n      steps {\n        withCredentials([string(credentialsId: 'api-token', variable: 'TOKEN')]) {\n          callApi(TOKEN)\n        }\n      }\n    }\n  }\n}\n",
 "B034": "def withApi(Closure body) {\n  withCredentials([string(credentialsId: 'api-token', variable: 'TOKEN')]) {\n    body()\n  }\n}\npipeline {\n  agent any\n  stages {\n    stage('Deploy') {\n      when { branch 'main' }\n      steps {\n        withApi {\n          sh \"curl -H Authorization:${TOKEN} https://example.com\"\n        }\n      }\n    }\n  }\n}\n",
 "B041": "pipeline {\n  agent any\n  stages {\n    stage('Deploy') {\n      when { branch 'main' }\n      steps {\n        sshagent(['deploy']) {\n          sh \"SSH_AUTH_SOCK=${env.SSH_AUTH_SOCK} ssh deploy@host true\"\n        }\n      }\n    }\n  }\n}\n",
 "B042": "pipeline {\n  agent any\n  stages {\n    stage('Deploy') {\n      when { branch 'main' }\n      steps {\n        withCredentials([string(credentialsId: 'api-token', variable: 'TOKEN')]) {\n          script {\n            docker.image('alpine:3').inside(\"-e T=${TOKEN}\") {\n              sh 'true'\n            }\n          }\n        }\n      }\n    }\n  }\n}\n",
 "B102": "pipeline {\n  agent any\n  stages {\n    stage('Deploy') {\n      when { branch 'main' }\n      steps {\n        withCredentials([gitUsernamePassword(credentialsId: 'repo', gitToolName: 'git')]) {\n          sh \"git push https://${GIT_USERNAME}:${GIT_PASSWORD}@example.com/repo.git HEAD:main\"\n        }\n      }\n    }\n  }\n}\n",
 "B046": "pipeline {\n  agent any\n  stages {\n    stage('Release') {\n      when { branch 'main' }\n      steps {\n        withCredentials([file(credentialsId: 'release.jks', variable: 'STORE')]) {\n          sh './gradlew assembleRelease -Pstore=\"$STORE\"'\n        }\n      }\n    }\n  }\n}\n",
 "B047": "pipeline {\n  agent any\n  stages {\n    stage('Release') {\n      when { branch 'main' }\n      steps {\n        withCredentials([certificate(credentialsId: 'release', keystoreVariable: 'STORE', passwordVariable: 'STOREPASS')]) {\n          sh './gradlew assembleRelease'\n        }\n      }\n    }\n  }\n}\n",
 "B048": "pipeline {\n  agent any\n  stages {\n    stage('Release') {\n      when { branch 'main' }\n      steps {\n        withCredentials([file(credentialsId: 'secring.gpg', variable: 'RING')]) {\n          sh './gradlew publish -Psigning.secretKeyRingFile=\"$RING\"'\n        }\n      }\n    }\n  }\n}\n",
 "B049": "pipeline {\n  agent any\n  stages {\n    stage('Release') {\n      when { branch 'main' }\n      steps {\n        withCredentials([file(credentialsId: 'signing.asc', variable: 'ASC')]) {\n          sh './gradlew assemble'\n        }\n      }\n    }\n  }\n}\n",
 "B050": "pipeline {\n  agent any\n  stages {\n    stage('Release') {\n      when { branch 'main' }\n      steps {\n        withCredentials([string(credentialsId: 'maven-central', variable: 'ORG_GRADLE_PROJECT_signingInMemoryKey')]) {\n          sh './gradlew assemble'\n        }\n      }\n    }\n  }\n}\n",
 "B052": "pipeline {\n  agent any\n  environment {\n    GPG = credentials('release-gpg')\n  }\n  stages {\n    stage('Release') {\n      when { branch 'main' }\n      steps {\n        sh './gradlew assemble'\n      }\n    }\n  }\n}\n",
 "B053": "pipeline {\n  agent any\n  stages {\n    stage('Release') {\n      when { branch 'main' }\n      steps {\n        withCredentials([file(credentialsId: 'ios-dist-cert', variable: 'DIST')]) {\n          sh 'xcodebuild -version'\n        }\n      }\n    }\n  }\n}\n",
 "B054": "pipeline {\n  agent any\n  stages {\n    stage('Release') {\n      when { branch 'main' }\n      steps {\n        withCredentials([file(credentialsId: 'artifact-signer-key', variable: 'K')]) {\n          sh 'true'\n        }\n      }\n    }\n  }\n}\n",
 "B055": "pipeline {\n  agent any\n  stages {\n    stage('Release') {\n      when { branch 'main' }\n      steps {\n        sh '''\n          cosign sign --yes \\\\\n            --key cosign.key registry.example.com/app:1\n        '''\n      }\n    }\n  }\n}\n",
 "B056": "pipeline {\n  agent any\n  stages {\n    stage('Release') {\n      when { branch 'main' }\n      steps {\n        sh '''\n          gpg --batch \\\\\n            --import key.asc\n        '''\n      }\n    }\n  }\n}\n",
 "B057": "pipeline {\n  agent any\n  stages {\n    stage('Release') {\n      when { branch 'main' }\n      steps {\n        sh '''gpg --batch \\\n--import key.asc'''\n      }\n    }\n  }\n}\n",
 "B059": "pipeline {\n  agent any\n  stages {\n    stage('Release') {\n      when { branch 'main' }\n      steps {\n        script {\n          def imp = 'gpg --batch --import key.asc'\n          sh imp\n        }\n      }\n    }\n  }\n}\n",
 "B060": "pipeline {\n  agent any\n  stages {\n    stage('Release') {\n      when { branch 'main' }\n      steps {\n        bat 'SignTool sign /fd SHA256 /f cert.pfx /p %P% app.exe'\n      }\n    }\n  }\n}\n",
 "B061": "pipeline {\n  agent any\n  stages {\n    stage('Release') {\n      when { branch 'main' }\n      steps {\n        sh 'security import \"$P12\" -k build.keychain -P \"$P12_PASS\" -T /usr/bin/codesign'\n      }\n    }\n  }\n}\n",
 "B062": "pipeline {\n  agent any\n  stages {\n    stage('Release') {\n      when { branch 'main' }\n      steps {\n        sh 'apksigner sign --key release.pk8 --cert release.x509.pem app.apk'\n      }\n    }\n  }\n}\n",
 "B063": "pipeline {\n  agent any\n  stages {\n    stage('Release') {\n      when { branch 'main' }\n      steps {\n        bat 'certutil -user -p %P% -importPFX cert.pfx'\n      }\n    }\n  }\n}\n",
 "B064": "pipeline {\n  agent any\n  stages {\n    stage('Release') {\n      when { branch 'main' }\n      steps {\n        sh 'cosign import-key-pair --key key.pem'\n      }\n    }\n  }\n}\n",
 "B065": "pipeline {\n  agent any\n  stages {\n    stage('Release') {\n      when { branch 'main' }\n      steps {\n        sh 'cosign sign --yes --key=awskms:///alias/release registry.example.com/app:1'\n      }\n    }\n  }\n}\n",
 "B066": "pipeline {\n  agent any\n  stages {\n    stage('Release') {\n      when { branch 'main' }\n      steps {\n        sh 'docker trust key load --name ci release.pem'\n      }\n    }\n  }\n}\n",
 "B067": "pipeline {\n  agent any\n  stages {\n    stage('Release') {\n      when { branch 'main' }\n      steps {\n        sh 'osslsigncode sign -pkcs12 cert.pfx -pass \"$P\" -in app.exe -out app-signed.exe'\n      }\n    }\n  }\n}\n",
 "B068": "pipeline {\n  agent any\n  stages {\n    stage('Release') {\n      when { branch 'main' }\n      steps {\n        sh 'gpg --batch --import key.asc'\n      }\n      post {\n        success {\n          sh 'mvn -B deploy'\n        }\n      }\n    }\n  }\n}\n",
 "B072": "pipeline {\n  agent any\n  stages {\n    stage('Release') {\n      when { branch 'main' }\n      steps {\n        script {\n          def c = [file(credentialsId: 'gpg-signing-key', variable: 'KEYFILE')]\n          withCredentials(c) {\n            sh './gradlew assemble'\n          }\n        }\n      }\n    }\n  }\n}\n",
 "B073": "pipeline {\n  agent any\n  stages {\n    stage('Release') {\n      when { branch 'main' }\n      steps {\n        withCredentials([file([credentialsId: 'gpg-signing-key', variable: 'KEYFILE'])]) {\n          sh './gradlew assemble'\n        }\n      }\n    }\n  }\n}\n",
 "B074": "pipeline {\n  agent any\n  stages {\n    stage('Release') {\n      when { branch 'main' }\n      steps {\n        withCredentials([sshUserPrivateKey(credentialsId: 'artifact-signer', keyFileVariable: 'KEY')]) {\n          sh 'ssh-keygen -Y sign -f \"$KEY\" -n file dist/app.tar.gz'\n        }\n      }\n    }\n  }\n}\n",
 "B075": "pipeline {\n  agent any\n  stages {\n    stage('Release') {\n      when { branch 'main' }\n      steps {\n        withCredentials([file(credentialsId: 'release-key', variable: 'KEY')]) {\n          sh 'openssl dgst -sha256 -sign \"$KEY\" -out app.sig app.bin'\n        }\n      }\n    }\n  }\n}\n",
 "B078": "def T = 'abc123secret'\npipeline {\n  agent any\n  triggers {\n    GenericTrigger(genericVariables: [[key: 'ref', value: '$.ref']], token: T)\n  }\n  stages {\n    stage('Build') {\n      steps {\n        sh 'make'\n      }\n    }\n  }\n}\n",
 "B079": "def T = 'abc123secret'\npipeline {\n  agent any\n  triggers {\n    GenericTrigger(genericVariables: [[key: 'ref', value: '$.ref']], token: \"${T}\")\n  }\n  stages {\n    stage('Build') {\n      steps {\n        sh 'make'\n      }\n    }\n  }\n}\n",
 "B080": "pipeline {\n  agent any\n  triggers {\n    GenericTrigger(genericVariables: [[key: 'ref', value: '$.ref']], token: 'abc123' + 'secret')\n  }\n  stages {\n    stage('Build') {\n      steps {\n        sh 'make'\n      }\n    }\n  }\n}\n",
 "B081": "pipeline {\n  agent any\n  triggers {\n    GenericTrigger([genericVariables: [[key: 'ref', value: '$.ref']], token: 'abc123secret'])\n  }\n  stages {\n    stage('Build') {\n      steps {\n        sh 'make'\n      }\n    }\n  }\n}\n",
 "B086": "pipeline {\n  agent any\n  triggers {\n    gitlab(triggerOnPush: true, triggerOnMergeRequest: false, branchFilterType: 'All', secretToken: 'abcdefghijklmnop0123')\n  }\n  stages {\n    stage('Build') {\n      steps {\n        sh 'make'\n      }\n    }\n  }\n}\n",
 "B087": "properties([pipelineTriggers([[$class: 'GitLabPushTrigger', triggerOnPush: true, triggerOnMergeRequest: false, secretToken: 'abcdefghijklmnop0123']])])\nnode {\n  sh 'make'\n}\n",
 "B089": "properties([pipelineTriggers([GenericTrigger(genericVariables: [[key: 'ref', value: '$.ref']], token: env.JOB_NAME)])])\nnode {\n  sh 'make'\n}\n",
 "B094": "pipeline {\n  agent any\n  triggers {\n    GenericTrigger(genericVariables: [[key: 'ref', value: '$.ref']], token: 'abc123secret'.trim())\n  }\n  stages {\n    stage('Build') {\n      steps {\n        sh 'make'\n      }\n    }\n  }\n}\n",
 "B096": "pipeline {\n  agent any\n  environment {\n    HOOK = 'abc123secret'\n  }\n  triggers {\n    GenericTrigger(genericVariables: [[key: 'ref', value: '$.ref']], token: env.HOOK)\n  }\n  stages {\n    stage('Build') {\n      steps {\n        sh 'make'\n      }\n    }\n  }\n}\n",
 "C021": "def creds = [string(credentialsId: 'k', variable: 'K')]\npipeline {\n  agent any\n  stages {\n    stage('Build') {\n      steps {\n        withCredentials(bindings: creds) {\n          sh './gradlew test'\n        }\n      }\n    }\n  }\n}\n",
 "C022": "pipeline {\n  agent any\n  stages {\n    stage('Build') {\n      options { withAWS(credentials: 'k', region: 'us-east-1') }\n      steps {\n        sh './gradlew test'\n      }\n    }\n  }\n}\n",
 "C026": "def runTests() {\n  sh './gradlew test'\n}\nnode {\n  stage('Build') {\n        withCredentials([string(credentialsId: 'k', variable: 'K')]) {\n          this.runTests()\n        }\n  }\n}\n",
 "C027": "def runTests() {\n  sh './gradlew test'\n}\nnode {\n  stage('Build') {\n    def f = this.&runTests\n        withCredentials([string(credentialsId: 'k', variable: 'K')]) {\n          f()\n        }\n  }\n}\n",
 "C029": "def body = { sh './gradlew test' }\nnode {\n  stage('Build') {\n        withCredentials([string(credentialsId: 'k', variable: 'K')]) {\n          body.call()\n        }\n  }\n}\n",
 "C030": "def body = { sh './gradlew test' }\nnode {\n  stage('Build') {\n        withCredentials([string(credentialsId: 'k', variable: 'K')]) {\n          body()\n        }\n  }\n}\n",
 "C031": "def body = { sh './gradlew test' }\nnode {\n  stage('Build') {\n    withCredentials([string(credentialsId: 'k', variable: 'K')], body)\n  }\n}\n",
 "C034": "def tasks = [:]\ntasks['a'] = { sh './gradlew test' }\nnode {\n  stage('Build') {\n        withCredentials([string(credentialsId: 'k', variable: 'K')]) {\n          parallel tasks\n        }\n  }\n}\n",
 "C040": "node {\n  stage('Build') {\n        withCredentials([string(credentialsId: 'k', variable: 'K')]) {\n          steps.sh './gradlew test'\n        }\n  }\n}\n",
 "C041": "def withTok(Closure body, String id) {\n  withCredentials([string(credentialsId: id, variable: 'K')]) {\n    body()\n  }\n}\nnode {\n  stage('Build') {\n    withTok({ sh './gradlew test' }, 'k')\n  }\n}\n",
 "C043": "def tasks = [build: { sh './gradlew test' }]\nnode {\n  stage('Build') {\n        withCredentials([string(credentialsId: 'k', variable: 'K')]) {\n          tasks.build()\n        }\n  }\n}\n",
 "C052": "pipeline {\n  agent any\n  stages {\n    stage('Build') {\n      when { branch 'MR-*' }\n      steps {\n        withCredentials([string(credentialsId: 'k', variable: 'K')]) {\n          sh './gradlew test'\n        }\n      }\n    }\n  }\n}\n",
 "C053": "pipeline {\n  agent any\n  stages {\n    stage('Build') {\n      when { not { branch 'PR-*' } }\n      steps {\n        withCredentials([string(credentialsId: 'k', variable: 'K')]) {\n          sh './gradlew test'\n        }\n      }\n    }\n  }\n}\n",
 "C054": "pipeline {\n  agent any\n  stages {\n    stage('Build') {\n      when { not { branch pattern: 'PR-\\\\d+', comparator: 'REGEXP' } }\n      steps {\n        withCredentials([string(credentialsId: 'k', variable: 'K')]) {\n          sh './gradlew test'\n        }\n      }\n    }\n  }\n}\n",
 "C055": "pipeline {\n  agent any\n  stages {\n    stage('Build') {\n      steps {\n        script {\n          if (env.GIT_BRANCH.startsWith('PR-')) {\n        withCredentials([string(credentialsId: 'k', variable: 'K')]) {\n          sh './gradlew test'\n        }\n          }\n        }\n      }\n    }\n  }\n}\n",
 "C056": "pipeline {\n  agent any\n  stages {\n    stage('Build') {\n      when { expression { env.BRANCH_NAME != 'main' } }\n      steps {\n        withCredentials([string(credentialsId: 'k', variable: 'K')]) {\n          sh './gradlew test'\n        }\n      }\n    }\n  }\n}\n",
 "C057": "pipeline {\n  agent any\n  stages {\n    stage('Build') {\n      when { not { not { changeRequest() } } }\n      steps {\n        withCredentials([string(credentialsId: 'k', variable: 'K')]) {\n          sh './gradlew test'\n        }\n      }\n    }\n  }\n}\n",
 "C062": "pipeline {\n  agent any\n  stages {\n    stage('Build') {\n      when { branch 'main' }\n      steps {\n        script {\n          def agentCmd = 'claude'\n        withCredentials([string(credentialsId: 'k', variable: 'K')]) {\n          sh \"${agentCmd} -p 'review'\"\n        }\n        }\n      }\n    }\n  }\n}\n",
 "C063": "pipeline {\n  agent any\n  stages {\n    stage('Build') {\n      when { branch 'main' }\n      steps {\n        script {\n          def cmd = 'codex exec \"fix the tests\"'\n        withCredentials([string(credentialsId: 'k', variable: 'K')]) {\n          sh cmd\n        }\n        }\n      }\n    }\n  }\n}\n",
 "C070": "pipeline {\n  agent any\n  stages {\n    stage('Build') {\n      when { branch 'main' }\n      steps {\n        withCredentials([string(credentialsId: 'k', variable: 'K')]) {\n          sh '''\n            claude \\\\\n              -p \"review\"\n          '''\n        }\n      }\n    }\n  }\n}\n",
 "C072": "pipeline {\n  agent any\n  stages {\n    stage('Build') {\n      when { branch 'main' }\n      steps {\n        script {\n        withCredentials([string(credentialsId: 'k', variable: 'K')]) {\n          steps.sh 'claude -p review'\n        }\n        }\n      }\n    }\n  }\n}\n",
 "C088": "node {\n  stage('Build') {\n        withCredentials([string(credentialsId: 'k', variable: 'K')]) {\n          this.sh './gradlew test'\n        }\n  }\n}\n",
 "C096": "pipeline {\n  agent any\n  stages {\n    stage('Build') {\n      steps {\n        withCredentials(bindings: [string(credentialsId: 'k', variable: 'K')] + []) {\n          sh './gradlew test'\n        }\n      }\n    }\n  }\n}\n",
 "C097": "def runTests() {\n  sh './gradlew test'\n}\nnode {\n  stage('Build') {\n        withCredentials([string(credentialsId: 'k', variable: 'K')]) {\n          this.&runTests.call()\n        }\n  }\n}\n",
 "C098": "pipeline {\n  agent any\n  stages {\n    stage('Build') {\n      options { withCredentials([string(credentialsId: 'k', variable: 'K')]) }\n      steps {\n        sh './gradlew test'\n      }\n    }\n  }\n}\n",
 "C045": "pipeline {\n  agent any\n  stages {\n    stage('Build') {\n      when { not { changeRequest() } }\n      steps {\n        withCredentials([string(credentialsId: 'k', variable: 'K')]) {\n          sh './gradlew test'\n        }\n      }\n    }\n  }\n}\n",
 "C051": "pipeline {\n  agent any\n  stages {\n    stage('Build') {\n      when { branch 'main' }\n      steps {\n        withCredentials([string(credentialsId: 'k', variable: 'K')]) {\n          sh './gradlew test'\n        }\n      }\n    }\n  }\n}\n",
 "C091": "node {\n  stage('Build') {\n    if (env.BRANCH_NAME == 'main') {\n        withCredentials([string(credentialsId: 'k', variable: 'K')]) {\n          sh './gradlew test'\n        }\n    }\n  }\n}\n",
 "C092": "node {\n  stage('Build') {\n    if (env.CHANGE_ID) {\n      echo 'pr'\n    } else {\n        withCredentials([string(credentialsId: 'k', variable: 'K')]) {\n          sh './gradlew test'\n        }\n    }\n  }\n}\n",
 "C093": "pipeline {\n  agent any\n  stages {\n    stage('Build') {\n      steps {\n        withCredentials([string(credentialsId: 'k', variable: 'K')]) {\n          echo 'hello'\n        }\n      }\n    }\n  }\n}\n",
 "C094": "pipeline {\n  agent any\n  stages {\n    stage('Review') { steps { sh 'claude -p \"review\"' } }\n    stage('Deploy') {\n      when { branch 'main' }\n      steps {\n        withCredentials([string(credentialsId: 'k', variable: 'K')]) {\n          sh 'curl -X POST https://deploy.example'\n        }\n      }\n    }\n  }\n}\n",
 "r05_wrapper_compose": "def withRetry(Closure body) {\n  retry(3) {\n    body()\n  }\n}\ndef withDeployCreds(Closure body) {\n  withRetry {\n    withCredentials([string(credentialsId: 'deploy', variable: 'TOKEN')]) {\n      body()\n    }\n  }\n}\nnode {\n  stage('Deploy') {\n    withDeployCreds {\n      sh './deploy.sh'\n    }\n  }\n}\n",
 "r01_frame_self": "def m(Closure body) { body() }\nnode {\n  stage('Build') {\n    withCredentials([string(credentialsId: 'k', variable: 'K')]) {\n      m { body() }\n    }\n  }\n}\n",
 "r02_map_self": "def tasks = [:]\ntasks['a'] = { parallel tasks }\nnode {\n  stage('Build') {\n    withCredentials([string(credentialsId: 'k', variable: 'K')]) {\n      parallel tasks\n    }\n  }\n}\n",
 "r03_nested_same_helper": "def m(Closure body) { body() }\nnode {\n  stage('Build') {\n    withCredentials([string(credentialsId: 'k', variable: 'K')]) {\n      m { m { sh './gradlew test' } }\n    }\n  }\n}\n",
 "c01_list_append": "node {\n  stage('Build') {\n    def b = []\n    b << string(credentialsId: 'k', variable: 'K')\n    withCredentials(b) {\n      sh \"./gradlew test -Pk=${K}\"\n    }\n  }\n}\n",
 "c01b_list_add": "node {\n  stage('Build') {\n    def b = []\n    b.add(string(credentialsId: 'k', variable: 'K'))\n    withCredentials(b) {\n      sh \"./gradlew test -Pk=${K}\"\n    }\n  }\n}\n",
 "h03_list_var_mixed": "pipeline {\n  agent any\n  stages {\n    stage('Deploy') {\n      when { branch 'main' }\n      steps {\n        script {\n          def extra = []\n          extra << string(credentialsId: 'gh', variable: 'GH_TOKEN')\n          withCredentials([string(credentialsId: 'a', variable: 'A')] + extra) {\n            sh \"curl -H Authorization:${GH_TOKEN} https://example.com\"\n          }\n        }\n      }\n    }\n  }\n}\n",
 "h01_method_binding": "def ghBinding() { return string(credentialsId: 'gh', variable: 'GH_TOKEN') }\npipeline {\n  agent any\n  stages {\n    stage('Deploy') {\n      when { branch 'main' }\n      steps {\n        withCredentials([string(credentialsId: 'a', variable: 'A'), ghBinding()]) {\n          sh \"curl -H Authorization:${GH_TOKEN} https://example.com\"\n        }\n      }\n    }\n  }\n}\n",
 "f01_gstrprop": "pipeline {\n  agent any\n  stages {\n    stage('Deploy') {\n      when { branch 'main' }\n      steps {\n        withCredentials([string(credentialsId: 'api-token', variable: 'TOKEN')]) {\n          script {\n            def n = 'TOK' + 'EN'\n            def v = env.\"${n}\"\n            sh \"curl -H Authorization:${v} https://example.com\"\n          }\n        }\n      }\n    }\n  }\n}\n",
 "f02_getenv": "pipeline {\n  agent any\n  stages {\n    stage('Deploy') {\n      when { branch 'main' }\n      steps {\n        withCredentials([string(credentialsId: 'api-token', variable: 'TOKEN')]) {\n          script {\n            def n = 'TOK' + 'EN'\n            sh \"curl -H Authorization:${System.getenv(n)} https://example.com\"\n          }\n        }\n      }\n    }\n  }\n}\n",
 "f04_envgetat": "pipeline {\n  agent any\n  stages {\n    stage('Deploy') {\n      when { branch 'main' }\n      steps {\n        withCredentials([string(credentialsId: 'api-token', variable: 'TOKEN')]) {\n          script {\n            def n = 'TOK' + 'EN'\n            sh \"curl -H Authorization:${env.getAt(n)} https://example.com\"\n          }\n        }\n      }\n    }\n  }\n}\n",
 "f06_env_index_var": "pipeline {\n  agent any\n  stages {\n    stage('Deploy') {\n      when { branch 'main' }\n      steps {\n        withCredentials([string(credentialsId: 'api-token', variable: 'TOKEN')]) {\n          script {\n            def n = 'TOK' + 'EN'\n            def e = env\n            sh \"curl -H Authorization:${e[n]} https://example.com\"\n          }\n        }\n      }\n    }\n  }\n}\n",
 "e01_each": "pipeline {\n  agent any\n  stages {\n    stage('Deploy') {\n      when { branch 'main' }\n      steps {\n        withCredentials([string(credentialsId: 'api-token', variable: 'TOKEN')]) {\n          script {\n            [TOKEN].each { t -> sh \"curl -H Authorization:${t} https://example.com\" }\n          }\n        }\n      }\n    }\n  }\n}\n",
 "e02_with": "pipeline {\n  agent any\n  stages {\n    stage('Deploy') {\n      when { branch 'main' }\n      steps {\n        withCredentials([string(credentialsId: 'api-token', variable: 'TOKEN')]) {\n          script {\n            TOKEN.with { sh \"curl -H Authorization:${it} https://example.com\" }\n          }\n        }\n      }\n    }\n  }\n}\n",
 "e06_multi": "pipeline {\n  agent any\n  stages {\n    stage('Deploy') {\n      when { branch 'main' }\n      steps {\n        withCredentials([string(credentialsId: 'api-token', variable: 'TOKEN')]) {\n          script {\n            def (a, b) = [TOKEN, \"x\"]\n            sh \"curl -H Authorization:${a} https://example.com\"\n          }\n        }\n      }\n    }\n  }\n}\n",
 "e07_closure_ret": "pipeline {\n  agent any\n  stages {\n    stage('Deploy') {\n      when { branch 'main' }\n      steps {\n        withCredentials([string(credentialsId: 'api-token', variable: 'TOKEN')]) {\n          script {\n            def get = { TOKEN }\n            sh \"curl -H Authorization:${get()} https://example.com\"\n          }\n        }\n      }\n    }\n  }\n}\n",
 "c02_methodptr_lastarg": "def runTests() {\n  sh './gradlew test'\n}\nnode {\n  stage('Build') {\n    withCredentials([string(credentialsId: 'k', variable: 'K')], this.&runTests)\n  }\n}\n",
 "c03_methodref_var_lastarg": "def runTests() {\n  sh './gradlew test'\n}\nnode {\n  stage('Build') {\n    def f = this.&runTests\n    withCredentials([string(credentialsId: 'k', variable: 'K')], f)\n  }\n}\n",
 "c04_map_put": "def tasks = [:]\ntasks.put('a', { sh './gradlew test' })\nnode {\n  stage('Build') {\n    withCredentials([string(credentialsId: 'k', variable: 'K')]) {\n      parallel tasks\n    }\n  }\n}\n",
 "c05_map_prop": "def tasks = [:]\ntasks.a = { sh './gradlew test' }\nnode {\n  stage('Build') {\n    withCredentials([string(credentialsId: 'k', variable: 'K')]) {\n      parallel tasks\n    }\n  }\n}\n",
 "c05b_map_call_index": "def tasks = [a: { sh './gradlew test' }]\nnode {\n  stage('Build') {\n    withCredentials([string(credentialsId: 'k', variable: 'K')]) {\n      tasks['a']()\n    }\n  }\n}\n",
 "k01_bat_caret": "pipeline {\n  agent any\n  stages {\n    stage('Release') {\n      when { branch 'main' }\n      steps {\n        bat '''signtool sign /fd SHA256 ^\n  /f cert.pfx /p %P% app.exe'''\n        powershell '''certutil -user -p $env:P `\n  -importPFX cert.pfx'''\n      }\n    }\n  }\n}\n",
 "c10_interp_cmd_var": "pipeline {\n  agent any\n  stages {\n    stage('Release') {\n      when { branch 'main' }\n      steps {\n        script {\n          def imp = \"gpg --batch --import ${env.WORKSPACE}/key.asc\"\n          sh imp\n        }\n      }\n    }\n  }\n}\n",
 "c10b_agent_interp_var": "pipeline {\n  agent any\n  stages {\n    stage('Review') {\n      steps {\n        withCredentials([string(credentialsId: 'gh-token', variable: 'GH_TOKEN')]) {\n          script {\n            def cmd = \"claude -p 'review ${env.BUILD_TAG}'\"\n            sh cmd\n          }\n        }\n      }\n    }\n  }\n}\n",
 "c06_certmulti_map": "pipeline {\n  agent any\n  stages {\n    stage('Release') {\n      when { branch 'main' }\n      steps {\n        withCredentials([[$class: 'CertificateMultiBinding', credentialsId: 'release', keystoreVariable: 'STORE', passwordVariable: 'PW']]) {\n          sh './gradlew assembleRelease'\n        }\n      }\n    }\n  }\n}\n",
 "u01_list_mutated_in_method": "def addGh(list) { list << string(credentialsId: 'gh', variable: 'GH_TOKEN') }\npipeline {\n  agent any\n  stages {\n    stage('Deploy') {\n      when { branch 'main' }\n      steps {\n        script {\n          def b = [string(credentialsId: 'a', variable: 'A')]\n          addGh(b)\n          withCredentials(b) {\n            sh \"curl -H Authorization:${GH_TOKEN} https://example.com\"\n          }\n        }\n      }\n    }\n  }\n}\n",
 "u02_list_alias": "pipeline {\n  agent any\n  stages {\n    stage('Deploy') {\n      when { branch 'main' }\n      steps {\n        script {\n          def b = [string(credentialsId: 'a', variable: 'A')]\n          def c = b\n          c << string(credentialsId: 'gh', variable: 'GH_TOKEN')\n          withCredentials(b) {\n            sh \"curl -H Authorization:${GH_TOKEN} https://example.com\"\n          }\n        }\n      }\n    }\n  }\n}\n",
 "e08_bindvar": "pipeline {\n  agent any\n  stages {\n    stage('Deploy') {\n      when { branch 'main' }\n      steps {\n        withCredentials([string(credentialsId: 'api-token', variable: 'TOKEN')]) {\n          script {\n            def tok = binding.getVariable(\"TOK\" + \"EN\")\n            sh \"curl -H Authorization:${tok} https://example.com\"\n          }\n        }\n      }\n    }\n  }\n}\n",
 "n05_ternary": "pipeline {\n  agent any\n  parameters { string(name: 'TARGET', defaultValue: 'staging') }\n  stages {\n    stage('Deploy') {\n      when { branch 'main' }\n      steps {\n        withCredentials([usernamePassword(credentialsId: 'registry', usernameVariable: 'REG_USER', passwordVariable: 'REG_PASS')]) {\n          script {\n            sh \"helm upgrade app ./chart -f values-${params.TARGET == \"prod\" ? \"prod\" : \"staging\"}.yaml\"\n          }\n        }\n      }\n    }\n  }\n}\n",
 "n06_tool": "pipeline {\n  agent any\n  parameters { string(name: 'TARGET', defaultValue: 'staging') }\n  stages {\n    stage('Deploy') {\n      when { branch 'main' }\n      steps {\n        withCredentials([usernamePassword(credentialsId: 'registry', usernameVariable: 'REG_USER', passwordVariable: 'REG_PASS')]) {\n          script {\n            sh \"${tool \"maven-3\"}/bin/mvn -B deploy\"\n          }\n        }\n      }\n    }\n  }\n}\n",
 "n07_newdate": "pipeline {\n  agent any\n  parameters { string(name: 'TARGET', defaultValue: 'staging') }\n  stages {\n    stage('Deploy') {\n      when { branch 'main' }\n      steps {\n        withCredentials([usernamePassword(credentialsId: 'registry', usernameVariable: 'REG_USER', passwordVariable: 'REG_PASS')]) {\n          script {\n            sh \"echo deployed at ${new Date().format(\"yyyyMMdd\")}\"\n          }\n        }\n      }\n    }\n  }\n}\n",
 "w04_as": "pipeline {\n  agent any\n  stages {\n    stage('Deploy') {\n      when { branch 'main' }\n      steps {\n        withCredentials([string(credentialsId: 'api-token', variable: 'TOKEN')]) {\n          script {\n            [TOKEN].each { t ->\n              sh \"curl -H Authorization:${t as String} https://example.com\"\n            }\n          }\n        }\n      }\n    }\n  }\n}\n",
 "w06_nested_gstring": "pipeline {\n  agent any\n  stages {\n    stage('Deploy') {\n      when { branch 'main' }\n      steps {\n        withCredentials([string(credentialsId: 'api-token', variable: 'TOKEN')]) {\n          script {\n            [TOKEN].each { t ->\n              sh \"curl -H Authorization:${\"${t}\".trim()} https://example.com\"\n            }\n          }\n        }\n      }\n    }\n  }\n}\n",
 "v01_plain": "\npipeline {\n  agent any\n  stages {\n    stage('Deploy') {\n      when { branch 'main' }\n      steps {\n        script {\n          def creds = [string(credentialsId: \"api\", variable: \"TOKEN\")]\n          withCredentials(creds) { sh \"curl -H Authorization:${TOKEN} https://example.com\" }\n        }\n      }\n    }\n  }\n}\n",
 "v03_echo_size": "\npipeline {\n  agent any\n  stages {\n    stage('Deploy') {\n      when { branch 'main' }\n      steps {\n        script {\n          def creds = [string(credentialsId: \"api\", variable: \"TOKEN\")]\n          echo \"bindings: ${creds.size()}\"\n          echo creds.size().toString()\n          withCredentials(creds) { sh \"curl -H Authorization:${TOKEN} https://example.com\" }\n        }\n      }\n    }\n  }\n}\n",
 "x04_nested_dollar_nobrace": "pipeline {\n  agent any\n  stages {\n    stage('Deploy') {\n      when { branch 'main' }\n      steps {\n        withCredentials([string(credentialsId: 'api-token', variable: 'TOKEN')]) {\n          script {\n            def v = '3'\n            [TOKEN].each { t ->\n              sh \"curl -H Authorization:${\"$t\".trim()} https://example.com\"\n            }\n          }\n        }\n      }\n    }\n  }\n}\n",
 "x07_nested_dollar_plus": "pipeline {\n  agent any\n  stages {\n    stage('Deploy') {\n      when { branch 'main' }\n      steps {\n        withCredentials([string(credentialsId: 'api-token', variable: 'TOKEN')]) {\n          script {\n            def v = '3'\n            [TOKEN].each { t ->\n              sh \"curl -H ${\"Authorization:$t\"} https://example.com\"\n            }\n          }\n        }\n      }\n    }\n  }\n}\n",
 "x03_tool_interp": "pipeline {\n  agent any\n  stages {\n    stage('Deploy') {\n      when { branch 'main' }\n      steps {\n        withCredentials([string(credentialsId: 'api-token', variable: 'TOKEN')]) {\n          script {\n            def v = '3'\n            [TOKEN].each { t ->\n              sh \"${tool \"m-${v}\"}/bin/mvn deploy\"\n            }\n          }\n        }\n      }\n    }\n  }\n}\n",
 "x05_nested_words": "pipeline {\n  agent any\n  stages {\n    stage('Deploy') {\n      when { branch 'main' }\n      steps {\n        withCredentials([string(credentialsId: 'api-token', variable: 'TOKEN')]) {\n          script {\n            def v = '3'\n            [TOKEN].each { t ->\n              sh \"echo ${\"build-${v}-done\".toUpperCase()}\"\n            }\n          }\n        }\n      }\n    }\n  }\n}\n",
 "y04_inner_quote_upper": "pipeline {\n  agent any\n  stages {\n    stage('Deploy') {\n      when { branch 'main' }\n      steps {\n        withCredentials([string(credentialsId: 'api-token', variable: 'TOKEN')]) {\n          script {\n            def v = '3'\n            def a = 'x'\n            [TOKEN].each { t ->\n              sh \"curl -H ${\"Bearer ${t ?: \"X\"}\"} https://example.com\"\n            }\n          }\n        }\n      }\n    }\n  }\n}\n",
 "y05_inner_replace_upper": "pipeline {\n  agent any\n  stages {\n    stage('Deploy') {\n      when { branch 'main' }\n      steps {\n        withCredentials([string(credentialsId: 'api-token', variable: 'TOKEN')]) {\n          script {\n            def v = '3'\n            def a = 'x'\n            [TOKEN].each { t ->\n              sh \"curl -H ${\"Bearer ${t.replace(\"A\", \"B\")}\"} https://example.com\"\n            }\n          }\n        }\n      }\n    }\n  }\n}\n",
 "y08_triple": "pipeline {\n  agent any\n  stages {\n    stage('Deploy') {\n      when { branch 'main' }\n      steps {\n        withCredentials([string(credentialsId: 'api-token', variable: 'TOKEN')]) {\n          script {\n            def v = '3'\n            def a = 'x'\n            [TOKEN].each { t ->\n              sh \"curl -H ${\"\"\"Bearer ${t}\"\"\"} https://example.com\"\n            }\n          }\n        }\n      }\n    }\n  }\n}\n"
}

# (case, rule, what the adapter must say: a finding, "unknown" (never a pass) or nothing, severity)
EXPECT = [
    ('B013', 'OBAAF-JEN-013', 'finding', 'medium'),
    ('B014', 'OBAAF-JEN-013', 'finding', 'medium'),
    ('B018', 'OBAAF-JEN-013', 'finding', 'medium'),
    ('B022', 'OBAAF-JEN-013', 'none', None),
    ('B023', 'OBAAF-JEN-013', 'finding', 'medium'),
    ('B024', 'OBAAF-JEN-013', 'finding', 'medium'),
    ('B025', 'OBAAF-JEN-013', 'finding', 'medium'),
    ('B026', 'OBAAF-JEN-013', 'finding', 'medium'),
    ('B027', 'OBAAF-JEN-013', 'finding', 'medium'),
    ('B028', 'OBAAF-JEN-013', 'finding', 'medium'),
    ('B029', 'OBAAF-JEN-013', 'finding', 'medium'),
    ('B030', 'OBAAF-JEN-013', 'unknown', None),
    ('B033', 'OBAAF-JEN-013', 'finding', 'medium'),
    ('B034', 'OBAAF-JEN-013', 'finding', 'medium'),
    ('B041', 'OBAAF-JEN-013', 'none', None),
    ('B042', 'OBAAF-JEN-013', 'finding', 'medium'),
    ('B102', 'OBAAF-JEN-013', 'finding', 'medium'),
    ('B046', 'OBAAF-JEN-014', 'finding', 'medium'),
    ('B047', 'OBAAF-JEN-014', 'finding', 'medium'),
    ('B048', 'OBAAF-JEN-014', 'finding', None),
    ('B049', 'OBAAF-JEN-014', 'finding', 'medium'),
    ('B050', 'OBAAF-JEN-014', 'finding', 'medium'),
    ('B052', 'OBAAF-JEN-014', 'finding', 'medium'),
    ('B053', 'OBAAF-JEN-014', 'finding', 'medium'),
    ('B054', 'OBAAF-JEN-014', 'finding', 'medium'),
    ('B055', 'OBAAF-JEN-014', 'finding', 'medium'),
    ('B056', 'OBAAF-JEN-014', 'finding', 'medium'),
    ('B057', 'OBAAF-JEN-014', 'finding', 'medium'),
    ('B059', 'OBAAF-JEN-014', 'finding', 'medium'),
    ('B060', 'OBAAF-JEN-014', 'finding', 'medium'),
    ('B061', 'OBAAF-JEN-014', 'finding', 'medium'),
    ('B062', 'OBAAF-JEN-014', 'finding', 'medium'),
    ('B063', 'OBAAF-JEN-014', 'finding', 'medium'),
    ('B064', 'OBAAF-JEN-014', 'finding', 'medium'),
    ('B065', 'OBAAF-JEN-014', 'none', None),
    ('B066', 'OBAAF-JEN-014', 'finding', 'medium'),
    ('B067', 'OBAAF-JEN-014', 'finding', 'medium'),
    ('B068', 'OBAAF-JEN-014', 'finding', 'high'),
    ('B072', 'OBAAF-JEN-014', 'finding', 'medium'),
    ('B073', 'OBAAF-JEN-014', 'finding', 'medium'),
    ('B074', 'OBAAF-JEN-014', 'finding', 'medium'),
    ('B075', 'OBAAF-JEN-014', 'finding', 'medium'),
    ('B078', 'OBAAF-JEN-015', 'finding', 'medium'),
    ('B079', 'OBAAF-JEN-015', 'finding', 'medium'),
    ('B080', 'OBAAF-JEN-015', 'finding', 'medium'),
    ('B081', 'OBAAF-JEN-015', 'finding', 'medium'),
    ('B086', 'OBAAF-JEN-015', 'finding', 'medium'),
    ('B087', 'OBAAF-JEN-015', 'finding', 'medium'),
    ('B089', 'OBAAF-JEN-015', 'unknown', None),
    ('B094', 'OBAAF-JEN-015', 'finding', 'medium'),
    ('B096', 'OBAAF-JEN-015', 'finding', 'medium'),
    ('C021', 'OBAAF-JEN-001', 'finding', 'medium'),
    ('C022', 'OBAAF-JEN-001', 'finding', 'medium'),
    ('C026', 'OBAAF-JEN-001', 'finding', 'medium'),
    ('C027', 'OBAAF-JEN-001', 'finding', 'medium'),
    ('C029', 'OBAAF-JEN-001', 'finding', 'medium'),
    ('C030', 'OBAAF-JEN-001', 'finding', 'medium'),
    ('C031', 'OBAAF-JEN-001', 'finding', 'medium'),
    ('C034', 'OBAAF-JEN-001', 'finding', 'medium'),
    ('C040', 'OBAAF-JEN-001', 'finding', 'medium'),
    ('C041', 'OBAAF-JEN-001', 'finding', 'medium'),
    ('C043', 'OBAAF-JEN-001', 'finding', 'medium'),
    ('C052', 'OBAAF-JEN-001', 'finding', 'high'),
    ('C053', 'OBAAF-JEN-001', 'finding', 'medium'),
    ('C054', 'OBAAF-JEN-001', 'finding', 'medium'),
    ('C055', 'OBAAF-JEN-001', 'finding', 'high'),
    ('C056', 'OBAAF-JEN-001', 'finding', 'high'),
    ('C057', 'OBAAF-JEN-001', 'finding', 'high'),
    ('C062', 'OBAAF-JEN-001', 'finding', 'high'),
    ('C063', 'OBAAF-JEN-001', 'finding', 'high'),
    ('C070', 'OBAAF-JEN-001', 'finding', 'high'),
    ('C072', 'OBAAF-JEN-001', 'finding', 'high'),
    ('C088', 'OBAAF-JEN-001', 'finding', 'medium'),
    ('C096', 'OBAAF-JEN-001', 'finding', 'medium'),
    ('C097', 'OBAAF-JEN-001', 'finding', 'medium'),
    ('C098', 'OBAAF-JEN-001', 'finding', 'medium'),
    ('C045', 'OBAAF-JEN-001', 'none', None),
    ('C051', 'OBAAF-JEN-001', 'none', None),
    ('C091', 'OBAAF-JEN-001', 'none', None),
    ('C092', 'OBAAF-JEN-001', 'none', None),
    ('C093', 'OBAAF-JEN-001', 'none', None),
    ('C094', 'OBAAF-JEN-001', 'none', None),
    ('r05_wrapper_compose', 'OBAAF-JEN-001', 'finding', 'medium'),
    ('r01_frame_self', 'OBAAF-JEN-001', 'unknown', None),
    ('r02_map_self', 'OBAAF-JEN-001', 'unknown', None),
    ('r03_nested_same_helper', 'OBAAF-JEN-001', 'finding', 'medium'),
    ('c01_list_append', 'OBAAF-JEN-001', 'finding', 'medium'),
    ('c01b_list_add', 'OBAAF-JEN-001', 'finding', 'medium'),
    ('h03_list_var_mixed', 'OBAAF-JEN-013', 'unknown', None),
    ('h01_method_binding', 'OBAAF-JEN-013', 'unknown', None),
    ('f01_gstrprop', 'OBAAF-JEN-013', 'unknown', None),
    ('f02_getenv', 'OBAAF-JEN-013', 'unknown', None),
    ('f04_envgetat', 'OBAAF-JEN-013', 'unknown', None),
    ('f06_env_index_var', 'OBAAF-JEN-013', 'unknown', None),
    ('e01_each', 'OBAAF-JEN-013', 'unknown', None),
    ('e02_with', 'OBAAF-JEN-013', 'unknown', None),
    # Flagship slice 2d.2 reads `def (a, b) = [x, y]` element by element, so `a` holds TOKEN: a finding.
    ('e06_multi', 'OBAAF-JEN-013', 'finding', 'medium'),
    ('e07_closure_ret', 'OBAAF-JEN-013', 'finding', 'medium'),
    ('c02_methodptr_lastarg', 'OBAAF-JEN-001', 'finding', 'medium'),
    ('c03_methodref_var_lastarg', 'OBAAF-JEN-001', 'finding', 'medium'),
    ('c04_map_put', 'OBAAF-JEN-001', 'finding', 'medium'),
    ('c05_map_prop', 'OBAAF-JEN-001', 'finding', 'medium'),
    ('c05b_map_call_index', 'OBAAF-JEN-001', 'finding', 'medium'),
    ('k01_bat_caret', 'OBAAF-JEN-014', 'finding', 'medium'),
    ('c10_interp_cmd_var', 'OBAAF-JEN-014', 'finding', 'medium'),
    ('c10b_agent_interp_var', 'OBAAF-JEN-001', 'finding', 'high'),
    ('c06_certmulti_map', 'OBAAF-JEN-014', 'finding', 'medium'),
    ('u01_list_mutated_in_method', 'OBAAF-JEN-013', 'unknown', None),
    ('u02_list_alias', 'OBAAF-JEN-013', 'unknown', None),
    ('e08_bindvar', 'OBAAF-JEN-013', 'unknown', None),
    ('n05_ternary', 'OBAAF-JEN-013', 'none', None),
    ('n06_tool', 'OBAAF-JEN-013', 'none', None),
    ('n07_newdate', 'OBAAF-JEN-013', 'none', None),
    ('w04_as', 'OBAAF-JEN-013', 'unknown', None),
    ('w06_nested_gstring', 'OBAAF-JEN-013', 'unknown', None),
    ('v01_plain', 'OBAAF-JEN-013', 'finding', 'medium'),
    ('v03_echo_size', 'OBAAF-JEN-013', 'unknown', None),
    ('x04_nested_dollar_nobrace', 'OBAAF-JEN-013', 'unknown', None),
    ('x07_nested_dollar_plus', 'OBAAF-JEN-013', 'unknown', None),
    ('x03_tool_interp', 'OBAAF-JEN-013', 'none', None),
    ('x05_nested_words', 'OBAAF-JEN-013', 'none', None),
    ('y04_inner_quote_upper', 'OBAAF-JEN-013', 'unknown', None),
    ('y05_inner_replace_upper', 'OBAAF-JEN-013', 'unknown', None),
    ('y08_triple', 'OBAAF-JEN-013', 'unknown', None),
]

A018 = b'// Review pipeline\rpipeline {\r  agent any\r  stages {\r    stage(\'Review\') {\r      steps {\r        withCredentials([string(credentialsId: \'gh-token\', variable: \'GH_TOKEN\')]) {\r          sh \'claude -p "review this change"\'\r        }\r      }\r    }\r  }\r}\r'

B097 = "def m0() {\n  m1()\n  m1()\n}\ndef m1() {\n  m2()\n  m2()\n}\ndef m2() {\n  m3()\n  m3()\n}\ndef m3() {\n  m4()\n  m4()\n}\ndef m4() {\n  m5()\n  m5()\n}\ndef m5() {\n  m6()\n  m6()\n}\ndef m6() {\n  m7()\n  m7()\n}\ndef m7() {\n  m8()\n  m8()\n}\ndef m8() {\n  m9()\n  m9()\n}\ndef m9() {\n  m10()\n  m10()\n}\ndef m10() {\n  m11()\n  m11()\n}\ndef m11() {\n  m12()\n  m12()\n}\ndef m12() {\n  m13()\n  m13()\n}\ndef m13() {\n  m14()\n  m14()\n}\ndef m14() {\n  sh \"curl -H Authorization:${TOKEN} https://example.com/0 && gpg --batch --import k0.asc && mvn -B deploy\"\n  sh \"curl -H Authorization:${TOKEN} https://example.com/1 && gpg --batch --import k1.asc && mvn -B deploy\"\n  sh \"curl -H Authorization:${TOKEN} https://example.com/2 && gpg --batch --import k2.asc && mvn -B deploy\"\n  sh \"curl -H Authorization:${TOKEN} https://example.com/3 && gpg --batch --import k3.asc && mvn -B deploy\"\n  sh \"curl -H Authorization:${TOKEN} https://example.com/4 && gpg --batch --import k4.asc && mvn -B deploy\"\n  sh \"curl -H Authorization:${TOKEN} https://example.com/5 && gpg --batch --import k5.asc && mvn -B deploy\"\n  sh \"curl -H Authorization:${TOKEN} https://example.com/6 && gpg --batch --import k6.asc && mvn -B deploy\"\n  sh \"curl -H Authorization:${TOKEN} https://example.com/7 && gpg --batch --import k7.asc && mvn -B deploy\"\n  sh \"curl -H Authorization:${TOKEN} https://example.com/8 && gpg --batch --import k8.asc && mvn -B deploy\"\n  sh \"curl -H Authorization:${TOKEN} https://example.com/9 && gpg --batch --import k9.asc && mvn -B deploy\"\n  sh \"curl -H Authorization:${TOKEN} https://example.com/10 && gpg --batch --import k10.asc && mvn -B deploy\"\n  sh \"curl -H Authorization:${TOKEN} https://example.com/11 && gpg --batch --import k11.asc && mvn -B deploy\"\n  sh \"curl -H Authorization:${TOKEN} https://example.com/12 && gpg --batch --import k12.asc && mvn -B deploy\"\n  sh \"curl -H Authorization:${TOKEN} https://example.com/13 && gpg --batch --import k13.asc && mvn -B deploy\"\n  sh \"curl -H Authorization:${TOKEN} https://example.com/14 && gpg --batch --import k14.asc && mvn -B deploy\"\n  sh \"curl -H Authorization:${TOKEN} https://example.com/15 && gpg --batch --import k15.asc && mvn -B deploy\"\n  sh \"curl -H Authorization:${TOKEN} https://example.com/16 && gpg --batch --import k16.asc && mvn -B deploy\"\n  sh \"curl -H Authorization:${TOKEN} https://example.com/17 && gpg --batch --import k17.asc && mvn -B deploy\"\n  sh \"curl -H Authorization:${TOKEN} https://example.com/18 && gpg --batch --import k18.asc && mvn -B deploy\"\n  sh \"curl -H Authorization:${TOKEN} https://example.com/19 && gpg --batch --import k19.asc && mvn -B deploy\"\n}\nnode {\n  withCredentials([string(credentialsId: 'gpg-signing-key', variable: 'TOKEN')]) {\n    m0()\n  }\n}\n"

R04 = "def t0 = [:]\ndef t1 = [:]\ndef t2 = [:]\ndef t3 = [:]\ndef t4 = [:]\ndef t5 = [:]\ndef t6 = [:]\ndef t7 = [:]\ndef t8 = [:]\ndef t9 = [:]\ndef t10 = [:]\ndef t11 = [:]\ndef t12 = [:]\ndef t13 = [:]\ndef t14 = [:]\ndef t15 = [:]\ndef t16 = [:]\ndef t17 = [:]\ndef t18 = [:]\ndef t19 = [:]\ndef t20 = [:]\ndef t21 = [:]\ndef t22 = [:]\ndef t23 = [:]\ndef t24 = [:]\ndef t25 = [:]\nt0['a'] = { parallel t1 }\nt0['b'] = { parallel t1 }\nt1['a'] = { parallel t2 }\nt1['b'] = { parallel t2 }\nt2['a'] = { parallel t3 }\nt2['b'] = { parallel t3 }\nt3['a'] = { parallel t4 }\nt3['b'] = { parallel t4 }\nt4['a'] = { parallel t5 }\nt4['b'] = { parallel t5 }\nt5['a'] = { parallel t6 }\nt5['b'] = { parallel t6 }\nt6['a'] = { parallel t7 }\nt6['b'] = { parallel t7 }\nt7['a'] = { parallel t8 }\nt7['b'] = { parallel t8 }\nt8['a'] = { parallel t9 }\nt8['b'] = { parallel t9 }\nt9['a'] = { parallel t10 }\nt9['b'] = { parallel t10 }\nt10['a'] = { parallel t11 }\nt10['b'] = { parallel t11 }\nt11['a'] = { parallel t12 }\nt11['b'] = { parallel t12 }\nt12['a'] = { parallel t13 }\nt12['b'] = { parallel t13 }\nt13['a'] = { parallel t14 }\nt13['b'] = { parallel t14 }\nt14['a'] = { parallel t15 }\nt14['b'] = { parallel t15 }\nt15['a'] = { parallel t16 }\nt15['b'] = { parallel t16 }\nt16['a'] = { parallel t17 }\nt16['b'] = { parallel t17 }\nt17['a'] = { parallel t18 }\nt17['b'] = { parallel t18 }\nt18['a'] = { parallel t19 }\nt18['b'] = { parallel t19 }\nt19['a'] = { parallel t20 }\nt19['b'] = { parallel t20 }\nt20['a'] = { parallel t21 }\nt20['b'] = { parallel t21 }\nt21['a'] = { parallel t22 }\nt21['b'] = { parallel t22 }\nt22['a'] = { parallel t23 }\nt22['b'] = { parallel t23 }\nt23['a'] = { parallel t24 }\nt23['b'] = { parallel t24 }\nt24['a'] = { parallel t25 }\nt24['b'] = { parallel t25 }\nnode { parallel t0 }\n"

POPENSSL = "def m0() {\n  m1()\n  m1()\n}\ndef m1() {\n  m2()\n  m2()\n}\ndef m2() {\n  m3()\n  m3()\n}\ndef m3() {\n  m4()\n  m4()\n}\ndef m4() {\n  m5()\n  m5()\n}\ndef m5() {\n  m6()\n  m6()\n}\ndef m6() {\n  m7()\n  m7()\n}\ndef m7() {\n  m8()\n  m8()\n}\ndef m8() {\n  m9()\n  m9()\n}\ndef m9() {\n  m10()\n  m10()\n}\ndef m10() {\n  m11()\n  m11()\n}\ndef m11() {\n  m12()\n  m12()\n}\ndef m12() {\n  m13()\n  m13()\n}\ndef m13() {\n  m14()\n  m14()\n}\ndef m14() {\n  sh 'openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst openssl dgst '\n}\nnode {\n  m0()\n}\n"

GHA_NOT_SIGNING = "name: ci\non: push\npermissions:\n  contents: read\njobs:\n  testflight:\n    runs-on: macos-latest\n    steps:\n      - uses: actions/checkout@08eba0b27e820071cde6df949e0beb9ba4906955 # v4\n      - run: bundle exec fastlane beta\n        env:\n          ASC_KEY_ID: ${{ secrets.ASC_KEY_ID }}\n          ASC_ISSUER_ID: ${{ secrets.ASC_ISSUER_ID }}\n          ASC_KEY_CONTENT: ${{ secrets.ASC_KEY_CONTENT }}\n  sentry:\n    runs-on: ubuntu-latest\n    steps:\n      - run: ./upload-symbols.sh\n        env:\n          SENTRY_UPLOAD_KEY: ${{ secrets.SENTRY_UPLOAD_KEY }}\n          GPG_FINGERPRINT: ${{ secrets.GPG_FINGERPRINT_PUBLIC }}\n  verify:\n    runs-on: ubuntu-latest\n    steps:\n      - run: |\n          gpg --verify SHA256SUMS.asc SHA256SUMS\n          openssl dgst -sha256 -verify pub.pem -signature app.sig app.bin\n          security import \"$RUNNER_TEMP/profile.mobileprovision\" -k build.keychain\n"


def analyze(text, name: str = "Jenkinsfile"):
    return jenkins.analyze(name, text.encode() if isinstance(text, str) else text, load(), None)


def outcome(result, rule: str) -> tuple:
    found = [f for f in result.findings if f.rule == rule]
    if found:
        order = {"low": 0, "medium": 1, "high": 2}
        return "finding", max((f.severity for f in found), key=order.get)
    status = next(row["status"] for row in jenkins.coverage(result, result.findings) if row["rule"] == rule)
    return ("unknown" if status == "unknown" else "none"), None


class AttackCasesTest(unittest.TestCase):
    def test_each_case(self):
        for cid, rule, kind, severity in EXPECT:
            with self.subTest(cid):
                result = analyze(CASES[cid])
                self.assertIsNone(result.error, cid)
                got_kind, got_severity = outcome(result, rule)
                self.assertEqual(got_kind, kind, cid)
                if severity is not None:
                    self.assertEqual(got_severity, severity, cid)

    def test_lone_cr_line_ends_are_line_ends(self):
        # A018: with lone-CR line ends a `//` comment on the first line hid the whole pipeline.
        self.assertEqual(outcome(analyze(A018), "OBAAF-JEN-001"), ("finding", "high"))

    def test_many_calls_of_a_method_stay_fast(self):
        # B097: 15 methods each calling the next twice; 7.5 seconds before the slice. Each step's call is
        # classified once, however many times the method holding it is expanded.
        from obaaf.checker.jenkins import rules as rules_mod
        calls = []
        original = rules_mod.JenkinsRules._ai

        def counted(engine, info):
            calls.append(info)
            return original(engine, info)

        start = time.monotonic()
        with mock.patch.object(rules_mod.JenkinsRules, "_ai", counted):
            result = analyze(B097)
        self.assertLess(time.monotonic() - start, 10.0)
        self.assertLess(len(calls), 100)
        self.assertTrue(any(f.rule == "OBAAF-JEN-013" for f in result.findings))

    def test_a_map_of_closures_that_doubles_per_level_stays_bounded(self):
        # From the first review: `t{i}['a'] = { parallel t{i+1} }` 26 levels deep did not finish in 100 s.
        start = time.monotonic()
        result = analyze(R04)
        self.assertLess(time.monotonic() - start, 10.0)
        self.assertIsNone(result.error)
        self.assertEqual(outcome(result, "OBAAF-JEN-001")[0], "unknown")

    def test_the_signing_scan_runs_once_per_call(self):
        # From the first review: a long `openssl dgst` line in B097's tree of methods took 66 s.
        from obaaf.checker.jenkins import rules as rules_mod
        calls = []
        original = rules_mod.JenkinsRules.script_text

        def counted(engine, info):
            calls.append(info)
            return original(engine, info)

        with mock.patch.object(rules_mod.JenkinsRules, "script_text", counted):
            result = analyze(POPENSSL)
        self.assertIsNone(result.error)
        self.assertLess(len(calls), 200)

    def test_app_store_and_upload_keys_are_not_signing_material_in_workflows(self):
        # From the first review: ASC_KEY_ID, SENTRY_UPLOAD_KEY, GPG_FINGERPRINT and importing a provisioning
        # profile were reported by OBAAF-GHA-018, which shares the signing lists.
        with TempDir() as tmp:
            wf = tmp / "repo" / ".github" / "workflows"
            wf.mkdir(parents=True)
            (wf / "ci.yml").write_text(GHA_NOT_SIGNING)
            code, out, err = run_cli("check", str(tmp / "repo"), "--format", "json", "--fail-on", "never")
            report = json.loads(out)
            self.assertEqual([f for f in report["findings"] if f["rule"] == "OBAAF-GHA-018"], [])

    def test_a_signer_that_only_asks_a_kms_is_not_signing_material(self):
        text = CASES["B054"].replace("artifact-signer-key", "release-signer")
        self.assertEqual(outcome(analyze(text), "OBAAF-JEN-014")[0], "none")

    def test_a_binding_without_named_variables_makes_interpolation_unknown(self):
        text = CASES["B028"].replace("env.AWS_SECRET_ACCESS_KEY", "params.TARGET").replace("withAWS",
                                                                                            "withKubeConfig")
        self.assertEqual(outcome(analyze(text), "OBAAF-JEN-013")[0], "unknown")


JENKINSFILE = """pipeline {
  agent any
  stages {
    stage('Fix') {
      steps {
        withCredentials([string(credentialsId: 'model-key', variable: 'MODEL_KEY')]) {
          sh 'claude -p "fix the build"'
        }
      }
    }
  }
}
"""


def check(root: Path, *extra: str) -> dict:
    code, out, err = run_cli("check", str(root), "--platform", "jenkins", "--format", "json", "--fail-on", "never",
                             *extra)
    return json.loads(out) if out.strip() else {"exit": code, "stderr": err, "files": [], "notes": []}


class DiscoveryTest(unittest.TestCase):
    def _repo(self, tmp: Path, files: dict, commit: bool = True) -> Path:
        repo = init_repo(tmp / "repo")
        for rel, text in files.items():
            path = repo / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)
        if commit:
            git(repo, "add", "-A")
            git(repo, "commit", "-q", "-m", "files")
        return repo

    def test_tracked_jenkinsfiles_in_any_folder_and_depth_are_read(self):
        # A001, A002 (A085, A086 of 2d.2h): folders the walk skips by name, and depth beyond six.
        with TempDir() as tmp:
            repo = self._repo(tmp, {"build/Jenkinsfile": JENKINSFILE, "vendor/ci/Jenkinsfile": JENKINSFILE,
                                    "a/b/c/d/e/f/g/Jenkinsfile": JENKINSFILE})
            files = set(check(repo)["files"])
            self.assertEqual(files, {"build/Jenkinsfile", "vendor/ci/Jenkinsfile", "a/b/c/d/e/f/g/Jenkinsfile"})

    def test_files_not_committed_yet_are_read(self):
        with TempDir() as tmp:
            repo = self._repo(tmp, {"build/Jenkinsfile": JENKINSFILE}, commit=False)
            self.assertEqual(check(repo)["files"], ["build/Jenkinsfile"])

    def test_more_names(self):
        # A008: Jenkinsfile2, JenkinsfileRelease, release-jenkinsfile.
        with TempDir() as tmp:
            repo = self._repo(tmp, {"Jenkinsfile2": JENKINSFILE, "JenkinsfileRelease": JENKINSFILE,
                                    "release-jenkinsfile": JENKINSFILE, "release_jenkinsfile": JENKINSFILE})
            self.assertEqual(len(check(repo)["files"]), 4)

    def test_a_link_inside_the_repository_is_read_by_its_own_path(self):
        # A003 (A088 of 2d.2h).
        with TempDir() as tmp:
            repo = self._repo(tmp, {"ci/pipeline.groovy": JENKINSFILE})
            os.symlink("ci/pipeline.groovy", repo / "Jenkinsfile")
            report = check(repo)
            self.assertEqual(report["files"], ["Jenkinsfile"])
            self.assertTrue(any(f["rule"] == "OBAAF-JEN-001" and f["path"] == "Jenkinsfile"
                                for f in report["findings"]))

    def test_a_link_out_of_the_repository_is_an_error(self):
        with TempDir() as tmp:
            outside = tmp / "outside.groovy"
            outside.write_text(JENKINSFILE)
            repo = self._repo(tmp, {"Jenkinsfile": JENKINSFILE})
            os.symlink(str(outside), repo / "Jenkinsfile.release")
            code, out, err = run_cli("check", str(repo), "--platform", "jenkins", "--format", "json")
            report = json.loads(out)
            self.assertEqual(code, 1)
            self.assertTrue(any(e.startswith("Jenkinsfile.release: not read: it is a link") for e in report["errors"]))

    def test_what_is_left_out_is_said(self):
        # A009, A010, A012: refused suffixes, `**/` matching no folder, a glob matching nothing, exclude.
        with TempDir() as tmp:
            repo = self._repo(tmp, {
                "Jenkinsfile": JENKINSFILE, "Jenkinsfile.yml": JENKINSFILE, "ci/release.groovy": JENKINSFILE,
                "testing/Jenkinsfile": JENKINSFILE,
                ".github/obaaf.yml": "jenkins:\n  files: ['ci/**/*.groovy', 'nothing/*.groovy']\n"
                                     "  exclude: ['testing/*']\n"})
            report = check(repo)
            self.assertEqual(set(report["files"]), {"Jenkinsfile", "ci/release.groovy"})
            notes = " ".join(report["notes"])
            self.assertIn("Not read as Jenkinsfiles because of their suffix: Jenkinsfile.yml", notes)
            self.assertIn("jenkins.files pattern 'nothing/*.groovy' matched no file", notes)
            self.assertIn("Left out by jenkins.exclude: testing/Jenkinsfile", notes)

    def test_outside_git_the_folders_not_entered_are_named(self):
        with TempDir() as tmp:
            root = tmp / "plain"
            (root / "build").mkdir(parents=True)
            (root / "Jenkinsfile").write_text(JENKINSFILE)
            (root / "build" / "Jenkinsfile").write_text(JENKINSFILE)
            (root / ".git").mkdir()     # looks like a repository root, but git has no list: the walk is used
            report = check(root)
            self.assertEqual(report["files"], ["Jenkinsfile"])
            self.assertIn("these folders were not entered: build", " ".join(report["notes"]))

    def test_a_named_path_in_a_skipped_folder_is_read_outside_git(self):
        # A011.
        with TempDir() as tmp:
            root = tmp / "plain"
            (root / "build").mkdir(parents=True)
            (root / ".git").mkdir()
            (root / "build" / "release.groovy").write_text(JENKINSFILE)
            (root / ".github").mkdir()
            (root / ".github" / "obaaf.yml").write_text("jenkins:\n  files: ['build/release.groovy']\n")
            self.assertIn("build/release.groovy", check(root)["files"])

    def test_nothing_outside_the_repository_is_read(self):
        # From the first review: `jenkins.files` named `../outside/x.groovy`, an absolute path, or a file under a
        # folder link out of the repository, and each was read.
        with TempDir() as tmp:
            (tmp / "outside").mkdir()
            (tmp / "outside" / "secret.groovy").write_text(JENKINSFILE)
            (tmp / "outdir").mkdir()
            (tmp / "outdir" / "Jenkinsfile").write_text(JENKINSFILE)
            repo = self._repo(tmp, {"Jenkinsfile": JENKINSFILE, ".github/obaaf.yml":
                                    "jenkins:\n  files: ['../outside/secret.groovy', '%s', 'linked/Jenkinsfile']\n"
                                    % (tmp / "outside" / "secret.groovy")})
            os.symlink("../outdir", repo / "linked")
            code, out, err = run_cli("check", str(repo), "--platform", "jenkins", "--format", "json")
            report = json.loads(out)
            self.assertEqual(report["files"], ["Jenkinsfile"])
            self.assertEqual(code, 1)
            self.assertEqual(len([e for e in report["errors"] if "not read" in e]), 3)

    def test_codeowners_must_cover_a_jenkinsfile_in_a_skipped_folder(self):
        # A025.
        with TempDir() as tmp:
            repo = self._repo(tmp, {"Jenkinsfile": JENKINSFILE, "build/Jenkinsfile": JENKINSFILE,
                                    ".github/CODEOWNERS": "/Jenkinsfile @org/ci\n/.github/ @org/ci\n"})
            code, out, err = run_cli("check", str(repo), "--format", "json", "--fail-on", "never")
            report = json.loads(out)
            messages = " ".join(f["message"] for f in report["findings"] if f["rule"] == "OBAAF-REPO-001")
            self.assertIn("build/Jenkinsfile", messages)


if __name__ == "__main__":
    unittest.main()
