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
 "C094": "pipeline {\n  agent any\n  stages {\n    stage('Review') { steps { sh 'claude -p \"review\"' } }\n    stage('Deploy') {\n      when { branch 'main' }\n      steps {\n        withCredentials([string(credentialsId: 'k', variable: 'K')]) {\n          sh 'curl -X POST https://deploy.example'\n        }\n      }\n    }\n  }\n}\n"
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
]

A018 = b'// Review pipeline\rpipeline {\r  agent any\r  stages {\r    stage(\'Review\') {\r      steps {\r        withCredentials([string(credentialsId: \'gh-token\', variable: \'GH_TOKEN\')]) {\r          sh \'claude -p "review this change"\'\r        }\r      }\r    }\r  }\r}\r'

B097 = "def m0() {\n  m1()\n  m1()\n}\ndef m1() {\n  m2()\n  m2()\n}\ndef m2() {\n  m3()\n  m3()\n}\ndef m3() {\n  m4()\n  m4()\n}\ndef m4() {\n  m5()\n  m5()\n}\ndef m5() {\n  m6()\n  m6()\n}\ndef m6() {\n  m7()\n  m7()\n}\ndef m7() {\n  m8()\n  m8()\n}\ndef m8() {\n  m9()\n  m9()\n}\ndef m9() {\n  m10()\n  m10()\n}\ndef m10() {\n  m11()\n  m11()\n}\ndef m11() {\n  m12()\n  m12()\n}\ndef m12() {\n  m13()\n  m13()\n}\ndef m13() {\n  m14()\n  m14()\n}\ndef m14() {\n  sh \"curl -H Authorization:${TOKEN} https://example.com/0 && gpg --batch --import k0.asc && mvn -B deploy\"\n  sh \"curl -H Authorization:${TOKEN} https://example.com/1 && gpg --batch --import k1.asc && mvn -B deploy\"\n  sh \"curl -H Authorization:${TOKEN} https://example.com/2 && gpg --batch --import k2.asc && mvn -B deploy\"\n  sh \"curl -H Authorization:${TOKEN} https://example.com/3 && gpg --batch --import k3.asc && mvn -B deploy\"\n  sh \"curl -H Authorization:${TOKEN} https://example.com/4 && gpg --batch --import k4.asc && mvn -B deploy\"\n  sh \"curl -H Authorization:${TOKEN} https://example.com/5 && gpg --batch --import k5.asc && mvn -B deploy\"\n  sh \"curl -H Authorization:${TOKEN} https://example.com/6 && gpg --batch --import k6.asc && mvn -B deploy\"\n  sh \"curl -H Authorization:${TOKEN} https://example.com/7 && gpg --batch --import k7.asc && mvn -B deploy\"\n  sh \"curl -H Authorization:${TOKEN} https://example.com/8 && gpg --batch --import k8.asc && mvn -B deploy\"\n  sh \"curl -H Authorization:${TOKEN} https://example.com/9 && gpg --batch --import k9.asc && mvn -B deploy\"\n  sh \"curl -H Authorization:${TOKEN} https://example.com/10 && gpg --batch --import k10.asc && mvn -B deploy\"\n  sh \"curl -H Authorization:${TOKEN} https://example.com/11 && gpg --batch --import k11.asc && mvn -B deploy\"\n  sh \"curl -H Authorization:${TOKEN} https://example.com/12 && gpg --batch --import k12.asc && mvn -B deploy\"\n  sh \"curl -H Authorization:${TOKEN} https://example.com/13 && gpg --batch --import k13.asc && mvn -B deploy\"\n  sh \"curl -H Authorization:${TOKEN} https://example.com/14 && gpg --batch --import k14.asc && mvn -B deploy\"\n  sh \"curl -H Authorization:${TOKEN} https://example.com/15 && gpg --batch --import k15.asc && mvn -B deploy\"\n  sh \"curl -H Authorization:${TOKEN} https://example.com/16 && gpg --batch --import k16.asc && mvn -B deploy\"\n  sh \"curl -H Authorization:${TOKEN} https://example.com/17 && gpg --batch --import k17.asc && mvn -B deploy\"\n  sh \"curl -H Authorization:${TOKEN} https://example.com/18 && gpg --batch --import k18.asc && mvn -B deploy\"\n  sh \"curl -H Authorization:${TOKEN} https://example.com/19 && gpg --batch --import k19.asc && mvn -B deploy\"\n}\nnode {\n  withCredentials([string(credentialsId: 'gpg-signing-key', variable: 'TOKEN')]) {\n    m0()\n  }\n}\n"


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
