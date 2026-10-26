// obaaf-models: A trusted Jenkinsfile loads deployment Groovy from the workspace, which a pull request controls, with credentials bound.
// obaaf-expect: OBAAF-JEN-004 OBAAF-JEN-001
node('linux') {
  checkout scm
  withCredentials([usernamePassword(credentialsId: 'deploy', usernameVariable: 'DEPLOY_USER',
                                    passwordVariable: 'DEPLOY_PASSWORD')]) {
    def deploy = load 'ci/deploy.groovy'
    deploy.run()
    sh './ci/smoke-test.sh'
  }
}
