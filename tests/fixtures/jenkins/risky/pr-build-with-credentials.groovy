// obaaf-models: A multibranch job binds a registry token around the test stage that runs for pull requests, so a pull request's tests can read it.
// obaaf-expect: OBAAF-JEN-001
pipeline {
  agent { label 'linux' }
  stages {
    stage('Test') {
      when { changeRequest() }
      steps {
        withCredentials([string(credentialsId: 'registry-token', variable: 'REGISTRY_TOKEN')]) {
          sh 'make test'
        }
      }
    }
  }
}
