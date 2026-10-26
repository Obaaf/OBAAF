// obaaf-models: Pull request builds run on the built-in node, where build code can read the controller's secrets.
// obaaf-expect: OBAAF-JEN-002
pipeline {
  agent { label 'built-in' }
  stages {
    stage('Build') {
      steps {
        sh './gradlew build'
      }
    }
  }
}
