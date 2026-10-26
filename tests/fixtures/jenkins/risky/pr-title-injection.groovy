// obaaf-models: Nx-style injection: a pull request title is interpolated by Groovy into a shell script.
// obaaf-expect: OBAAF-JEN-009
pipeline {
  agent { label 'linux' }
  stages {
    stage('Announce') {
      when { changeRequest() }
      steps {
        sh "echo Building change: ${env.CHANGE_TITLE}"
      }
    }
  }
}
