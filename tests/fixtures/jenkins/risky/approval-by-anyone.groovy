// obaaf-models: A release waits for an input step that any user who can build the job may approve.
// obaaf-expect: OBAAF-JEN-005
pipeline {
  agent { label 'release' }
  stages {
    stage('Approve') {
      when { branch 'main' }
      steps {
        input message: 'Release?'
      }
    }
    stage('Release') {
      when { branch 'main' }
      steps {
        sh 'obaaf verify release --policy release-policy.yml --artifacts out/game.zip'
        sh 'gh release upload v1.0 out/game.zip'
      }
    }
  }
}
