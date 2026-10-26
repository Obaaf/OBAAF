// obaaf-models: A promotion job publishes whatever the last successful build produced, without checking digests.
// obaaf-expect: OBAAF-JEN-010 OBAAF-JEN-012 OBAAF-JEN-005
pipeline {
  agent { label 'release' }
  stages {
    stage('Promote') {
      when { branch 'main' }
      steps {
        copyArtifacts(projectName: 'game-build', selector: lastSuccessful())
        sh 'butler push build/ studio/game:windows'
      }
    }
  }
}
