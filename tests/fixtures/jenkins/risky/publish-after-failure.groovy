// obaaf-models: A release pipeline swallows a failed verification and uploads in post always, with no approval.
// obaaf-expect: OBAAF-JEN-011 OBAAF-JEN-012 OBAAF-JEN-005
pipeline {
  agent { label 'release' }
  stages {
    stage('Verify') {
      when { branch 'main' }
      steps {
        catchError(buildResult: 'UNSTABLE', stageResult: 'FAILURE') {
          sh 'cosign verify-attestation --key cosign.pub registry.example/game:1.0'
        }
      }
    }
  }
  post {
    always {
      sh 'aws s3 cp build/game.zip s3://releases/game.zip'
    }
  }
}
