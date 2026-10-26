// obaaf-models: A release build loads the code-signing certificate into the job, then uploads, with no verification or approval.
// obaaf-expect: OBAAF-JEN-014 OBAAF-JEN-012 OBAAF-JEN-005
pipeline {
  agent { label 'mac' }
  stages {
    stage('Sign and upload') {
      when { buildingTag() }
      steps {
        withCredentials([file(credentialsId: 'ios-signing-p12', variable: 'SIGNING_P12')]) {
          sh 'security import "$SIGNING_P12" -k build.keychain'
          sh 'fastlane upload_to_testflight'
        }
      }
    }
  }
}
