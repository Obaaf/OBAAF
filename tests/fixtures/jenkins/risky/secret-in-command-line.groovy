// obaaf-models: A deploy step interpolates a password with Groovy, so it appears in the process list.
// obaaf-expect: OBAAF-JEN-013
pipeline {
  agent { label 'linux' }
  stages {
    stage('Deploy') {
      when { branch 'main' }
      steps {
        withCredentials([usernamePassword(credentialsId: 'web', usernameVariable: 'WEB_USER',
                                          passwordVariable: 'WEB_PASSWORD')]) {
          sh "curl -u ${WEB_USER}:${WEB_PASSWORD} -X POST https://deploy.example/hook"
        }
      }
    }
  }
}
