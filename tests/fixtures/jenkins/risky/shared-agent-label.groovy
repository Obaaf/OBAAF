// obaaf-models: One persistent agent label runs pull request builds and the deployment that holds credentials.
// obaaf-expect: OBAAF-JEN-002
pipeline {
  agent none
  stages {
    stage('Test') {
      agent { label 'build-pool' }
      steps { sh 'make test' }
    }
    stage('Deploy') {
      when { branch 'main' }
      agent { label 'build-pool' }
      steps {
        withCredentials([string(credentialsId: 'deploy-token', variable: 'TOKEN')]) {
          sh './deploy.sh'
        }
      }
    }
  }
}
