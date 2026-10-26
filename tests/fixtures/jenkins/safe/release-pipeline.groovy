// A pipeline that follows the advisory rules: change requests get no credentials, the release
// stage is protected, verified and approved by a named group, and every reference is pinned.
@Library('build-tools@0123456789abcdef0123456789abcdef01234567') _
pipeline {
  agent none
  stages {
    stage('Test') {
      agent {
        kubernetes {
          yaml '''
apiVersion: v1
kind: Pod
spec:
  automountServiceAccountToken: false
  containers:
  - name: build
    image: registry.example/build@sha256:0000000000000000000000000000000000000000000000000000000000000000
'''
        }
      }
      steps {
        container('build') {
          sh 'make test'
        }
      }
    }
    stage('Approve') {
      when { branch 'main' }
      steps {
        input message: 'Publish this build?', submitter: 'release-managers'
      }
    }
    stage('Release') {
      when { branch 'main' }
      agent { label 'release-signing' }
      steps {
        sh 'obaaf verify release --policy release-policy.yml --artifacts out/game.zip'
        withCredentials([string(credentialsId: 'store-upload-token', variable: 'UPLOAD_TOKEN')]) {
          sh 'butler push out/ studio/game:windows'
        }
      }
    }
  }
}
