// obaaf-models: Docker-in-Docker for pull request builds: a privileged pod with the host's Docker socket, images by tag.
// obaaf-expect: OBAAF-JEN-006 OBAAF-JEN-008
pipeline {
  agent {
    kubernetes {
      yaml '''
apiVersion: v1
kind: Pod
spec:
  containers:
  - name: docker
    image: docker:27-dind
    securityContext:
      privileged: true
    volumeMounts:
    - name: sock
      mountPath: /var/run/docker.sock
  volumes:
  - name: sock
    hostPath:
      path: /var/run/docker.sock
'''
    }
  }
  stages {
    stage('Image') {
      steps {
        container('docker') {
          sh 'docker build -t app .'
        }
      }
    }
  }
}
