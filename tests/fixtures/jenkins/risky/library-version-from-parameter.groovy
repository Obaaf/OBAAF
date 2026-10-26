// obaaf-models: The shared library version is taken from a build parameter, so whoever starts the build chooses the pipeline code.
// obaaf-expect: OBAAF-JEN-004
@Library("build-tools@${params.LIB_VERSION}") _
pipeline {
  agent { label 'linux' }
  parameters { string(name: 'LIB_VERSION', defaultValue: 'main') }
  stages {
    stage('Build') {
      steps { sh 'make' }
    }
  }
}
