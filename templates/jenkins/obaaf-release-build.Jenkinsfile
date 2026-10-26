// OBAAF release lane on Jenkins, build half (G3.1 to G3.4, G4.1, G4.2; FR4). See docs/jenkins.md.
//
// Use this as the Jenkinsfile of the multibranch project that builds your repository, with tag
// discovery on. For a protected tag it builds the release with no credentials at all, keeps the
// artifacts, and starts the publish job (obaaf-release-publish.Jenkinsfile), which signs, verifies,
// waits for a person to approve and uploads. Branches and pull requests skip every stage.
//
// Signing and upload credentials must never be visible to this project: credentials scoped to a
// multibranch project reach every branch and pull request it builds. They belong to the publish job.
//
// Before use: set OBAAF_REVISION, edit the marked lines, protect tags matching v* in your SCM so only
// maintainers can create them, and give the build an agent label that runs release builds only.
pipeline {
  agent none
  options {
    disableConcurrentBuilds()
    skipDefaultCheckout()
    timeout(time: 2, unit: 'HOURS')
    // The publish job copies the artifacts of exactly this build.
    copyArtifactPermission('obaaf-release-publish')
  }
  environment {
    OBAAF_URL = 'https://github.com/Obaaf/OBAAF.git'
    OBAAF_REVISION = '0000000000000000000000000000000000000000'   // EDIT: the OBAAF release commit you reviewed
  }
  stages {
    stage('Build') {
      when { buildingTag() }
      // Tier B: persistent hosts that run release builds only. For Tier A, build in a fresh pod per
      // build (agent { kubernetes { ... } }) and pass --tier A in the publish job.
      agent { label 'obaaf-release-build' }
      steps {
        checkout scm
        installObaaf()
        sh '''
          set -eu
          export PATH="$WORKSPACE/.obaaf-venv/bin:$PATH"
          obaaf manifest check --manifest obaaf-manifest.json
        '''
        // EDIT: your build. It must write the files to ship into dist/ and use no credentials.
        // Regenerate derived data here rather than reading a cache other builds can write (G4.2).
        sh './scripts/build.sh dist'
        archiveArtifacts artifacts: 'dist/**', fingerprint: true
      }
    }
    stage('Hand over to the publish job') {
      when { buildingTag() }
      steps {
        build job: 'obaaf-release-publish', wait: false, parameters: [
          string(name: 'RELEASE_JOB', value: env.JOB_NAME),
          string(name: 'RELEASE_BUILD', value: env.BUILD_NUMBER),
          string(name: 'RELEASE_BUILD_URL', value: env.BUILD_URL),
          string(name: 'RELEASE_TAG', value: env.TAG_NAME)
        ]
      }
    }
  }
}

// Installs OBAAF from the commit you reviewed, with every dependency pinned by hash (D-011).
def installObaaf() {
  sh '''
    set -eu
    if [ "$OBAAF_REVISION" = 0000000000000000000000000000000000000000 ]; then
      echo "error: set OBAAF_REVISION to the OBAAF release commit you reviewed" >&2; exit 2
    fi
    rm -rf .obaaf-src .obaaf-venv
    git init -q .obaaf-src
    git -C .obaaf-src fetch -q --depth 1 "$OBAAF_URL" "$OBAAF_REVISION"
    git -C .obaaf-src checkout -q --detach FETCH_HEAD
    python3 -m venv .obaaf-venv
    .obaaf-venv/bin/python -m pip install --quiet --disable-pip-version-check --only-binary=:all: \
      --require-hashes --requirement .obaaf-src/actions/setup-obaaf/requirements.txt
    .obaaf-venv/bin/python -m pip install --quiet --disable-pip-version-check --no-build-isolation \
      --no-deps ./.obaaf-src
    .obaaf-venv/bin/python -m pip check
  '''
}
