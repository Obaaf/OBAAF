// OBAAF release lane on Jenkins, build half (G3.1 to G3.4, G4.1, G4.2; FR4). See docs/jenkins.md.
//
// Use this as the Jenkinsfile of a multibranch project that discovers tags only (no branches, no
// pull requests), separate from the project that builds branches and pull requests. Name that
// project in release.jenkins_project: the publish job ships only artifacts of a build in it, so a
// branch whose name looks like a tag cannot stand in for one. For a tag, this builds the release
// with no credentials at all, keeps the artifacts, and starts the publish job
// (obaaf-release-publish.Jenkinsfile), which signs, verifies, waits for a person to approve and
// uploads.
//
// Jenkins discovers tags but does not build them on its own: add the "Build tags" strategy (Basic
// Branch Build Strategies plugin), or start each tag build by hand (that person then cannot approve
// the release). Signing and upload credentials must never be visible to this project: credentials
// scoped to a multibranch project reach every build it runs. They belong to the publish job.
//
// Before use: set OBAAF_REVISION, edit the marked lines, and protect tags matching v* in your SCM so
// only maintainers can create them.
pipeline {
  agent none
  options {
    disableConcurrentBuilds()
    skipDefaultCheckout()
    timeout(time: 2, unit: 'HOURS')
    // EDIT: the publish job's full name, with a leading slash. It may copy this build's artifacts.
    copyArtifactPermission('/releases/obaaf-release-publish')
  }
  environment {
    OBAAF_URL = 'https://github.com/Obaaf/OBAAF.git'
    OBAAF_REVISION = '0000000000000000000000000000000000000000'   // EDIT: the OBAAF release commit you reviewed
  }
  stages {
    stage('Build') {
      when {
        beforeAgent true
        buildingTag()
      }
      // EDIT: Tier B, persistent hosts that run release builds only. A label does not stop other jobs
      // from using these hosts: restrict them to this project on the controller (docs/jenkins.md). For
      // Tier A, build in a fresh pod per build (agent { kubernetes { ... } }) and pass --tier A in
      // the publish job.
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
        // The publish job finds this build from its start cause, so nothing is passed to it.
        build job: '/releases/obaaf-release-publish', wait: false   // EDIT: the same full name as above
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
