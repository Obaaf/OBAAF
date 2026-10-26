// OBAAF audit job for Jenkinsfiles (advisory; see docs/jenkins.md in the OBAAF repository).
//
// Configure this as a Pipeline job ("Pipeline script from SCM") whose definition comes from a
// repository your platform or security team protects, never from the repository being audited.
// The audit fetches the target at a fixed revision and reads it as data: no file from the target
// runs, and the target's own obaaf.yml (with its ignore entries) is not used. Put the audit's
// configuration in obaaf-audit.yml next to this file in the protected repository, if you need one.
//
// Before use, set OBAAF_REVISION to the full commit SHA of the OBAAF release you reviewed, and give
// the job an agent labelled obaaf-audit that holds no other credentials. For a private target,
// wrap the target fetch in withCredentials with a read-only token for that repository alone.
pipeline {
  agent { label 'obaaf-audit' }
  options {
    disableConcurrentBuilds()
    timeout(time: 30, unit: 'MINUTES')
  }
  parameters {
    string(name: 'TARGET_URL', description: 'Clone URL of the repository to audit')
    string(name: 'TARGET_REVISION', description: 'Full 40-character commit SHA to audit')
  }
  environment {
    OBAAF_URL = 'https://github.com/Obaaf/OBAAF.git'
    OBAAF_REVISION = '0000000000000000000000000000000000000000'
  }
  stages {
    stage('Fetch') {
      steps {
        sh '''
          set -eu
          for rev in "$TARGET_REVISION" "$OBAAF_REVISION"; do
            case "$rev" in
              *[!0-9a-f]*|"") echo "error: revisions must be full commit SHAs" >&2; exit 2 ;;
            esac
            [ "${#rev}" -eq 40 ] || { echo "error: revisions must be full commit SHAs" >&2; exit 2; }
          done
          if [ "$OBAAF_REVISION" = 0000000000000000000000000000000000000000 ]; then
            echo "error: set OBAAF_REVISION to the OBAAF release commit you reviewed" >&2; exit 2
          fi
          rm -rf target obaaf reports
          git init -q target
          git -C target fetch -q --depth 1 "$TARGET_URL" "$TARGET_REVISION"
          git -C target checkout -q --detach FETCH_HEAD
          git init -q obaaf
          git -C obaaf fetch -q --depth 1 "$OBAAF_URL" "$OBAAF_REVISION"
          git -C obaaf checkout -q --detach FETCH_HEAD
        '''
      }
    }
    stage('Install OBAAF') {
      steps {
        sh '''
          set -eu
          python3 -m venv .obaaf-venv
          .obaaf-venv/bin/python -m pip install --quiet --disable-pip-version-check --only-binary=:all: \
            --require-hashes --requirement obaaf/actions/setup-obaaf/requirements.txt
          .obaaf-venv/bin/python -m pip install --quiet --disable-pip-version-check --no-build-isolation \
            --no-deps ./obaaf
          .obaaf-venv/bin/python -m pip check
          .obaaf-venv/bin/obaaf --version
        '''
      }
    }
    stage('Audit') {
      steps {
        sh '''
          set -eu
          mkdir -p reports
          if [ -f obaaf-audit.yml ]; then cp obaaf-audit.yml reports/config.yml; else echo '{}' > reports/config.yml; fi
          echo "target $TARGET_URL at $TARGET_REVISION" > reports/input.txt
          for format in json sarif; do
            .obaaf-venv/bin/obaaf check target --platform jenkins --config reports/config.yml \
              --format "$format" --output "reports/obaaf.$format" --fail-on never
          done
          .obaaf-venv/bin/obaaf check target --platform jenkins --config reports/config.yml \
            --output reports/obaaf.txt
        '''
      }
    }
  }
  post {
    always {
      archiveArtifacts artifacts: 'reports/*', allowEmptyArchive: true, fingerprint: true
    }
  }
}
