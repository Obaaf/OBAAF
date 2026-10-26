// OBAAF release lane on Jenkins, publish half (G5.1, G6.1, G6.2, G7.1, G7.2, G8.3; FR5, FR6, FR11).
// See docs/jenkins.md.
//
// Configure this as its own Pipeline job named obaaf-release-publish (not a multibranch project),
// with "Pipeline script from SCM" reading this file from your protected default branch. The build
// job (obaaf-release-build.Jenkinsfile) starts it for each release tag. It:
//   resolve   checks out the default branch, resolves the tag to a commit through your SCM, and
//             copies the artifacts of exactly that build
//   sign      writes SLSA provenance and the OBAAF build record, and signs both with a key held in a
//             key service, so no step can read the private key (FR11)
//   verify    checks the release before anyone is asked to approve it
//   approve   waits for a named release manager
//   publish   checks everything again, now including who approved, then uploads
//
// Keep this job's credentials in a folder that holds only this job, run it on agents that run
// nothing else, and do not grant Run/Replay on it: Jenkins enforces the boundary, and the checks
// below only hold while this file is the one that runs. Edit the marked lines, and keep the public
// key and the policy in .obaaf/ on the default branch.
pipeline {
  agent { label 'obaaf-release' }
  options {
    disableConcurrentBuilds()
    skipDefaultCheckout()
    timeout(time: 3, unit: 'DAYS')
  }
  parameters {
    string(name: 'RELEASE_JOB', description: 'Full name of the build job that built the release')
    string(name: 'RELEASE_BUILD', description: 'Its build number')
    string(name: 'RELEASE_BUILD_URL', description: 'Its build URL on this controller')
    string(name: 'RELEASE_TAG', description: 'The release tag')
  }
  environment {
    OBAAF_URL = 'https://github.com/Obaaf/OBAAF.git'
    OBAAF_REVISION = '0000000000000000000000000000000000000000'   // EDIT: the OBAAF release commit you reviewed
    SIGNING_KEY = 'alias/obaaf-release'                            // EDIT: the key service key that signs records
    AWS_REGION = 'us-east-1'                                       // EDIT
  }
  stages {
    stage('Resolve') {
      when { not { changeRequest() } }
      steps {
        checkout scm
        sh '''
          set -eu
          if ! printf '%s' "$RELEASE_TAG" | grep -Eq '^v[0-9A-Za-z._-]+$'; then
            echo "error: unexpected release tag" >&2; exit 2
          fi
          case "$RELEASE_BUILD_URL" in
            "$JENKINS_URL"*) ;;
            *) echo "error: the release build is not on this controller" >&2; exit 2 ;;
          esac
          if [ "$(git rev-parse --is-shallow-repository)" = true ]; then git fetch -q --unshallow --no-tags origin; fi
          git fetch -q --force --no-tags origin "+refs/heads/main:refs/remotes/origin/main" \
            "+refs/tags/$RELEASE_TAG:refs/tags/$RELEASE_TAG"
          git rev-parse "refs/tags/$RELEASE_TAG^{commit}" > release-sha.txt
          git show "$(cat release-sha.txt):obaaf-manifest.json" > release-manifest.json
          rm -rf dist attestations && mkdir attestations
        '''
        copyArtifacts(projectName: params.RELEASE_JOB, selector: specific(params.RELEASE_BUILD), filter: 'dist/**',
                      fingerprintArtifacts: true)
        installObaaf()
      }
    }
    stage('Sign') {
      when { not { changeRequest() } }
      steps {
        // EDIT: a credential that can only sign with SIGNING_KEY (kms:Sign on that key, nothing else).
        // On EKS, an IAM role for this agent's service account avoids a stored credential.
        withAWS(credentials: 'obaaf-release-signer', region: env.AWS_REGION) {
          sh '''
            set -eu
            export PATH="$WORKSPACE/.obaaf-venv/bin:$PATH"
            rev="$(cat release-sha.txt)"
            origin="$(git remote get-url origin)"
            obaaf attest slsa --artifact dist --builder-id "${JENKINS_URL}job/obaaf-release-publish/" \
              --repository-uri "$origin" --source-revision "$rev" --source-ref "refs/tags/$RELEASE_TAG" \
              --invocation-id "$BUILD_URL" --out attestations/slsa.json --statement-out attestations/slsa.statement.json
            # EDIT: --tier B for persistent release-only build hosts, A for a fresh pod per build. If your
            # assets live outside Git (for example Perforce), pass that revision and system.
            obaaf attest build-record --artifact dist --source-revision "$rev" --source-ref "refs/tags/$RELEASE_TAG" \
              --repository "$origin" --asset-revision "$rev" --asset-system git --manifest release-manifest.json \
              --builder-id "${JENKINS_URL}job/obaaf-release-publish/" --tier B \
              --out attestations/build-record.json --statement-out attestations/build-record.statement.json
            for record in slsa build-record; do
              obaaf dsse prepare --statement "attestations/$record.statement.json" \
                --out "attestations/$record.to-sign" --digest-out "attestations/$record.digest"
              aws kms sign --key-id "$SIGNING_KEY" --message "fileb://attestations/$record.digest" \
                --message-type DIGEST --signing-algorithm ECDSA_SHA_256 --query Signature --output text \
                > "attestations/$record.sig"
              obaaf dsse assemble --statement "attestations/$record.statement.json" \
                --signature "attestations/$record.sig" --public-key .obaaf/keys/release.pub.pem \
                --out "attestations/$record.dsse.json"
            done
          '''
        }
        archiveArtifacts artifacts: 'attestations/*.dsse.json', fingerprint: true
      }
    }
    stage('Verify') {
      when { not { changeRequest() } }
      steps {
        // Everything except the approvals, which do not exist yet. The approver reads this log.
        sh '''
          set -eu
          export PATH="$WORKSPACE/.obaaf-venv/bin:$PATH"
          obaaf verify release --policy .obaaf/policy.yaml --artifacts dist \
            --dsse attestations/slsa.dsse.json --dsse attestations/build-record.dsse.json \
            --repo-dir . --source-revision "$(cat release-sha.txt)" --pre-approval
        '''
      }
    }
    stage('Approve') {
      when { not { changeRequest() } }
      steps {
        // EDIT: the group whose members may approve releases. Keep whoever creates release tags out of it.
        input message: 'Publish this release? The verification result is in the log above.',
              id: 'release', submitter: 'release-managers'
      }
    }
    stage('Publish') {
      when { not { changeRequest() } }
      environment { OBAAF_LANE = 'release' }
      steps {
        // The controller records who approved this build (ApproverAction) and who started each build.
        // EDIT: a read-only API token for a Jenkins user that can read both jobs.
        withCredentials([usernamePassword(credentialsId: 'obaaf-jenkins-reader', usernameVariable: 'READER',
                                          passwordVariable: 'READER_TOKEN')]) {
          sh '''
            set -eu
            tree='url,number,actions[_class,userId,causes[_class,userId,shortDescription]]'
            curl -fsS --user "$READER:$READER_TOKEN" -G --data-urlencode "tree=$tree" "${BUILD_URL}api/json" \
              -o publish-run.json
            curl -fsS --user "$READER:$READER_TOKEN" -G --data-urlencode "tree=$tree" "${RELEASE_BUILD_URL}api/json" \
              -o release-run.json
          '''
        }
        // FR6: stop here unless provenance, the build record, the approvals and every agent record verify
        // against the policy. An approval by whoever started either build does not count.
        sh '''
          set -eu
          export PATH="$WORKSPACE/.obaaf-venv/bin:$PATH"
          obaaf verify release --policy .obaaf/policy.yaml --artifacts dist \
            --dsse attestations/slsa.dsse.json --dsse attestations/build-record.dsse.json \
            --approvals publish-run.json --release-run release-run.json \
            --repo-dir . --source-revision "$(cat release-sha.txt)"
        '''
        // EDIT: your upload, with a dedicated identity that can only publish (G6.1), to a beta or
        // staging channel; a person sets the build live in the store (G6.2).
        withCredentials([usernamePassword(credentialsId: 'store-upload', usernameVariable: 'STORE_UPLOAD_USER',
                                          passwordVariable: 'STORE_UPLOAD_TOKEN')]) {
          sh './scripts/publish.sh dist'
        }
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
