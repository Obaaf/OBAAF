// An agent stage that only writes a proposal: no credentials, no push, a pinned CLI and image.
// The egress rule (OBAAF-JEN-007, low) still applies: a Jenkinsfile cannot show network policy.
pipeline {
  agent none
  stages {
    stage('Propose') {
      agent {
        docker { image 'registry.example/agent@sha256:1111111111111111111111111111111111111111111111111111111111111111' }
      }
      steps {
        sh 'npm install -g @anthropic-ai/claude-code@2.0.14'
        sh 'claude -p "Propose a fix for the failing test" > proposal.md'
        archiveArtifacts artifacts: 'proposal.md'
      }
    }
  }
}
