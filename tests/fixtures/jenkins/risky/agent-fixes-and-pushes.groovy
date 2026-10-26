// obaaf-models: An AI agent fixes failing tests and the same stage pushes its edits with an SSH key, with the agent CLI installed unpinned.
// obaaf-expect: OBAAF-JEN-001 OBAAF-JEN-003 OBAAF-JEN-007 OBAAF-JEN-008
pipeline {
  agent { label 'linux' }
  stages {
    stage('AI autofix') {
      steps {
        sshagent(credentials: ['repo-deploy-key']) {
          sh 'npm install -g @anthropic-ai/claude-code'
          sh 'claude -p "Fix the failing tests" --dangerously-skip-permissions'
          sh 'git commit -am "AI fixes" && git push origin HEAD:main'
        }
      }
    }
  }
}
