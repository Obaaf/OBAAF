// obaaf-models: A webhook-triggered review agent: the trigger token is in the file, the title is interpolated, and the agent gets an API key.
// obaaf-expect: OBAAF-JEN-015 OBAAF-JEN-009 OBAAF-JEN-001 OBAAF-JEN-007
pipeline {
  agent { label 'linux' }
  triggers {
    GenericTrigger(
      genericVariables: [[key: 'PR_TITLE', value: '$.pullRequest.title'], [key: 'PR_ID', value: '$.pullRequest.id']],
      token: 'review-trigger-123',
      regexpFilterText: '$EVENT',
      regexpFilterExpression: '^pr:(opened|modified)$'
    )
  }
  stages {
    stage('Review') {
      steps {
        sh "echo Reviewing ${PR_TITLE}"
        aiAgent(prompt: 'Review the change in this workspace', apiCredentialsId: 'model-api-key', yoloMode: true)
      }
    }
  }
}
