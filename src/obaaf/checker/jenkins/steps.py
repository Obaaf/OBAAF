"""Names the Jenkins model treats as known: built-in Pipeline steps, steps of widely used plugins,
Declarative directives, and global objects.

A call to anything else that the Jenkinsfile does not define itself is most likely a
shared-library step (`buildPlugin()`, `infra.runMaven()`) or a plugin step the checker does
not know. Its code is not in the file, so the checker reports it as a coverage unknown
instead of assuming it is harmless. Adding a name here asserts that the checker understands
what the step can do, so add only steps whose effect on credentials, agents and publishing is
either nothing or modelled in model.py and rules.py.
"""

# Pipeline core (workflow-basic-steps, workflow-durable-task-step, workflow-cps, workflow-support,
# pipeline-build-step, pipeline-input-step, pipeline-stage-step, pipeline-milestone-step, lockable-resources).
CORE = {
    "archive", "archiveArtifacts", "bat", "build", "catchError", "checkout", "cleanWs", "deleteDir", "dir", "echo",
    "error", "fileExists", "fingerprint", "git", "input", "isUnix", "junit", "library", "libraryResource", "load",
    "lock", "mail", "milestone", "node", "parallel", "powershell", "properties", "pwd", "pwsh", "readFile",
    "readTrusted", "resolveScm", "retry", "script", "sh", "sleep", "stage", "stash", "step", "timeout",
    "timestamps", "tm", "tool", "unarchive", "unstable", "unstash", "waitUntil", "warnError", "withEnv",
    "wrap", "writeFile", "ws", "evaluate", "getContext", "withContext", "emailext", "emailextrecipients",
    "ansiColor", "cleanWs", "skipDefaultCheckout", "buildDiscarder", "logRotator", "disableConcurrentBuilds",
    "pipelineTriggers", "cron", "pollSCM", "upstream", "githubPush", "parameters", "string", "text", "booleanParam",
    "choice", "password", "file", "credentials", "run", "durabilityHint", "preserveStashes", "quietPeriod",
    "checkoutToSubdirectory", "disableResume", "newContainerPerStage", "overrideIndexTriggers",
    "parallelsAlwaysFailFast", "rateLimitBuilds", "retry", "skipStagesAfterUnstable", "nonresumable",
    "copyArtifactPermission", "githubProjectProperty", "buildBlocker",
}

# Declarative directives and conditions. They are interpreted by model.py, never run as steps.
DECLARATIVE = {
    "pipeline", "agent", "any", "none", "label", "docker", "dockerfile", "kubernetes", "environment", "options",
    "triggers", "tools", "stages", "steps", "post", "when", "branch", "buildingTag", "changelog", "changeset",
    "changeRequest", "equals", "expression", "tag", "not", "allOf", "anyOf", "triggeredBy", "beforeAgent",
    "beforeInput", "beforeOptions", "isRestartedRun", "always", "changed", "fixed", "regression", "aborted",
    "failure", "success", "unstable", "unsuccessful", "cleanup", "matrix", "axes", "axis", "values", "excludes",
    "exclude", "notValues", "failFast", "submitter", "submitterParameter", "ok", "message", "id", "image", "args",
    "reuseNode", "registryUrl", "registryCredentialsId", "customWorkspace", "alwaysPull", "filename", "dir",
    "additionalBuildArgs", "libraries", "lib", "jdk", "maven", "gradle", "nodejs", "yaml", "yamlFile",
    "inheritFrom", "defaultContainer", "cloud", "namespace", "retries", "containerTemplate", "containerTemplates",
}

# Credentials and SCM helpers (credentials-binding, ssh-agent, git, docker-workflow, kubernetes, config-file-provider).
CREDENTIALS = {
    "withCredentials", "usernamePassword", "usernameColonPassword", "string", "file", "zip", "certificate",
    "sshUserPrivateKey", "dockerCert", "gitUsernamePassword", "sshagent", "withDockerRegistry", "withDockerServer",
    "withDockerContainer", "dockerFingerprintFrom", "dockerFingerprintRun", "podTemplate", "container",
    "containerLog", "configFileProvider", "configFile", "withKubeConfig", "withAWS", "withSonarQubeEnv",
    "waitForQualityGate", "withMaven", "withGradle", "withNPM", "withPythonEnv", "withVault", "vaultString",
    "vaultFile", "azureServicePrincipal", "withAzureCLI", "gitChangelog", "scmGit", "GitSCM", "branches",
    "extensions", "userRemoteConfigs", "cloneOption", "localBranch", "pruneStaleBranch",
}

# Reporting and analysis steps that read results and publish them inside Jenkins only.
REPORTING = {
    "recordIssues", "recordCoverage", "publishHTML", "publishChecks", "withChecks", "junit", "jacoco", "cobertura",
    "publishCoverage", "checkStyle", "spotBugs", "pmdParser", "cpd", "taskScanner", "esLint", "styleLint", "java",
    "javaDoc", "mavenConsole", "hadoLint", "findbugsPublisher", "junitPublisher", "discoverReferenceBuild",
    "discoverGitReferenceBuild", "realtimeJUnit", "xunit", "nunit", "mstest", "perfReport", "plot", "slackSend",
    "office365ConnectorSend", "mattermostSend", "setGitHubPullRequestStatus", "githubNotify", "gitlabCommitStatus",
    "updateGitlabCommitStatus", "addBadge", "addShortText", "addInfoBadge", "addWarningBadge", "addErrorBadge",
    "createSummary", "removeBadges", "buildName", "buildDescription", "currentBuild", "readJSON", "writeJSON",
    "readYaml", "writeYaml", "readProperties", "readCSV", "writeCSV", "readMavenPom", "writeMavenPom", "findFiles",
    "touch", "sha1", "sha256", "zip", "unzip", "tee", "httpRequest", "copyArtifacts", "lastSuccessful",
    "lastCompleted", "latestSavedBuild", "specific", "permalink", "upstream", "buildParameter", "workspace",
    "jiraComment", "excludeFile",
}

# Steps that copy files outside Jenkins. Those that publish artifacts are also listed in
# detection.yaml (jenkins_upload_steps); generic file transfer (sshPublisher, ftpPublisher)
# is not counted as publishing. Here they only count as understood.
PUBLISHING = {
    "sshPublisher", "sshPublisherDesc", "sshTransfer", "ftpPublisher", "s3Upload", "nexusArtifactUploader", "nexusPublisher",
    "googleStorageUpload", "rtUpload", "rtPublishBuildInfo", "rtDockerPush", "azureUpload", "ftpPublisher",
    "androidApkUpload", "googlePlayUpload", "appCenter", "gitHubRelease", "createGitHubRelease",
}

# Triggers (read by model.py) and the AI Agent plugin's step (detection.yaml, jenkins_agent_steps).
TRIGGERS = {"GenericTrigger", "ghprbTrigger", "GhprbTrigger", "githubPullRequests", "gitlab", "bitbucketPR",
            "githubPush", "pollSCM", "cron", "upstream", "aiAgent", "claudeCode", "codex", "cursor", "openCode",
            "antigravity", "grok", "pi", "omp", "kiro"}

# Groovy built-ins that are not steps.
GROOVY = {"println", "print", "printf", "sprintf", "assert", "tokenize", "each", "collect", "find", "findAll",
          "any", "every", "with", "sleep", "toString", "equals", "hashCode", "getClass", "use", "isCase",
          "call", "super", "this", "Integer.parseInt", "String.format", "Math.max", "Math.min"}

KNOWN_STEPS = CORE | DECLARATIVE | CREDENTIALS | REPORTING | PUBLISHING | TRIGGERS | GROOVY

# Objects whose methods are understood: `env.X`, `currentBuild.result`, `docker.image(...)`.
KNOWN_OBJECTS = {"env", "params", "currentBuild", "scm", "docker", "manager", "Jenkins", "jenkins", "System",
                 "Math", "JsonOutput", "JsonSlurper", "JsonSlurperClassic", "Integer", "Long", "String", "Boolean",
                 "Double", "Float", "Date", "Calendar", "TimeUnit", "Thread", "it", "this", "steps", "script",
                 "binding", "BUILD_NUMBER", "BRANCH_NAME", "JOB_NAME", "WORKSPACE", "CHANGE_ID", "TAG_NAME",
                 "hudson", "org", "java", "groovy", "Collections", "Arrays", "UUID", "URLEncoder", "Paths",
                 "Files", "Pattern", "Matcher", "LocalDate", "LocalDateTime", "Instant", "Duration", "ZonedDateTime"}
