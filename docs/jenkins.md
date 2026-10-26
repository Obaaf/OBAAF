# Jenkins

OBAAF runs on Jenkins in two parts:

- `obaaf check` reads Jenkinsfiles as well as GitHub Actions workflows. For Jenkins it is an
  **advisory auditor**: it reports what a Jenkinsfile shows, and it says plainly what a Jenkinsfile
  cannot show.
- The **release lane** ([below](#the-release-lane-on-jenkins)) builds from a protected tag, signs
  SLSA provenance and the OBAAF build record with a key held in a key service, and blocks the
  upload unless `obaaf verify release` passes and a named person approves.

The agent and effect lanes, controller inventory and enforcement are not built for Jenkins yet
(see [What is not built yet](#what-is-not-built-yet)).

```sh
obaaf check .                        # workflows and Jenkinsfiles in the repository
obaaf check . --platform jenkins     # Jenkinsfiles only
obaaf check ci/Jenkinsfile.release   # one file
obaaf check . --lanes                # how each stage was classified
```

Every finding names the profile requirement and agent control it threatens, and the fix, like the
GitHub Actions rules. The Jenkins rules are `OBAAF-JEN-001` to `OBAAF-JEN-015`, listed with their
requirements in [the pipeline checker rules](../spec/checker-rules.md).

## Exit status 0 is not a conformance decision

Much of what decides whether a Jenkins pipeline is safe lives on the controller, not in the
Jenkinsfile:

- the security realm and authorization strategy, and who has Build, Run/Replay and Configure;
- build authorization (without it, builds run as SYSTEM and can start any job);
- which agents exist, whether the built-in node has executors, and which jobs share an agent;
- whether a shared library is trusted (global, run outside the Groovy sandbox) or untrusted
  (folder), and whether a Jenkinsfile may override its version;
- which jobs build pull requests from forks, and with which Jenkinsfile trust setting;
- credential scopes on folders, script approvals, and network policy around agents.

The checker reports each of these as a **coverage unknown** where it matters, never as a pass.
After the findings, the text report prints a coverage line per Jenkinsfile:

```
Jenkinsfile (declarative, sha256:5f25af801af6...): 2 unknown, 9 pass, 4 not applicable
  unknown OBAAF-JEN-004: line 3: whether each library is trusted ...
```

| Coverage | Meaning |
| --- | --- |
| fail | the rule found something (an active finding) |
| ignored | every finding was suppressed by an expiring ignore entry |
| unknown | the Jenkinsfile alone cannot settle it; the reason is listed |
| pass | the rule applied and found nothing |
| not applicable | nothing in the file the rule is about (for example no AI agent) |

Unknowns do not change the exit status in advisory mode. Findings gate it the usual way
(`--fail-on`), and a Jenkinsfile that cannot be analyzed is an error (exit 1). When nothing at all
is found to check, `obaaf check` exits 2.

When part of a file cannot be analyzed, no rule in that file can pass. This happens for calls to
steps that are neither built into Jenkins nor defined in the file (almost always shared-library
steps such as `buildPlugin()`), Groovy loaded at run time (`load`, `evaluate`), parallel branches
built elsewhere, Groovy classes, `@Grab`, and statements the parser could not read. The report lists
them under "No rule can pass".

## How the file is read

The checker parses Groovy with its own syntax-only reader. It never compiles the file, loads
classes, resolves `@Grab`, runs AST transforms or evaluates an expression, so nothing in a hostile
Jenkinsfile runs. Files over 1 MiB, more than 400,000 tokens, nesting deeper than 64 levels, or a
parse taking more than 10 seconds are reported as not analyzed. It makes no network requests, and
reads only the Jenkinsfile and files it names inside the repository (repository scripts, to find
agents; a pod `yamlFile`). Modelling and the rules are linear in the size of the file; a 1 MiB
pipeline takes a few seconds. A file the model cannot handle is reported as not analyzed, and the
other files are still checked.

It finds Jenkinsfiles at any depth up to six directories: `Jenkinsfile`, `Jenkinsfile.<name>`,
`Jenkinsfile-<name>` and `<name>.jenkinsfile`. Other files, such as `ci/*.groovy`, are added with
`jenkins.files`; test fixtures are left out with `jenkins.exclude` (see [Configuration](#configuration)).
A single `.groovy` file given on the command line is read as a pipeline.

## What it models

**Declarative Pipeline.** `pipeline`, `agent` (any, none, label, node, docker, dockerfile,
kubernetes with inline `yaml` or a `yamlFile` in the repository), `environment` (including
`credentials()` and its `_USR` and `_PSW` variables), `parameters`, `triggers`, `libraries`,
`stages`, nested `stages`, `parallel`, `matrix`, `steps`, `script`, `input`, `when` and `post`.
Credential scope follows nesting: a pipeline-wide `environment` reaches every stage.

**Scripted Pipeline.** `node`, `stage`, `if` and `else`, `try`, `catch` and `finally`, `switch`,
loops, `parallel` (maps, lists and computed expressions such as `collectEntries`),
`docker.image(...).inside`, `withDockerContainer`, `podTemplate` and `container`. A method the file
defines and calls is read where it is called, so its steps get the caller's stage, credentials, post
condition and conditions, and its arguments flow into its parameters. A method the file defines but
never calls (a shared-library step) is read as reachable from anywhere.

**Verification that can stop a publish.** A check counts only when it runs before the publish, its
failure stops the build, and it cannot be skipped while the publish still runs. It does not count
inside `catchError`, `warnError` or a `catch` block that does not throw again; with `returnStatus`;
followed by `||`, `&` or a pipe without `pipefail`; in a `#!` script without `-e`, a `bat` or a
`powershell` script when more commands follow it; in a parallel branch beside the publish; or under
a `when` or `if` that does not also guard the publish.

**Credentials.** `withCredentials` with every binding type, `environment` `credentials()`,
`sshagent`, `withSonarQubeEnv`, `docker.withRegistry` (also with a computed ID),
`configFileProvider`, `wrap` with a credential or Vault wrapper class, wrapper steps that supply
credentials by design (`withAWS`, including `role:`, `withVault`, `withKubeConfig`,
`withDockerRegistry` and others), and any step that names a credential ID at any depth of its
arguments. File and key-file bindings hold a path, not the secret.

**Who can reach a stage.** For each step the checker decides whether a change request (a pull or
merge request in a multibranch or organization-folder job) can reach it:

| Value | When |
| --- | --- |
| yes | `when { changeRequest() }`, `if (env.CHANGE_ID)`, or a pull-request trigger (GenericTrigger filtered on pull-request events, GitHub Pull Request Builder, GitLab merge requests) |
| no | `when { branch 'main' }`, `buildingTag()`, `not { changeRequest() }`, `if (env.BRANCH_NAME == 'main')`, combined with `&&` and `||`, and methods of the file that return such a test |
| possible | nothing keeps change requests out; whether the job builds them is job configuration |
| unknown | a condition the checker cannot evaluate that mentions branches or change requests |

Jenkins does not withhold credentials from pull-request builds, including builds from forks, so a
credential bound where a change request can reach it is available to the change's code. Jenkins can
take the Jenkinsfile itself from the target branch for untrusted changes, but the workspace, the
build scripts and the tests are still the change's own.

**Untrusted values.** Groovy interpolation (`"${...}"`), concatenation or `String.format` of a
change request's title, source branch or author name; build parameters; branch and tag names; GitLab
and GitHub Pull Request Builder variables; values a webhook trigger reads from the request; and
commit text read with `git log` or `git show`. They are followed through variables, `env['X']`,
`env.getProperty('X')`, method calls such as `.trim()`, `?:`, maps, lists and method parameters.

**AI agents.** An agent CLI in a shell step (the patterns in `src/obaaf/data/detection.yaml`), a
repository script that runs one, the AI Agent plugin's `aiAgent` step, steps and commands declared
in the configuration, and stages declared with `OBAAF_LANE = 'agent'`. Not recognizing an agent is
never evidence that a stage runs none.

**Publishing.** The upload commands shared with the workflow checker, plus `mvn deploy`, `gradle
publish`, JFrog, Helm, crane and skopeo pushes, `curl --upload-file`, `docker.image(...).push()`
and steps such as `s3Upload`, `nexusArtifactUploader`, `rtUpload`, `androidApkUpload` and
`appCenter`. Generic file transfer (`scp`, `rsync`, `sshPublisher`, `ftpPublisher`) is not counted,
because it mostly copies reports and logs; declare a stage that releases that way with
`OBAAF_LANE = 'release'`.

## Configuration

The checker reads the same file as for workflows: `.github/obaaf.yml`, `.github/obaaf.yaml` or
`obaaf.yml` at the root.

```yaml
# obaaf.yml
jenkins:
  files: ["ci/*.groovy"]                  # pipelines with other names
  exclude: ["src/test/resources/**"]      # test fixtures that are not real pipelines
agents:
  steps: [reviewWithClaude]               # shared-library steps that run an agent
  commands: ['run-agent\.sh']             # regular expressions matched against shell scripts
lanes:
  "Jenkinsfile#Publish": release          # file#stage, as --lanes prints it
ignore:
  - rule: OBAAF-JEN-007
    path: Jenkinsfile
    job: Review                           # the stage label
    reason: "Agent pods run in the ai-agents namespace, whose NetworkPolicy allows only the inference proxy"
    until: 2027-03-31
```

In a Jenkinsfile, set a stage's lane in its `environment` (`OBAAF_LANE = 'agent'`) or with
`withEnv(['OBAAF_LANE=agent'])`. A declared lane only adds rules.

## Running the audit in Jenkins

[`templates/jenkins/obaaf-audit.Jenkinsfile`](../templates/jenkins/README.md) runs the audit as a
Jenkins job. It belongs in a repository your platform or security team protects: it fetches the
target at a fixed commit and reads it as data, installs OBAAF from a reviewed commit with hashed
dependencies, ignores the target's own configuration, and archives the reports.

## Output

Text output adds the coverage block. JSON output adds a `jenkins` object, present only when a
Jenkinsfile was checked, so existing consumers see no change:

```json
"jenkins": {
  "advisory": true,
  "files": [{"path": "Jenkinsfile", "kind": "declarative", "digest": "sha256:...",
             "error": null, "unknowns": [], "lanes": [{"stage": "Build", "lane": "untrusted", "reason": "..."}]}],
  "coverage": [{"path": "Jenkinsfile", "platform": "jenkins", "rule": "OBAAF-JEN-001",
                "status": "pass", "reasons": []}]
}
```

Jenkins findings carry `"scope": "stage"`, and their `job` field names the stage. SARIF output is
unchanged in form.

## Testing

`tests/fixtures/jenkins/risky` holds one pipeline per documented attack pattern, each with the
rules it must produce; every Jenkins rule is exercised. `tests/fixtures/jenkins/safe` holds
pipelines that must produce no medium or high finding. `tests/test_jenkins_parser.py` checks that
hostile input (`@Grab`, `@ASTTest`, static initializers, deep nesting, token floods, huge files)
runs nothing and fails within the limits.

During development the parser and rules were also run over 512 public Jenkinsfiles and Groovy
pipeline files: the Declarative Pipeline plugin's test resources, the Jenkins project's examples,
Kubernetes plugin examples and shared pipeline library, and the Jenkinsfiles of several large open
source projects. All 512 parsed, with 7 statements recorded as not analyzed (4 deliberately invalid
test files and 3 Groovy constructors), in about one second in total. That run is how the rules'
precision was tuned; it is not a claim about any project's security. An adversarial review then
found 13 ways to get a silent pass or a crash (computed parallel branches, methods called from
credential scopes and post blocks, checks that cannot stop a publish, taint through ordinary Groovy,
filtered `changeRequest` conditions, more credential wrappers, computed pod specs, map-form
triggers, and a quadratic step); each is fixed and has a regression test.

## The release lane on Jenkins

The same rule as on GitHub Actions: no provenance, no upload. Two templates in
[`templates/jenkins/`](../templates/jenkins/README.md) split the work so that signing and upload
credentials never reach code a branch or pull request can change:

| Job | Where it runs | What it does | Credentials |
| --- | --- | --- | --- |
| `obaaf-release-build.Jenkinsfile` | your multibranch project, for tags only | builds the release, keeps `dist/`, starts the publish job | none |
| `obaaf-release-publish.Jenkinsfile` | its own Pipeline job, read from the protected default branch | resolves the tag through your SCM, copies exactly that build's artifacts, writes and signs the records, verifies, waits for approval, verifies again with the approvals, uploads | signing, controller read, upload |

The split matters on Jenkins in a way it does not on GitHub Actions: credentials scoped to a
multibranch project reach every branch and pull request it builds, and a pipeline runs whatever
Jenkinsfile its branch carries. So the build job holds nothing, and everything that can sign or
publish lives in a job whose definition comes only from the default branch.

### Signing with a key service

Jenkins has no identity for a job that the public Sigstore service accepts, so the publish job signs
DSSE envelopes with a key in a key service, and the policy sets `signing: keys` (the verifier has
supported that mode since 0.1; this is its first template). Two commands wrap the key service, so
the private key never leaves it and no OBAAF code needs cloud libraries:

```sh
obaaf attest build-record ... --statement-out build-record.statement.json
obaaf dsse prepare --statement build-record.statement.json --out build-record.to-sign --digest-out build-record.digest
aws kms sign --key-id alias/obaaf-release --message fileb://build-record.digest --message-type DIGEST \
  --signing-algorithm ECDSA_SHA_256 --query Signature --output text > build-record.sig
obaaf dsse assemble --statement build-record.statement.json --signature build-record.sig \
  --public-key .obaaf/keys/release.pub.pem --out build-record.dsse.json
```

`prepare` writes the exact bytes DSSE signs (and their digest, for services that sign a digest).
`assemble` takes the signature as raw bytes or base64, DER or raw r||s, checks it against the public
key, and only then writes the envelope, so a wrong key or a changed statement fails in the build,
not at release time. Google Cloud KMS (`gcloud kms asymmetric-sign --input-file ... --digest-algorithm
sha256`) and Azure Key Vault (`az keyvault key sign`, which returns r||s) work the same way. Use an
ECDSA P-256 key (P-384 with `--digest sha384`), or RSA.

To set it up: create the key (in AWS, key spec `ECC_NIST_P256`, usage `SIGN_VERIFY`), export its public
key to `.obaaf/keys/release.pub.pem` on the default branch (`aws kms get-public-key ... --output text |
base64 -d | openssl pkey -pubin -inform DER -outform PEM`), give the publish job a credential that can
call only `kms:Sign` on that key, and copy
[`obaaf-policy.example.yaml`](../templates/jenkins/obaaf-policy.example.yaml) to `.obaaf/policy.yaml`.

### Approvals Jenkins records

The publish job's `input` step names a submitter group. When someone approves it, the Pipeline:
Input Step plugin records an `ApproverAction` with their user ID on the build, and every build
records why it started (`CauseAction`). The publish job reads both builds' JSON from the controller
(`BUILD_URL/api/json`) with a read-only API token and passes them to `obaaf verify release
--approvals publish-run.json --release-run release-run.json`. The verifier then:

- counts distinct approvers, and does not count anyone who started either build;
- blocks a build that is a Replay (which can run an edited Jenkinsfile) or was restarted from a
  stage (which skips the stages before it);
- checks, as on GitHub, the signatures, the artifact digests, the build record, the release
  commit's place on the protected branch, and agent records.

### What this does not prove

Be precise about what the Jenkins release lane rests on, because some of it is controller
configuration the files cannot show:

- **The publish job's definition.** The checks hold only while the publish job runs this file from
  the default branch. Do not grant Run/Replay or Configure on it to people who can push branches; the
  verifier blocks a Replay it can see, but a replayed script could also edit that check.
- **Who holds the signing credential.** Keep it in a folder that contains only the publish job,
  and run that job on agents that run nothing else. On EKS, an IAM role for the agent pod's service
  account is better than a stored credential.
- **Where the build ran.** The tier in the build record comes from the publish job's `--tier`: it
  is declared, not observed. The artifacts are trusted as the output of the tag build that Jenkins
  names; the commit is resolved through your SCM's protected tag, not taken from that build.
- **Who created the tag.** Jenkins does not record it, so keep tag creators out of the approver group.
- **Run identity.** Fields such as `BUILD_URL` in the records come from the build's own environment
  and say so (`"reportedBy": "build process environment (self-reported)"`); they locate a build, they
  do not authenticate it.

These templates were checked with OBAAF's own Jenkins rules and the signing and verification path is
tested end to end with a simulated key service; they have not yet run on a live controller.

## What is not built yet

The Jenkins integration is staged (D-034 to D-037 in [DECISIONS.md](../DECISIONS.md)). Built: the
advisory auditor and the release lane. Not yet built:

- the agent and effect lanes: a snapshot of Jenkins triggers, agent-run records whose authority
  comes from the Jenkinsfile model and controller facts, approval records for agent changes, and the
  AI workload as a separate Kubernetes Job behind the inference proxy;
- controller inventory (an exported, signed snapshot of security, agent, library and job settings)
  that would turn many unknowns into passes or findings;
- shared-library analysis at a verified revision;
- signed Jenkins run evidence from the controller, so run identity stops being self-reported.

Until then, treat a clean Jenkins report as "nothing found in the file", not as assurance.
