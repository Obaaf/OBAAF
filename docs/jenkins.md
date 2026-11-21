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

It finds Jenkinsfiles by name, in any letter case: `Jenkinsfile`, `Jenkinsfile.<name>`, `Jenkinsfile-<name>`,
`Jenkinsfile_<name>`, `Jenkinsfile<name>` (`Jenkinsfile2`, `JenkinsfileRelease`), `<name>.jenkinsfile`,
`<name>-jenkinsfile` and `<name>_jenkinsfile`, but not one ending in `.md`, `.txt`, `.html`, `.png`, `.svg`,
`.yml`, `.yaml`, `.json`, `.xml`, `.properties`, `.orig` or `.bak`, which a note names. In a git work tree
it looks at every file git lists (tracked, or not committed and not ignored), in any folder and at any
depth, because the file a Jenkins job runs is set on the controller and can be any path; elsewhere it walks
the folders, skipping `build`, `dist`, `target`, `vendor`, `node_modules` and similar folders and anything
deeper than six folders, and a note names the folders it did not enter. A Jenkinsfile that is a link is
read, under its own path, when it leads to a file in the repository, and is an error otherwise. Other files,
such as `ci/*.groovy`, are added with `jenkins.files` (`**/` there also matches no folder, and a pattern that
matches nothing is a note); test fixtures are left out with `jenkins.exclude`, and a note names what it left
out (see [Configuration](#configuration)). A single `.groovy` file given on the command line is read as a
pipeline. A Jenkinsfile with a name none of these has, which a job runs because the controller says so, is
not read unless `jenkins.files` names it.

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

**An approval that stops a publish** (OBAAF-JEN-005, flagship slice 2d.2l). An `input` step, or a
Declarative stage's `input`, counts for a publish on the same terms, with two differences: an input in
the same `catchError` or `try` block as the publish, before it, still counts, because an abort skips the
rest of the block; and a stage's `input` is asked before its `when` unless the `when` says `beforeInput
true`. No input counts for a publish in `post { always }`, `aborted`, `failure` or another failure path,
or in a `catch` or `finally` block. A blank, empty or `null` `submitter`, and the group `authenticated`,
let any user who can build the job approve. Not read, and so not counted as an approval: an input whose
abort sets a flag the publish tests, one in a `finally` block, one inside `catchError(catchInterruptions:
false)`, and a shared-library step. A submitter held in a variable, a method parameter or a map
variable is "cannot tell", and so is a missing approval when part of the file was not read. Two
conditions written the same way (compared by their whole structure) count as the same condition, even
where a variable or a file they test changes between them; inside a method the file inlines, a condition
that reads anything but properties of `env`, `params` and `currentBuild` (`env.BRANCH_NAME`, not a bare
`BRANCH_NAME`) is tied to that call.

**Another job's artifacts** (OBAAF-JEN-010, flagship slice 2d.2m). A copy is `copyArtifacts` on any
receiver, `step([$class: 'CopyArtifact', ...])`, or a Jenkins URL to another build's artifacts in a shell
step or `httpRequest` (`job/b/lastSuccessfulBuild/artifact/`, a job's `ws/`, a URL kept in the file's
`environment` or in a variable). Its arguments are read as Groovy builds them: a map given as the only
argument or held in a local variable the file declares once, in a block around the copy, and names nowhere else, and the last of a repeated key.
A selector moves when it is the default, `lastSuccessful`, `lastCompleted`, `latestSavedBuild`, `permalink`,
`lastWithArtifacts`, `workspace` or `buildParameter`, a `specific` build named by anything but digits (Jenkins
reads other text as a permalink or a build's display name), or `upstream(fallbackToLastSuccessful: true)`;
`specific` with digits, or with the number of a `build` step the file runs and keeps in a variable it names
nowhere else, is fixed. The copy is cleared for a publish only by an `obaaf verify release` after it and before
that publish, run in an `sh` script as a command whose failure stops the script (the reader of slice 2d.2e: not
in an `echo`, a comment, after `|| true`, `&`, `set +e` or `exit`, nor with `returnStatus`), under no condition
the publish does not share (a condition on parameters alone that the copy shares excepted), not in a parallel
branch or a `catch`, `catchError` or `warnError`. A publish in a failure path, beside the copy in a parallel
block, or before the copy in the same `retry` block or loop is never cleared. Another digest or signature check
(`sha256sum -c`, `cosign verify`, `gpg --verify`) makes the copy "cannot tell", because its sums may come from
the build that was copied. Also "cannot tell": a selector, a build number, a project or a `$class` the file
computes, a spread map (`*: m`), `downstream`, `invokeMethod`, a method pointer or computed method name, any
other place the file names `copyArtifacts` or the `CopyArtifact` class, a copy in a method or closure (read
where it is written), and a file whose copies, checks and publishes expand into too many to compare. Not read:
downloads by other tools (JFrog CLI, the Artifactory and Nexus plugins, an object store's "latest" key), a URL
built in other ways (`env.X =`, a parameter's default; a value from `environment` or a variable is put in, but
never takes away what the text alone shows, since the shell or a `withEnv` may set it otherwise), `bat` and `powershell` checks, a check whose
status the script tests (`if (sh(..., returnStatus: true) != 0)`), and whether the check covers the files that
were copied. Stages are told apart by name, so two Scripted stages with one name, or computed names, are one
stage for the severity.

**A provenance check that stops the publish** (OBAAF-JEN-012, flagship slice 2d.2n). Each publish needs an
earlier `obaaf verify release` (without `--pre-approval`) that stops it when it fails: on a line of its own in an
`sh` script that stops at a failed command, read by the reader of slice 2d.2e, with `returnStatus` absent or
`false`, not in a parallel branch beside the publish, not in a `catch`, `catchError` or `warnError` the publish is
not also in, and under no condition the publish does not share. A provenance-only check (`cosign
verify-attestation`, `gh attestation verify`, `slsa-verifier verify`, `--pre-approval`) gives medium. A publish in
the pipeline's `post` block is never checked; one in a stage's `post` block is checked by a check in an earlier
stage; one in a `catch` or `finally` block after a check is "cannot tell". Also "cannot tell": a check the reader
does not vouch for (Groovy text in the script, a computed `returnStatus`, an expansion among its arguments, a path
or wrapper, `bat`, `powershell`, `pwsh`, a line before it the reader cannot read), a publish read where a closure
or uncalled method is written, and a check read only there. To clear it, put `obaaf verify release` on its own
line in an `sh` step, with literal arguments, before the publish. The limits are listed in
[bypass-attempts.md](bypass-attempts.md#2d2n-a-provenance-check-before-the-publish).

**A publish that can run after a failed or skipped check** (OBAAF-JEN-011, flagship slice 2d.2o). Two cases are
reported at high. First, a publish in a failure path: a Declarative `post` condition that runs after a failure
(`always`, `changed`, `regression`, `aborted`, `failure`, `unstable`, `unsuccessful`, `notBuilt`, `cleanup`) or a
Scripted `catch` or `finally` block. A publish in a stage's own `post` block is not reported when every check runs
in an earlier stage and stops its step, since a failed check skips the stage, post block included. Second, a check
before a publish whose failure does not stop it. The checks are `obaaf verify ...`, `gh attestation verify`,
`cosign verify...`, `slsa-verifier verify...`, `sha256sum -c` and its kin, and `gpg --verify`. Each is read from
the command's words by the shell reader of slice 2d.2e. Its failure is ignored when the step says so:
`returnStatus: true`, `|| true`, `|| :`, `|| echo`, a trailing `&`, a pipe without pipefail set before it, `set +e`
or a `#!` line without `-e` with more commands after it, a trap that runs `exit 0`, or more lines after it in a
`bat` script. It is also reported when it runs in a parallel branch beside the publish, in a `catchError`,
`warnError` or `catch` the publish is not also in, or under a condition the publish does not share. "Cannot tell"
covers:

- a check the reader does not vouch for (Groovy text in the script, a computed `returnStatus`, `powershell`, a
  path to the program, `bash -c`, a check inside `if`, after `!` or in a `&&` list, a line before it the reader
  cannot read, such as `export PATH=...`);
- a check or publish read only where a closure or uncalled method is written;
- a publish in a Declarative `post` block under a condition on the build's result;
- a check in a catching block when the publish runs only on a result that block may have set (`post { success }`
  or a guard on `currentBuild.result`).

To clear it, publish in a later stage or in `post { success }`, and put each check on its own line in an `sh` step
with literal arguments and nothing that ignores its failure. The limits are listed in
[bypass-attempts.md](bypass-attempts.md#2d2o-a-publish-after-a-failed-or-skipped-check).

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

**Workspaces and agents** (flagship slice 2d.2j). OBAAF-JEN-003 asks whether what an AI agent wrote
can reach a push, a `build` step or a publish without review, so the checker records the workspace
every step runs in:

| In the Jenkinsfile | Workspace |
| --- | --- |
| a top-level `agent` | one, for every stage that has no `agent` of its own, the pipeline's `post` and the stages' `post` blocks |
| a stage's own `agent` (label, node, any, docker, dockerfile, kubernetes), `node()`, a `matrix` agent | a new one |
| `agent none` on a stage, `dir()`, `container()`, `docker.image(...).inside`, `withDockerContainer` | the enclosing one |
| a docker or dockerfile agent with `reuseNode true`, or a `reuseNode` the file does not fix | the enclosing one |
| `ws()` | another directory on the same node, written by the same user: counted as shared |
| `node(POD_LABEL)` (`"${POD_LABEL}"`, or the template's own `label:`: the same text, variable or literal) inside `podTemplate` | the pod's own, gone with the pod unless its `workspaceVolume` is a claim, a host path or an NFS export; pods on one named claim, or one export of one server, share it. Any other label there is an ordinary agent |
| a method nothing in the file calls, the body of a step whose code is not in the file | one of its own, shared by everything in it |
| a closure, where it is written | one of its own; where the file calls it, the caller's |

The table follows the Jenkins handbook ([Pipeline Syntax](https://www.jenkins.io/doc/book/pipeline/syntax/):
the top-level agent "specifies where the entire Pipeline ... will execute", and `reuseNode` runs the
container "on the node specified at the top-level of the Pipeline, in the same workspace"; [Using
Docker with Pipeline](https://www.jenkins.io/doc/book/pipeline/docker/); read on 2026-11-20). Where the
handbook says nothing (that a stage's `post` runs in the stage's workspace, that a nested stage
without an agent runs in its parent's), the checker takes the reading under which more steps share a
workspace.

The verdicts:

- an agent and an effect in the same workspace, the effect running after the agent (later in the
  file, in a sibling parallel branch, or inside a loop, `retry` or `waitUntil` around both): **high**;
- a `stash` taken after the agent and `unstash`ed before the effect (the same name, or a name the file
  does not fix), or `archiveArtifacts` brought back with `unarchive`: **high**;
- the effect before the agent in a workspace Jenkins keeps between builds: **medium**, because what
  the agent leaves there (a Git hook, `.git/config`, a script the effect runs) is in place for the
  effect in the next build. A fresh pod, or `deleteDir()`, a full `cleanWs()` (or the `WsCleanup`
  step) or a checkout with `WipeWorkspace` that certainly runs before the effect (or a clean in a
  `post { always }` or `cleanup` block after the agent), clears it; `cleanWs` with `patterns`,
  `externalDelete` or a `cleanWhen...: false`, and `CleanBeforeCheckout` (`git clean`, which keeps
  `.git`), do not;
- the agent and the effect in separate allocations that may land on the same machine (the same label,
  label expressions that require a common label such as `linux && docker` and `linux`, an expression
  that requires none such as `sandbox -> gpu`, any agent, a label the file does not fix, the same
  `customWorkspace` or `ws()` path, or pods whose workspace claim the file does not fix):
  **unknown**, because Jenkins keeps a job's workspace directory on an agent between allocations and
  which agents carry which labels is controller configuration;
- different labels, or separate pods with their own workspace: no finding.

OBAAF-JEN-002 counts an AI agent's work like a change request's: an agent stage and a stage that
holds credentials or publishes on the same persistent label, or on labels that require a common one,
is a medium finding. Label expressions are parsed with Jenkins's operators (`!`, `&&`, `||`, `->`,
`<->`, brackets). One that names the built-in node where a match can require it and holds on that
node (`built-in || linux`, `linux -> built-in`, `built-in && !master`: since Jenkins 2.307 the built-in
node carries `built-in` and not `master` unless the old label was kept) can place work on the
controller, and so can a docker or dockerfile agent with `label 'built-in'`, whose workspace is under
`$JENKINS_HOME` (when the controller itself runs in a container, Docker Pipeline also passes it
`--volumes-from`). A label expression that requires no label (`!windows`) is read like `agent any`.

OBAAF-JEN-006 reads docker run options as docker splits them: grouped short options (`-itv`), values
written with `=` or attached (`-v/path`), `--mount type=bind,source=...`, `CAP_`-prefixed capabilities
and `--device`, and `--privileged=false` is not privileged. A host mount of `/`, a container runtime's
socket, the kernel's file systems (`/proc`, `/sys`), the runtimes' state (`/var/lib/docker` and others),
rootless Docker's socket folder (`/run/user/...`), the controller's home (`/var/lib/jenkins`,
`/var/jenkins_home`) and an agent's root (`/home/jenkins/agent`), whole or any part but a build's caches
(`.m2`, `.gradle`, `.cache`, `tools` and others; the Git plugin's mirrors under `caches` count), a user's whole home (`/home/jenkins`), a home's
credential folders (`.ssh` but its `known_hosts`, `.docker`, `.kube`, `.aws`, `.gnupg`) and credential
files (`.netrc`, `.git-credentials`, `.npmrc`, `.pypirc`), or a whole system folder (`/run`, `/var/run`, `/dev`, `/etc`, `/root`, `/home`, `/var`,
read-only too; only the folders that hold programs, such as `/usr` and
`/opt`, are ordinary read-only) reaches the host. A folder inside one (`/root/.m2`,
`/etc/localtime:ro`, `/dev/shm`, `/var/jenkins_home/.m2`) and read-only `/sys/fs/cgroup` do not.
`--volumes-from` is an unknown. Jenkins splits `args` itself, not exactly as a shell does, so the
options are read both as a shell splits them and between blanks, and anything either reading finds
counts; a backslash in them is an unknown. Booleans are read as docker reads them (`--privileged=t` is
privileged), paths are cleaned (`//var/run`), `--mount` fields are read as CSV with keys in any case,
`--use-api-socket` mounts the Docker socket, and Windows drive roots and the Docker named pipe count.
Pod specs are read as YAML, which also reads JSON: string booleans count, a projected
`serviceAccountToken` volume mounts a token whatever `automountServiceAccountToken` says, only the
first document is read for the token, and a spec nested too deeply or too large to read is an unknown.
`podTemplate`'s own `privileged`, `hostPathVolume`, `hostNetwork` and a `hostPathWorkspaceVolume`
count; a Kubernetes agent with no pod spec at all mounts the service account token.

OBAAF-JEN-007 passes a stage whose agent's shell steps run in a container started with exactly one
network, `none`, and nothing that reaches the host. A host path mounted into that container may hold
a socket, which is a way out whatever the network, so the finding stays and names the paths. A step
that Docker Pipeline does not launch in the container (`aiAgent`, which the plugin runs itself) is not
limited by it.

**What the checker cannot decide here.** Reported as unknown, or left as a finding:

- which machines carry which labels, whether a persistent agent is shared with other jobs, and what a
  pod template defined on the controller (`inheritFrom`) mounts;
- `matrix` cells: each cell has its own allocation, but the checker reads the cells as one, so an
  agent in one cell and a push in another, kept apart only by `when` conditions on the axes, is
  reported as sharing a workspace;
- what an agent leaves outside the workspace on a persistent agent (`$HOME/.gitconfig`, tool caches):
  a clean workspace does not remove it, which is why OBAAF-JEN-002 reports agent work on shared labels;
- a later step outside the container that runs what an agent with no network wrote into the
  workspace: OBAAF-JEN-007 judges where the agent runs, not what is done with its output;
- what reaches an effect through values rather than files: the agent's output read into a variable
  and passed to `build job:` parameters or a commit message, or `copyArtifacts` of the running build;
- agent commands and effects the checker does not recognise (a push through `/usr/bin/git`, a
  quoted option value before `push`, `gh api`, a repository script or Makefile that runs one): the
  recorded attempts in [bypass-attempts.md](bypass-attempts.md#2d2j-agent-stages-and-workspaces)
  list them, and #330 tracks them;
- a closure handed to code outside the file, which is read where it is written, in a workspace of
  its own;
- a pod spec whose YAML redefines the plugin's workspace volume, and a label built from an
  `environment` value (read as a label the file does not fix);
- labels are compared without letter case, so `Built-In` counts as the built-in node, although Jenkins
  compares labels with case;
- a build's caches and `tools` under the controller's home or an agent's root are ordinary even when
  mounted writable, though other builds on that machine use them, and a job named `tools` under
  `/home/jenkins/workspace` is read as such a folder;
- a `node()` whose literal label is a pod template's literal label is read as that pod, though a static
  agent with the same label may take the build (only `POD_LABEL` is certain);
- option-like text inside a quoted `--label` or `-e` value can be read as an option, because the
  options are also read split between blanks; a workspace claim mounted read-only by the agent's pod
  still counts as shared.

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
  "Jenkinsfile#Publish": release          # file#stage; --lanes prints it as "Jenkinsfile#stage Publish"
ignore:
  - rule: OBAAF-JEN-007
    path: Jenkinsfile
    job: Review                           # the stage label
    owner: "@my-org/platform"
    reason: "Agent pods run in the ai-agents namespace, whose NetworkPolicy allows only the inference proxy"
    until: 2027-03-31
```

In a Jenkinsfile, set a stage's lane in its `environment` (`OBAAF_LANE = 'agent'`) or with
`withEnv(['OBAAF_LANE=agent'])`. A declared lane only adds rules, and every declaration counts: the
pipeline's, each enclosing stage's, the stage's own, and a `lanes:` entry in the configuration for
the file (`Jenkinsfile`), the stage (`Jenkinsfile#Ship`) or a stage it is nested in. None of them
hides another, so a stage declared `release` in the file and `agent` in the configuration gets the
rules of both. A value that is not a lane, or one computed when the build runs, declares nothing.
Where it reaches at least one step it is reported as the finding `OBAAF-CFG-001`, on its line in
the Jenkinsfile, with the labels of the stages it reaches as `--lanes` prints them (a method
that nothing in the file calls is `name()`, a `post` block `post always`), except that steps
outside any stage have the empty label and not `pipeline`. So is a `lanes:` entry that names a stage the file does
not have, in the configuration file; a stage written without a block (`stage 'Build'`) holds no
step and counts as one the file does not have. Unlike the OBAAF-JEN rules it is not advisory about the
controller: it says the checker did not get a declaration its author wrote. Two things are not
read as declarations and not reported: an assignment (`env.OBAAF_LANE = 'agent'`), and the
variable under another spelling (`obaaf_lane`). See
[the configuration guide](checker-configuration.md#a-declaration-that-does-nothing).

On a stage, `agent` and `release` are the lanes that change what is checked. `agent` says the
stage's shell steps, and its steps whose code is not in the file (shared-library steps, outside
`post`, `catch` and `finally` blocks), run an agent; `release` says they publish, and that the stage's `sshPublisher` and
`ftpPublisher` steps do. Other steps the checker knows (`archiveArtifacts`, `httpRequest`, `build`)
are not changed by a declaration. The other lanes are accepted and change nothing.

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
| `obaaf-release-build.Jenkinsfile` | a multibranch project that discovers tags only | builds the release, keeps `dist/`, starts the publish job | none |
| `obaaf-release-publish.Jenkinsfile` | its own Pipeline job, read from the protected default branch | finds the tag build that started it, resolves the tag through your SCM, copies that build's artifacts, writes and signs the records, verifies, waits for approval, verifies again with the approvals, uploads | SCM read, signing, controller read, upload |

The split matters on Jenkins in a way it does not on GitHub Actions: credentials scoped to a
multibranch project reach every branch and pull request it builds, and a pipeline runs whatever
Jenkinsfile its branch carries. So the build job holds nothing, and everything that can sign or
publish lives in a job whose definition comes only from the default branch.

Give the tag builds a project of their own, with tag discovery and nothing else, and keep branches
and pull requests in your usual project. A branch can carry any name, including one that looks like
a release tag, and its build runs whatever Jenkinsfile the branch holds; in a project that builds
only tags, every build runs the Jenkinsfile of a protected tag. Jenkins discovers tags but does not
build them on its own: add the "Build tags" strategy from the Basic Branch Build Strategies plugin,
or start each tag build by hand, in which case that person cannot approve the release.

### How the artifacts are tied to the tag

The publish job takes no parameters. It finds the build that started it from its own start cause
(`currentBuild.getBuildCauses`), refuses to run if a person started it, and requires that build to be
in the tag project. The tag is the name of that build's job, resolved to a commit through your SCM.
At the end, the verifier checks the same facts again from the controller's JSON for both builds,
which the publish job fetches with a read-only API token:

- the publishing build was started by exactly one build, and not by a person;
- that build is the one whose JSON was passed as `--release-run` (same URL);
- that build is the tag build `<release.jenkins_project>/<tag>`, where the tag is the one in the
  signed build record;
- that build checked out the release commit, as the Git plugin records it (`lastBuiltRevision`);
- neither build is a Replay (which can run an edited Jenkinsfile) or was restarted from a stage
  (which skips the stages before it);
- every start cause has a class, so nothing is hidden by a JSON request that leaves fields out.

Anything missing blocks: a policy without `release.jenkins_project`, approvals from Jenkins without `--release-run`, a GitHub approvals list
with a Jenkins `--release-run`, a build with no recorded causes, or a tag build with no recorded
commit. The pre-approval check runs the parts that do not need approvals, so the approver sees them.

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
not at release time. Google Cloud KMS hashes its input itself, so give it the bytes to sign, not the
digest (`gcloud kms asymmetric-sign --digest-algorithm sha256 --input-file build-record.to-sign
--signature-file build-record.sig ...`). Azure Key Vault (`az keyvault key sign --algorithm ES256`
with the base64 digest) returns r||s, which `assemble` accepts. Use an ECDSA P-256 key (P-384 with
`--digest sha384`), or RSA.

To set it up: create the key (in AWS, key spec `ECC_NIST_P256`, usage `SIGN_VERIFY`), export its public
key to `.obaaf/keys/release.pub.pem` on the default branch (`aws kms get-public-key ... --output text |
base64 -d | openssl pkey -pubin -inform DER -outform PEM`), give the publish job a credential that can
call only `kms:Sign` on that key, and copy
[`obaaf-policy.example.yaml`](../templates/jenkins/obaaf-policy.example.yaml) to `.obaaf/policy.yaml`,
with `release.jenkins_project` set to the tag project and `release.approvers` to your release managers.

### Approvals Jenkins records

The publish job's `input` step names a submitter group. When someone approves it, the Pipeline:
Input Step plugin records an `ApproverAction` with their user ID on the build. The verifier:

- counts distinct approvers, and does not count anyone who started either build;
- counts only people listed in `release.approvers`, when the policy lists them. Set it: Jenkins
  administrators can approve any input step whatever its submitter says, and an input step with no
  submitter can be approved by anyone who can build the job;
- checks, as on GitHub, the signatures, the artifact digests, the build record, the release
  commit's place on the protected branch, and agent records.

### What this does not prove

Be precise about what the Jenkins release lane rests on, because some of it is controller
configuration the files cannot show:

- **The publish job's definition.** The checks hold only while the publish job runs this file from
  the default branch, because that job also fetches the controller JSON the verifier reads. Grant
  Run/Replay and Configure on it to nobody who can push branches; the verifier blocks a Replay it can
  see, but a replayed script could also edit that check.
- **Who holds the signing credential.** Keep it in a folder that contains only the publish job. A
  label does not stop other jobs from asking for the same agents: restrict the release agents to the
  release jobs on the controller (for example with the Job Restrictions plugin), or run the release
  jobs in a fresh Kubernetes pod per build. On EKS, an IAM role for the agent pod's service account
  is better than a stored credential.
- **Where the build ran.** The tier in the build record comes from the publish job's `--tier`: it
  is declared, not observed.
- **What the tag build did.** The artifacts are trusted as the output of the tag build that started
  the publish job. The verifier checks that build checked out the release commit, but a Jenkinsfile
  can check out more than one commit; the guarantee comes from the tag's Jenkinsfile, which your
  SCM's tag protection controls, and from the tag project building nothing else. The release commit
  itself is resolved through your SCM, not taken from that build.
- **Who created the tag.** Jenkins does not record it, so keep tag creators out of the approver group.
- **Run identity.** Fields such as `BUILD_URL` in the records come from the build's own environment
  and say so (`"reportedBy": "build process environment (self-reported)"`); they locate a build, they
  do not authenticate it.

These templates were checked with OBAAF's own Jenkins rules, and the signing and verification path is
tested end to end with a simulated key service and simulated controller JSON; they have not yet run
on a live controller.

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
