# Checker configuration

`obaaf check` runs with no configuration. A repository can tune it with a file at `.github/obaaf.yml` (also read from `.github/obaaf.yaml` or `obaaf.yml` at the root), and with two environment variables set on a job.

## Telling the checker about your agents

The checker puts each job in every lane it belongs to (untrusted, agent, effect, release; a job in none of them is trusted) and runs each lane's rules on the jobs in that lane. A job that runs an agent and publishes is in the agent lane and in the release lane, and gets the rules of both. The agent controls run only on jobs in the agent lane. It recognizes an agent by the action a job `uses:`, or by an agent CLI in a `run:` script. The recognized actions and commands live in `src/obaaf/data/detection.yaml`.

The checker also reads repository `.sh` and `.bash` wrappers to find an agent CLI:

```yaml
jobs:
  triage:
    runs-on: ubuntu-latest
    steps:
      - run: bash scripts/run-agent.sh   # the agent starts inside the script
```

It can trace a simple copy in the same `run:` block back to the original repository directory, including a symbolic temporary path:

```yaml
      - run: |
          SNAPSHOT=$(mktemp -d)
          cp -r scripts "$SNAPSHOT/scripts"
          bash "${SNAPSHOT}/scripts/run-agent.sh"
```

This is best-effort static inspection. It does not execute shell code or read the
temporary destination. The copy source must be readable within the repository;
symlinks that escape it are not followed. Arbitrary variable assignments, fetched
or generated scripts, copies across separate steps, nested wrapper chains, and
complex shell control flow are not resolved. A copy alias means the source may
be executed; it is not proof of runtime reachability.

Always run `obaaf check . --lanes` and confirm that agent jobs are classified as
`agent` before relying on the findings. When the checker finds agent instruction
files (`AGENTS.md`, `CLAUDE.md`, and the like) but places no job in the agent lane,
it prints an advisory note. For wrappers it cannot resolve, declare the entry
point so the agent controls apply:

```yaml
# .github/obaaf.yml
agents:
  commands:
    - 'run-agent\.sh'          # a Python regular expression, matched against each run: line
  actions:
    - my-org/internal-agent    # a private action that runs an agent, matched as a uses: prefix
```

With that, the `triage` job above is placed in the agent lane, and the agent controls (for example a write token or a secret reaching the job) are reported.

You can also set the lane on a single job explicitly:

```yaml
jobs:
  triage:
    env:
      OBAAF_LANE: agent        # untrusted, agent, effect, release, or trusted
```

A declaration adds a lane. It never takes a job out of a lane the checker inferred, so it can add rules and cannot remove any: declaring `release` on a job that runs an agent leaves it an agent job and makes it a release job as well. Declaring `trusted` adds no lane and removes none. When `trusted` is the only lane declared for a job and the checker puts the job in a lane anyway, the reason shown for that lane ends with `declared trusted, which cannot override what the job does`. Case and surrounding space do not matter (`Agent` is `agent`).

`OBAAF_LANE` is read in a job's `env` and in the workflow's `env`, and nowhere else, and under that exact name. A declaration that does nothing is a finding, `OBAAF-CFG-001`: a value that is not a lane (a misspelling, an expression, an empty value), the variable in another spelling (`obaaf_lane`), and `OBAAF_LANE` set in a step's `env`, a container's or a service's. See [A declaration that does nothing](#a-declaration-that-does-nothing).

When a job is in a lane both because of what it does and because it was declared, the declaration is the reason shown (`set by OBAAF_LANE`, `set in the checker configuration`).

## Lane overrides

```yaml
# .github/obaaf.yml
lanes:
  "release.yml#publish": release
```

A lane override only adds rules, like `OBAAF_LANE`: the job is put in the lane you name as well as the lanes the checker inferred, and if `OBAAF_LANE` names another lane the job is in that one too. A key without `#job` applies to every job in the file. Use the workflow path shown by `--lanes`, for example `.github/workflows/release.yml#publish`, when checking a repository root. The same key applies when you check that one workflow on its own (`obaaf check .github/workflows/release.yml --config .github/obaaf.yml`); a Jenkinsfile checked on its own is known by its file name only.

For a Jenkinsfile the key names a stage (`Jenkinsfile#Ship`) and also covers the stages nested in it; `Jenkinsfile` alone covers every stage. See [jenkins.md](jenkins.md).

For a file this run reads, an entry is a finding (`OBAAF-CFG-001`, reported in the configuration file, on the entry's line) when its value is not a lane or when it names a job or Jenkins stage the file does not have. When a repository is checked, so is an entry for a file that is not there. An entry for a file outside the run (another file when one file is checked, a Jenkinsfile when only workflows are checked) is not looked at. `lanes:` must be a mapping; any other value that is not empty is a configuration error and the check does not run.

### A declaration that does nothing

A lane declaration exists to add rules to a job. One that changes nothing leaves the job without those rules, and nothing else in the report would show it: a job declared `OBAAF_LANE: agnet` is not an agent job to the checker, so none of the agent findings appear and the check passes. Until 0.3.0 such a declaration was listed in the notes at the end of the report, which do not affect the result. It is now a finding, `OBAAF-CFG-001`, so it fails the check until it is corrected or accepted.

```text
.github/workflows/triage.yml
     9  HIGH   OBAAF-CFG-001  Lane declaration that does nothing  [job triage]
        Job 'triage' sets OBAAF_LANE to 'agnet', which is not a lane (untrusted, agent, effect, release, trusted), so the declaration changes nothing.
```

What is reported, and where:

| The declaration | Reported in |
| --- | --- |
| `OBAAF_LANE` in a job's `env` or the workflow's `env`, set to a value that is not a lane | the workflow |
| the variable in another spelling in a job's `env` or the workflow's `env`: another case, spaces round the name, a hyphen or a space for the underscore (`obaaf_lane`, `OBAAF-LANE`) | the workflow |
| `OBAAF_LANE` in a step's `env`, a `parallel` group's, a container's or a service's, whatever its value | the workflow |
| `OBAAF_LANE` in a Jenkinsfile, in an `environment` block or a `withEnv` that reaches at least one step, set to a value that is not a lane or computed when the build runs | the Jenkinsfile |
| a `lanes:` entry whose value is not a lane | the configuration file |
| a `lanes:` entry that names a job or Jenkins stage its file does not have, or a file that is not there. A stage written without a block (`stage 'Build'`) holds no step, and an entry for it is reported | the configuration file |
| a `lanes:` entry whose key is not text (`5:`, `true:`) | the configuration file |

The line is the line the declaration is written on. One that reaches a job or a step through a YAML alias or a merge key (`<<:`) is reported on the first line of that job or step. One entry can be two findings: `'ci.yml#wrok': agnet` has a value that is not a lane and names a job that is not there.

**Severity.** The finding is high. The checker cannot know which findings are missing because of the declaration, and the agent lane alone has high-severity rules, so anything lower would let a gate set to `--fail-on high` pass a job whose agent rules never ran. It is low where nothing can be missing: the declaration names `trusted`, which adds no rule even where it is read; it is written where it is not read, or under another spelling, in a job that is in the lane it names anyway; or it is a `lanes:` entry for a Jenkins stage that is not there and names `untrusted` or `effect`, which change nothing on a stage. If the job later leaves that lane the finding becomes high, and a baseline entry that accepted it at low no longer covers it.

**Fixing it.** Correct the value, spell the variable `OBAAF_LANE`, move it to the job's `env`, correct the `lanes:` key, or delete the declaration. For a workflow the key is the path and job that `obaaf check . --lanes` prints (`.github/workflows/ci.yml#build`). For a Jenkinsfile it is the file and the stage's own name (`Jenkinsfile#Ship`, or `Jenkinsfile#Outer > Inner`), without the word `stage` that `--lanes` prints before it. A finding in a Jenkinsfile names what the declaration reaches by the same labels: a stage by its name, a method that nothing in the file calls as `name()`, a `post` block as `post always`. One label differs: steps outside any stage are `pipeline` in `--lanes` and under `lanes:`, and the empty text (`""`) in the finding's `stages`, because a stage may itself be named `pipeline`. `--lanes` prints these declarations too, as notes, because it lists lanes and reports no findings.

**Accepting it: with a baseline entry, not an `ignore` entry.** A baseline entry carries an owner, a reason and an expiry date, and names the declaration it accepts: the file it is written in, the job and step for one in a workflow, the names of the stages it reaches for one in a Jenkinsfile, the `lanes:` key for one in the configuration, the variable's name where that is misspelt, and the value it was set to. Change any of them and it is another finding. Two declarations that agree in all of them (two steps of the same name with the same stray declaration) need an entry each. Two Jenkins stages with the same label are one stage to the checker, here as in `--lanes` and under `lanes:`, so a declaration moved from one to the other is the same finding. The label is the stage's name with the stages it is nested in (`Outer > Inner`), so a stage that is itself named `Outer > Inner` shares it. A `lanes:` key that is not text and a text key spelled the same (`true:` and `'true':`) are one finding too; neither names a file. A value, key or name longer than 200 characters is identified by its length and SHA-256 digest, so that a baseline stays readable. An `ignore` entry cannot do this: it accepts a rule in a file, whatever the finding says, so one entry for the configuration file would accept every `lanes:` entry that does nothing, including ones written later. An `ignore` entry that names `OBAAF-CFG-001` is therefore a configuration error, and the check does not run.

**The configuration file's path.** A finding about a `lanes:` entry names the configuration file from the directory every other path in the report is given from: `.github/obaaf.yml` when a repository is checked, and `../obaaf.yml` when one workflow is checked on its own with `--config .github/obaaf.yml`, because that workflow is `ci.yml` in the same report. A baseline written for one of those two ways of running the check therefore does not accept the finding in the other, as it does not for the findings in the workflow itself.

**Not reported.** In a Jenkinsfile, `OBAAF_LANE` under another spelling, and one set by assignment (`env.OBAAF_LANE = 'agent'`), which the checker does not read as a declaration at all. A second configuration file: the checker reads the first of `.github/obaaf.yml`, `.github/obaaf.yaml` and `obaaf.yml` that exists, and says nothing about the others.

`obaaf check . --lanes` shows the first lane a job is in, in the order agent, effect, release, untrusted, and names the others after it: `ci.yml#ship: agent (uses openai/codex-action; also release: uploads or publishes artifacts)`.

## Authority and hygiene

Every rule is one of two categories, reported separately in the summary and in the SARIF output (as `obaaf-category`):

- **authority**: who or what can change, build, release or sign, and the controls that bound an agent's authority. These are the findings to gate on first.
- **hygiene**: pinning and hardening. Today these are `OBAAF-GHA-008` (pin actions and images to a digest) and `OBAAF-GHA-020` (restrict agent egress). They matter, but they should not bury the authority findings, and a pilot does not need to clear every one to be a success.

Gate CI on one category with `--fail-on`:

```bash
obaaf check . --fail-on authority:medium   # fail only on authority findings at medium or above
```

`--fail-on` also accepts a plain severity (`high`, `medium`, `low`) or `never`. A bare category (`authority` or `hygiene`) means that category at low severity and above.

GHA-008 stays high for agent, release and effect jobs.
It is low for other jobs only when their token permissions are explicit and
limited, no secrets are referenced, and no privileged outside event can start
them. Other jobs retain medium pinning findings. Low severity still recommends
pinning; `--fail-on low` includes these findings.

Informational findings are included in text, JSON and SARIF, but do not fail any
severity threshold. SARIF records use their actual reported severity; a rule's
documented default is not necessarily the severity of each occurrence.

<a id="protected-secrets"></a>
## Protected secrets

List the secrets that must never be available outside an environment. Anyone with write access can read a repository secret by pushing a branch with a new workflow, so these belong in an environment limited to the default branch ([GitHub settings](github-settings.md#secrets)):

```yaml
# .github/obaaf.yml
protected_secrets:
  PYPI_TOKEN: release          # must be used only by jobs in the `release` environment
  PRIVATE_SET_TOKEN: private-set
```

A plain list (`protected_secrets: [PYPI_TOKEN]`) accepts any declared environment. Names are case-insensitive and may use `*` and `?` globs, with at least three letters or digits (`*_API_KEY`, not `*_*`). When several entries match a secret, every one applies. OBAAF-GHA-024 is reported, at high severity, for every job that uses a listed secret without the named environment, including jobs that can take every secret (`toJSON(secrets)`, or `secrets[...]` with a computed index). Environment names compare case-insensitively, as GitHub does. An environment named by an expression is reported at medium, because the checker cannot tell which environment it will be.

A job that calls a reusable workflow (`uses:` at job level) cannot declare an environment. Passing it a protected secret is reported, with the advice to declare the environment in the called workflow's job instead. `secrets: inherit` is not reported, because it passes repository and organization secrets only, never an environment's.

The checker refuses a configuration with a setting it does not know, so a misspelt key such as `protected-secrets` cannot turn a rule off silently.

The rule checks the workflow files against what you declared. It cannot see that the secret has actually been removed from the repository and organization, or that the environment's deployment branches are limited, so check those in the settings.

<a id="lifecycle"></a>
## What happens to a finding

Every finding is in one of four states. JSON output gives the state of each finding as `state`. The text report prints a line under a finding when there is something to say about it: who accepted it and until when, why an entry that names it does not count, or what was established about its controls. A finding with no such line is new. Findings ignored by configuration are listed at the end, one line each, with who accepted them and until when. Every report [begins with the accepted risk](#accepted-risk).

| State | What it means | Does it fail the check? |
| --- | --- | --- |
| **new** | Nobody has decided anything about it, or the decision does not count (see below). | Yes, at or above `--fail-on` |
| **accepted** | A valid acceptance names it: an [ignore entry](#ignore) or a [baseline entry](#baseline) with an owner, a reason and an expiry date. | No, until the date passes |
| **fixed** | Every control that clears the finding was read and verified by the checker. It is listed at the end of the report with the controls. | No |
| **cannot tell** (`cannot-tell` in JSON) | No control that would clear it is known to be missing, but the checker could not read what decides at least one of them. | Yes. The checker never assumes a control it cannot read. |

Two rules report controls: a secret in an agent job (OBAAF-GHA-005) and an agent job with no egress restriction (OBAAF-GHA-020). Every other finding is new or accepted.

<a id="controls"></a>
### Controls that clear a finding

Under a finding that has controls the report lists each one with a verdict:

- **verified**: the checker read what decides it, and it holds.
- **not met**: the checker read it, and it does not hold.
- **cannot tell**: the checker could not read what decides it. This is never treated as a pass.

A finding is fixed when every control is verified. If none is known to be missing and at least one could not be read, the finding is "cannot tell". If any is not met, it is new. Controls do not change which finding an acceptance names, so a finding can be accepted whatever its controls say.

```text
.github/workflows/agent.yml
     5  HIGH   OBAAF-GHA-005  Secret available to an agent job  [job agent]
        Agent job 'agent' receives MODEL_API_KEY.
        Controls (it is cleared when all 4 are verified):
          verified     each of the job's secrets is listed in protected_secrets, and the job declares the environment named there (MODEL_API_KEY in environment 'main-only')
          cannot tell  the secrets are stored only in that environment, and only protected branches may use it (where a secret is stored and which branches may use environment 'main-only' are repository settings, which obaaf check does not read; obaaf audit reads environments and their branch rules)
          verified     no pull request, issue or comment starts the job, and its checkout steps and the event fields it reads take nothing from one (started only by workflow_dispatch; 1 checkout step(s) take the ref the event names)
          not met      a control the checker recognises limits the job's network access to an allow-list (no blocking egress control in the job)
```

**OBAAF-GHA-005 cannot be cleared today**: its second control is a repository setting, which `obaaf check` does not read. **OBAAF-GHA-020 can be**, by GitHub's native egress firewall, and by OBAAF's egress action once OBAAF lists a released commit of it (none is listed yet). Until a finding is cleared, the controls say what is in place and what is missing, and the finding is accepted with an owner, a reason and an expiry date, or it fails the check. JSON output gives the controls of each finding as `controls`, each with an `id` that stays the same when the wording changes.

What each control is, and what the checker reads to decide it:

| Control (`id`) | Verified when | Not met when | Cannot tell when |
| --- | --- | --- | --- |
| `secrets-protected` | Every secret the job references matches an entry in [`protected_secrets`](#protected-secrets), and the job declares the environment the entry names (any environment, for an entry that names none). This is what OBAAF-GHA-024 checks for the secrets that are listed. | A secret is not listed; the job can take every secret (`toJSON(secrets)`, `secrets[...]`, `secrets: inherit`); the job declares no environment, or another one; the job calls a reusable workflow, which cannot declare an environment. | The job's environment is an expression, is not written as text (a number, true or false, a list or a mapping: YAML readers do not agree on how numbers are spelt), or differs from the one named only in the case of letters outside ASCII. |
| `environment-restricted` | Never, today. | The job declares no environment, or calls a reusable workflow: its secrets then come from the repository or organization. | In every other case. Where a secret is stored, and which branches may use an environment, are repository settings. [`obaaf audit`](settings-audit.md) reads environments and their branch rules; `obaaf check` does not use what it reads yet. |
| `no-outsider-input` | Only `push`, `workflow_dispatch`, `schedule` or `release` can start the job; every `actions/checkout` step takes the ref the event names or one written out in the workflow; and no `${{ }}` in the job, and no `if:` of the job or its steps, reads a field someone without write access can write (the fields OBAAF-GHA-010 lists). | A pull request, an issue, a comment or another outsider's event can start the job, a run that follows any other run included; a checkout step names a pull request's ref; a script uses a command the checker knows to fetch a pull request's code (`gh pr checkout`, `gh pr diff`, `git fetch` or `git pull` of `pull/N/head`, a `.patch` address); an expression or condition reads such a field (a commit message, for example). | Another event can start the job (`workflow_call`, `repository_dispatch`, `merge_group`, a run that the job's `if:` limits to runs started by `push`, `release`, `workflow_dispatch` or `schedule`), or no event was found; a checkout names another repository or a ref computed when the job runs, or takes its inputs from an expression; the job calls a reusable workflow. |
| `egress-enforced` | One of two controls holds, [as below](#egress-controls): GitHub's native egress firewall, or OBAAF's egress action around the agent's command. | The control the job has is read and does not hold: no blocking control, one behind an `if:`, a monitor that does not start first, or only a declaration in `OBAAF_EGRESS`; and each case marked "not met" below. | The control the job has cannot be read to the end: each case marked "cannot tell" below. Harden-Runner and the Agent Workflow Firewall run from a script are never better than this. |

What the third control does not read, so that "verified" is not taken for more than it is. Its name says what it covers: the events, the checkout steps and the event fields. It does not cover what a script, an action other than `actions/checkout` or the agent itself fetches while the job runs (issue text fetched with `gh`, a web page, a pull request fetched by a command the checker does not know); a workflow that starts this one with `workflow_dispatch` and passes on text an outsider wrote; a value another job hands over through `needs.*.outputs`; or the content of a local action. A proxy that holds the model key is not a control of its own: a model key given to OBAAF's egress action in `model-keys` goes to AWF's API proxy, out of the command's reach, and the fourth control says so, but nothing clears the finding for it (plan slice 2c.7).

<a id="egress-controls"></a>
#### What clears OBAAF-GHA-020

The checker reads every control the job might have and keeps the one that comes out best, because one real control is enough. Each is verified only where every condition below was read and holds (decision D-050).

- **GitHub's native egress firewall** covers every step of the job, post steps included, from outside the runner's virtual machine. *Verified* when every run of the job is on `ubuntu-24.04-firewall` and the repository's `.github/egress-firewall.yaml` sets `mode: enforce`. *Not met* when the file is missing or spelt otherwise (the name is case sensitive), sets `mode: log`, or the job's token has no `contents` permission (the firewall's README: without `contents: read` no policy file is enforced, and there is no warning); or when some runs of a matrix are on another runner. *Cannot tell* when the file cannot be read to the end (not YAML, duplicate keys, a link, larger than 1,000,000 bytes, a merge key `<<`, which YAML 1.1 and 1.2 readers read differently, or U+0085, U+2028 or U+2029, which YAML readers do not agree are line breaks), its mode is anything else, it allows an entry that is not a plain host name or that is or has under it a public suffix (the README does not say whether a name covers the names under it), other workflows can call this one (whose policy file then applies is not established), or a single workflow file was checked rather than a repository; and for a job on labels the checker cannot name, in a repository whose policy enforces, because a larger runner with the firewall image carries labels of its owner's choosing. The firewall is a technical preview, and the report says so beside a cleared finding, with what it does not stop: anything sent to an allowed host, printed to the job's log or saved as an artifact.
- **OBAAF's egress action** (`Obaaf/OBAAF/actions/egress`, [its page](egress-control.md)) confines one command, so it holds only for the command it runs. A copy of it in the repository (`./actions/egress`) is any repository's own action and is not taken for it. *Verified* when, for every step that uses it: the action is pinned to a commit OBAAF lists as released (**none is listed yet**, so today this is "cannot tell"); its `allow` is written out, and every entry is a host name the action accepts and none is, or has under it, a public suffix from the [public suffix list](https://publicsuffix.org/), private section included (a listed name covers every name under it, so `github.io`, or `amazonaws.com` with `s3.amazonaws.com` under it, would let in anyone's site); it gives a `run`; the job runs on GitHub-hosted `ubuntu-24.04`, the only runner the action was tested on, and not in a container; the agent is that command; and **no step but `actions/upload-artifact` can run after it or beside it**.
  - *The agent is that command* is read from where credentials go, because an agent needs a key and the checker recognises few agents by name. No other step, and no `env` of the job or the workflow, may be given in the workflow a secret (`GITHUB_TOKEN` included) or `github.token`; the job may not be able to request OIDC tokens (`id-token: write`), which any step can turn into a cloud credential, or give its token the `models` permission, which every action receives without being asked (`actions/checkout` takes it as its default `token`); and no other step may run an agent the checker recognises (by action, by command, or in a repository script). A step before the action that does nothing but install an agent's CLI (`npm`, `pnpm`, `yarn global` or `bun` installing `@anthropic-ai/claude-code`, `@openai/codex` or `@google/gemini-cli`, with options and a version, and printing the CLI's version) is not taken for running it, since slice 2c.8: every command in its script must be one of those two, in a plain `bash` or `sh` step, with no `$`, quote, pipe, redirection, `&`, glob, backslash or trailing comment; anything else in the step, or the same step after the action, and it counts as an agent outside. A job that does not declare its token's permissions is "cannot tell": the repository's default is not read. A job in which no credential reaches the confined command or AWF's API proxy (below) is "cannot tell", unless the checker recognises the agent in the action's `run` input or in a script it runs, because an agent that needs no key could run in any step.
  - *Where the confined step's credentials go* (since slice 2c.5, decision D-052) is read as the action reads its inputs. A credential set in the step's `env` under a name its `model-keys` input names (`ANTHROPIC_API_KEY` or `OPENAI_API_KEY`) goes to AWF's API proxy, which the command can use and cannot read, and which reaches that provider's API host whatever `allow` says: the finding shows that host after the allow-list, as `api.anthropic.com (through AWF's API proxy)`, as one of the finding's facts. A credential set in the step's `env` under a name its `env` input names, or written in its `run` input, is passed to the command, which can send it to a listed host (and have that host act for it, if the credential lets it) or print it to the job's log. So is a credential of the step's `env` written into `run` through the `env` context (`${{ env.ANTHROPIC_API_KEY }}`), which GitHub fills with the step's own `env` when it writes the inputs, whatever `model-keys` says. Either is the evidence that the agent is the confined command, and neither stops the control from being verified: the network is limited as the allow-list (and the provider's host) says, and the report says the rest beside the cleared finding. That evidence is text the workflow's author writes (a credential in a comment in `run` counts), as all of D-050's evidence is. A credential set in the step's `env` under a name neither input names, and written into no input, reaches neither, and is no evidence. *Not met* when a name would make the action refuse to run in one of these ways: a model key, a GitHub token name or another name AWF withholds under `env`, a name `model-keys` does not take (another provider, another case), something that is not a variable name, or a model key no `env` of the step, the job or the workflow sets. Other ways the action refuses at run time are not read (a name under `env` set nowhere, an empty key, a line break in a value, a reserved name such as `PATH`). *Cannot tell* when `env` or `model-keys` is computed when the job runs or is not written as text, the step's `env` is computed and holds a credential, a credential in it is set under a name that differs from another only in case or is not written as text (`true:`), the whole `env` context is written into `run` (`${{ toJSON(env) }}`), a credential is given anywhere else in the step (another input, a condition), or an `env` value holding one is written into another input. OBAAF-GHA-005's fourth control says, whatever its verdict, where each credential the checker could place goes, what it could not place, and what would make the action refuse. The checker reads the inputs as the action does from the merge of slice 2c.4 on, so only commits at or after it may be listed as released (`egress_action_floor` in `src/obaaf/data/detection.yaml`; a test refuses an older one).
  - *No step but `actions/upload-artifact` after it*: any other step that can run after it or beside it (a script, `git` in the copy, another action) could run or load what the command wrote with the full network, and the checker cannot tell reading from running, so it is "cannot tell". Steps before it are read too, for what their post steps or the processes they leave running could reach: a step that names `/tmp`, the scratch directory (`obaaf-egress`) or the action's outputs is "cannot tell", and so is one that may leave a process running: `&` as an operator, or any mention of `nohup`, `setsid`, `disown`, `daemonize`, `start-stop-daemon`, `systemd-run`, `coproc`, `batch`, `at` followed by a time word, a digit or an option (not a quoted or computed time), a container engine (`docker`, `docker-compose`, `podman`, `podman-compose`, `nerdctl`) or a terminal multiplexer (`screen`, `tmux`), detached or not, because shell can detach one in more spellings than the checker could list; and service containers given volumes or options. The whole script is searched, comments and quoted text included, so a word in a comment adds a "cannot tell" rather than hiding one. `actions/cache` with such a path, anywhere in the job, is *not met*: its post step saves after the job, for a later run to load.
  - *Not met* also when the allow-list has a name the action refuses, or `allow` or `run` is missing. A cleared finding says what the action does not stop: anything sent to a listed host, the credentials passed to the command included; data in a name under a listed name, which leaves the runner in a DNS query to that name's DNS servers (since slice 2c.4, a name the proxy refuses does not leave the runner); with a model key, anything the command sends the provider through AWF's API proxy, and whatever the provider is asked to fetch or connect to for it (remote MCP servers, URLs), since the proxy refuses only the providers' hosted web search and fetch tools; and anything the command prints to the job's log or leaves for a later `actions/upload-artifact` step to save, which whoever can read the run's logs and artifacts can read.
- **Harden-Runner** (`step-security/harden-runner`) runs beside the job, on the same machine. *Not met* when it is not the job's first step on its own, runs behind an `if:`, is a release before v2.16.0 by its commit (which fixed two published bypasses of the block policy), leaves `sudo` or containers to the job (`disable-sudo-and-containers` is not `true`; `disable-sudo` alone keeps Docker, from which a step can undo its rules), or the job runs in a container on a GitHub-hosted runner, where its source at v2.16.0 sets up nothing. Its version is read only from a commit OBAAF lists with the release it was tagged as on 2026-11-13, never from a tag or a comment beside a commit; a tag or an unlisted commit is "cannot tell" whatever it says. Otherwise it is *cannot tell*, always: whether the repository is public, or covered by a paid tier (the free tier does not cover private repositories), is not in the workflow. It is also "cannot tell" when its policy comes from StepSecurity's policy store (`policy:` or `use-policy-store:`; it falls back to audit mode on some errors in fetching it), or on a runner that is not GitHub-hosted. Its source at v2.16.0 also switches block mode to audit when it cannot reach its cache (`src/setup.ts`), which a workflow cannot show.
- **The Agent Workflow Firewall run from a script** (`awf ... --` where a command starts, outside what the checker takes for a comment, which follows `'` and `"` but not every form of shell quoting) is *cannot tell*: which AWF version runs, with which options, and whether the agent is the command it wraps are read from a shell command line, which the checker does not do well enough. With `--enable-dind` anywhere in such a script, comments included, which AWF's documentation says allows a bypass, it is *not met*.

What none of these reads: a control outside the workflow and the repository (a self-hosted runner behind a network policy, which an ignore entry with an owner, a reason and an expiry date records); a process an earlier step leaves running in a form the checker does not recognise (`sudo -b`, `systemctl start`, a program that detaches itself), or an earlier action's post step that finds the scratch directory without being given it; a key kept in a configuration variable (`vars.`) or handed from another job's outputs (`needs.*.outputs`), which the checker does not count as a credential; whether the confined command can reach a service container of the job (the escape tests did not try); and whether the hosts on an allow-list can be trusted with what the agent sends them.

A baseline entry that accepts OBAAF-GHA-020 for a control the checker cannot verify (a monitor, the firewall, OBAAF's action or AWF) is for the workflow file as it stood, byte for byte; the finding shows the first 32 characters of the file's SHA-256, and for the firewall the policy file's as well. Any later change to that file makes the finding a new one, to be looked at again. That is blunt on purpose: the checker cannot verify the control, so it does not judge which changes to it matter. An [ignore entry](#ignore) names the rule, the file and the job and holds until its date; use one if the finding should stay accepted while the file changes.

Which events can start a job is read from the tokens of the job's `if:`. Only a comparison of `github.event_name` with a text (`==` or `!=`, either way round), on its own or joined to other conditions by `&&` and `||`, rules an event out. A negation, a comparison of a comparison, a function, and words inside a string rule nothing out. An `if:` that has `${{ }}` and anything outside it, even a space or the line break of a `|` block, is a text to GitHub and is always true, so it rules nothing out either. In a workflow that other workflows call, `github.event_name` is the caller's event, so no test rules `workflow_call` out. A job that needs another job is limited to the events that job runs on, unless its `if:` has `always(`, `failure(` or `cancelled(` anywhere in it, or `success()` anywhere but as one of the conditions joined by `&&`.

Input names under `with:` are read with A to Z in either case, as GitHub reads them: `REF:` is the `ref` input. A step that gives the same input twice in two spellings is reported as an error, because the checker cannot tell which value GitHub uses. So is an input name with a letter outside ASCII, because it is not established what GitHub's upper-casing makes of one.

### An acceptance needs an owner, a reason and an expiry date

Accepting a finding is a decision somebody makes for a while. The checker enforces three things about it, in an ignore entry and in a baseline entry alike:

- **an owner**: a user (`@octocat`), a team (`@my-org/build`) or an e-mail address, the forms a CODEOWNERS file takes. The checker checks the form only. It cannot tell whether the account exists, or that `@tbd` is nobody.
- **a reason**, in words. The checker cannot judge a reason. It refuses one with fewer than four letters or digits, which rules out an empty one, a dot, `n/a` and `tbd`, and nothing more: `aaaa` is a reason to the checker, and so are four letters of a script whose letters look like punctuation.
- **an expiry date** (`YYYY-MM-DD`) that has not passed and is at most 366 days ahead. An acceptance is looked at again at least once a year; a date of 2999 would be a permanent acceptance with a date on it.

An entry that lacks one of these, has expired, or is dated too far ahead accepts nothing. Its finding counts as new and fails the check like any other, and the report says under the finding what the entry lacks:

```text
    12  HIGH   OBAAF-GHA-005  Secret available to an agent job  [job triage]
        Agent job 'triage' receives MODEL_API_KEY.
        Not accepted: the baseline entry that names this finding does not count, because it expired on 2026-10-01.
```

<a id="accepted-risk"></a>
### The report begins with the accepted risk

An accepted finding does not fail the check, so a gate can be green with any amount of accepted risk behind it. The first thing each report says is therefore how much is accepted, at what severity, by whom and until when. "0 new" comes after that.

```text
Accepted risk: 38 finding(s) are accepted and do not fail the check (19 high, 19 low).
  @my-org/build: 36 (18 high, 18 low); the first expires 2027-03-31
  @octocat: 2 (1 high, 1 low); the first expires 2026-12-01
  36 accepted by baseline entries, 2 by ignore entries in the checker configuration.
  Nearest expiry: 2026-12-01 (in 19 days).
Expiring soon: 2 acceptance(s) expire within 30 days, the first on 2026-12-01 (in 19 days). From the day after its date an accepted finding counts again and can fail the check: fix it, or renew the acceptance in a reviewed change.
  2026-12-01  @octocat  OBAAF-GHA-005 .github/workflows/agent.yml:12 [job triage]  (ignore entry)
  2026-12-01  @octocat  OBAAF-GHA-020 .github/workflows/agent.yml:12 [job triage]  (ignore entry)
Other findings: 0 new, 0 cannot tell, 0 fixed by controls the checker verified.
```

What the lines mean:

- **Accepted risk** counts the findings whose state is accepted, whether a baseline entry or an ignore entry accepted them. A finding named by an entry that does not count is not accepted: it is counted as new, or as cannot tell when it has controls and none of them is known to be missing. With nothing accepted the line reads `Accepted risk: none.`
- **One line for each owner**, with the number of findings they accepted, by severity, and the first date on which one of their acceptances runs out. The owner who accepted most comes first. Two spellings are one owner when they differ only in the case of the letters A to Z, because `@Octocat` and `@octocat` are one account to GitHub, or in how an accented letter is stored; the owner is shown as spelt on the first of their findings in order of file and line. Nothing else is merged: the checker does not know that two different names are one person, and it does not add up two addresses that only look alike. The text report lists ten owners and says how many more there are; JSON lists all of them.
- **Expiring soon** lists the acceptances that run out within 30 days, the soonest first, ten at most in text. An acceptance is valid on its date and stops on the day after. Nothing else warns: on that day the finding counts again, and a gate that passed fails. `--expiry-warning DAYS` changes the window, and `--expiry-warning 0` turns the list off. The list never changes the exit status.
- **Other findings** gives the other three states in one line: new, cannot tell, and fixed.
- **Baseline entries that no longer match a finding** and **Errors**, when there are any, are each counted in one more line, because both can fail a check whose findings are all accepted. The entries are listed further down and the errors straight after these lines. Something the checker could not read fails the check whatever `--fail-on` says.

These lines do not say whether the check passed. The exit status does: the report is not given `--fail-on`, and never has been.

The days are counted from the day the check ran (`asOf` in JSON), and every acceptance in a report is judged on that one day, also when the check crosses midnight. The lines the report had before are still there, below these, with four differences. A finding ignored by configuration is listed with its owner (`ignored: RULE path:line - accepted by OWNER until DATE: REASON`). The `obaaf baseline migrate` command printed for an old baseline repeats the options the check was given, where a line told the reader to add them. Where a file's path heads its findings, a character that does not print (a line break, a tab, a no-break space) is written as an escape, as everywhere in the report; the path is then printed without quotes only if what is left is made of visible ASCII characters and nothing else (letters, digits and punctuation, no space), and in quotes otherwise. Every line of text that the checker writes in its own words has a space in it and none begins with a quotation mark, so a directory named like a line of the report cannot pass for one, whether it is written with spaces or with characters that only look blank. And the Jenkins coverage lines show a line break or another character that does not print as an escape, as the rest of the report already did. The older line `Baseline: N finding(s) accepted by the baseline, M new.` is unchanged, and its "new" is every finding the baseline does not accept, the ones the checker cannot tell about included, so M can be larger than the count of new findings in the first lines.

**JSON** has the same numbers in `acceptedRisk`, before the findings: `asOf`, `total`, `bySeverity`, `bySource` (`baseline` and `ignore`), `owners` (each with `owner`, `total`, `bySeverity` and `nearestExpiry`), `nearestExpiry`, `daysToNearestExpiry`, and `expiringSoon` (`withinDays`, `total`, and `findings`, each with its rule, severity, path, line, job, owner, expiry date, `daysLeft` and source). The `acceptance` of a finding has `daysLeft` when it is valid. Every field earlier versions wrote is still there under the same name.

**SARIF** says it in four places, because readers of SARIF differ in what they read:

- The run's `properties` hold `obaaf-accepted-risk`, the same object as `acceptedRisk` in JSON, and `obaaf-summary`.
- The run's `invocations[0].toolExecutionNotifications` begins with the accepted risk as a sentence. After it come, when there are any: a warning for acceptances expiring soon, one error for each thing the checker could not read (and `executionSuccessful` is then `false`), a warning for a baseline in the old format and for each baseline entry that no longer matches a finding, and the notes.
- An accepted finding is a result with a suppression: `"suppressions": [{"kind": "external", "status": "accepted", "justification": "Accepted by @my-org/build until 2027-03-31: ..."}]`, and the owner, reason, date and days left as data in `properties` under `obaaf-acceptance`. Every other result has `"suppressions": []`, which is how SARIF says a result is not suppressed; that includes a finding named by an entry that does not count.
- The result's message says the same in words after the finding's own sentence, then why an entry does not count, then the controls with their verdicts. The controls are also data, in `properties` under `obaaf-controls`.

**What GitHub code scanning shows of this.** GitHub's page on [its SARIF support](https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning) (read on 2026-11-12) lists the fields code scanning uses, and says the rest are ignored. Suppressions, invocations and their notifications, `baselineState`, and the property bags of a run and of a result are not on the list. So, going by that page, an accepted finding uploaded to code scanning is an open alert like any other, and what tells a reader that it was accepted is the sentence in its message; the accepted-risk total, the expiry warning, the notes and a file that could not be read are not shown there at all. No upload was made to check this. Two things follow. Dismissing an alert in GitHub and accepting a finding in OBAAF are separate records, and only the second has an expiry date that fails a gate. And a team that reads only code scanning should keep the step that runs `obaaf check` able to fail, because that is how a file the checker could not read shows: the command exits 1 for one whatever `--fail-on` says.

<a id="baseline"></a>
## Adopting the checker without hiding regressions

A project that adopts the checker with existing findings usually starts in reporting mode (`--fail-on never`). Reporting mode lets new findings in unnoticed. A baseline keeps the existing findings visible while failing on anything new. [From a report to a gate](from-report-to-gate.md) has the whole path, one step at a time; [Upgrading](upgrading.md) has what changes when you move to a newer OBAAF. The command:

```bash
# record today's findings, once, in somebody's name
obaaf check . --write-baseline .github/obaaf-baseline.json \
  --owner @my-org/build --reason "Inherited on adoption; tracked in issue 12" --expires 2027-03-31
obaaf check . --baseline .github/obaaf-baseline.json --fail-on low
```

With `--baseline`, a finding that a valid baseline entry accepts is still reported, with who accepted it and until when. It is marked `(baseline)` in text, `"baselined": true` and `"state": "accepted"` in JSON, and `baselineState: unchanged` with an accepted [suppression](#accepted-risk) in SARIF, and it does not fail the check. Every other finding at or above `--fail-on` fails it. So does a baseline entry at or above `--fail-on` that no longer matches any finding: run `--write-baseline` again and commit the result, so the improvement is locked in and the finding cannot come back unnoticed.

An entry looks like this:

```json
{
  "rule": "OBAAF-GHA-005",
  "severity": "high",
  "path": ".github/workflows/agent.yml",
  "job": "triage",
  "kind": "secrets",
  "facts": { "secrets": ["MODEL_API_KEY"] },
  "owner": "@my-org/build",
  "reason": "Inherited on adoption; tracked in issue 12",
  "expires": "2027-03-31"
}
```

What an entry accepts:

- **Exactly the finding its fields describe**: the rule, the file, the job and step, which of the rule's cases it is (`kind`), and the values it is about (`facts`: which secrets, which triggers, which action). There is no fingerprint beside the text, so the lines a reviewer reads in a diff are the acceptance. A job that receives one more secret is a different finding and counts as new.
- **Not its line number, and not the wording of a rule's message.** Moving code does not disturb a baseline, and neither does a release of OBAAF that words a rule's message differently. There are three exceptions, where text is the finding:
  - *OBAAF-GHA-003 (an agent job can write)*: why the job is an agent job is one of its facts, as the text the checker shows (`uses anthropics/claude-code-action`, `runs an agent CLI in 'Agent'`, `set by OBAAF_LANE`). When that text changes, the finding counts as new: another recognised action, a command in another step, a declaration added where the agent was recognised before, or a later release that words the reason differently. The text is not a description of the agent. Another command in a step of the same name, a second agent added after the first, and any change of agent in a job that is declared an agent job all leave it as it was, and the acceptance still covers the job. 0.3.0 behaved the same way.
  - *OBAAF-INS-001 (hidden characters)*: each character is a fact together with a digest of the line it is on. A line ends at a line feed or a carriage return and nowhere else: a form feed, a vertical tab or U+2028 does not end it. A line that moves up or down is the same finding. The same character with any other text on its line is another finding, because what a direction override does depends on the text beside it. Text on the lines before and after is not part of it.
  - *Jenkins findings* have no `kind` or `facts` yet. They are identified by their message (`"message": "..."` in the entry), line numbers in it included, so moving code or a change of wording does disturb them.
- **At the severity it was accepted at, or lower.** If the finding is now more severe than the entry says, the entry does not cover it.
- **One finding per entry.** Two findings that differ only in their line need two entries.
- **A step by its name.** A finding on a step names it by the step's `name`, else its `id`, else the action it uses, else its position (`step 3`). Give a name to a step that carries an accepted finding, or a step inserted above it makes the finding a new one.

Writing a baseline again never renews an acceptance by itself. Entries of the file being replaced that are still valid keep their own owner, reason and expiry date (and are written at the finding's present severity, if that is lower than it was). Only findings that no valid entry accepts are written with the `--owner`, `--reason` and `--expires` you give, and if there are any and you give none, nothing is written. So a diff of the baseline shows who accepted what, why, and until when, one entry at a time. `--write-baseline` replaces a baseline: it does not write over a file that exists and is not one. Findings already ignored by configuration are not written to the baseline. Findings whose ignore entry has expired or does not count are not newly accepted either: renew, complete or remove the entry instead. An entry for a finding that has since been given an ignore entry is not stale.

The baseline is a list of accepted risks, so review changes to it like changes to the workflows: put it under CODEOWNERS. Prefer an `ignore` entry for a finding you have decided does not apply.

<a id="baseline-migrate"></a>
### A baseline written by 0.2.0 or 0.3.0

Those versions wrote `obaaf-baseline/v0.1` files, whose entries name no owner, reason or expiry date. The file is still read, and each entry still finds its finding, but none of them accepts one: with `--fail-on low` the check fails until the file is converted. The report says so once, with the command, which repeats the `--config` and `--platform` the check was given:

```bash
obaaf baseline migrate .github/obaaf-baseline.json \
  --owner @my-org/build --reason "Inherited on adoption; tracked in issue 12" --expires 2027-03-31
```

`migrate` runs the check on the path you give after the file name (the current directory if you give none; use the path the baseline was written for), carries over the findings the old file covers that are still found, and gives them the owner, reason and date you state. It accepts nothing the old file did not cover, and tells you which old entries no longer match and how many findings are outside the baseline. It replaces the file in place unless you give `--output`. Convert with the first version that has this command: an old entry matches on the exact wording of its finding, and later versions may word messages differently.

<a id="ignore"></a>
## When a finding does not apply

Suppress a finding you have reviewed with an expiring `ignore` entry. Every entry needs a rule, a path, an owner, a reason and an `until` date, and the path may not match everything:

```yaml
# .github/obaaf.yml
ignore:
  - rule: OBAAF-GHA-013
    path: .github/workflows/ci.yml
    job: build
    owner: "@my-org/build"
    reason: Reviewed fork selector and ephemeral runner lifecycle, see issue 42
    until: 2027-01-31
```

An ignore entry is an acceptance, so [the same three things](#lifecycle) are enforced. A configuration file whose entries have no `owner` (every file written for 0.3.0 or earlier) still loads, but those entries ignore nothing until an owner is added, and neither does an entry dated more than 366 days ahead; the report says which. An entry with no rule, path, reason or `until`, or with an `until` that is not a plain date (`YYYY-MM-DD`), is a configuration error and the check does not run.

This is also how to record a reviewed runner pool without suppressing findings
for other jobs. GHA-013 distinguishes:

- A known self-hosted pool, including a literal matrix containing one: high for
  untrusted or agent work.
- An unresolved expression explicitly naming both a standard hosted label and a
  self-hosted alternative: informational, because the selected runner is unknown.
- Other unknown labels or runtime inputs, such as `${{ inputs.runner }}`: medium.

The informational result does not certify a selector as fork-safe or a pool as
ephemeral. Verify where outside contributions execute and how the runner is
destroyed, then record evidence and a review expiry with an entry like the above.
Do not use an ignore entry merely to obtain a green check.

## Trying unreleased checker changes

A release on PyPI does not contain changes merged after it; the changelog's
"Unreleased" section lists them. Everything described on this page is in version
0.3.0, except the states of a finding, the owner, reason and expiry date that an
acceptance needs, and `obaaf baseline migrate`, which are not released yet. Use a separate environment and install a reviewed, full Git commit SHA
when piloting unreleased code:

```bash
python -m pip install "obaaf @ git+https://github.com/Obaaf/OBAAF.git@<reviewed-full-commit-sha>"
obaaf check . --lanes
obaaf check . --fail-on never
obaaf check . --fail-on authority:medium
```

Replace the placeholder with an actual reviewed commit. A source install reports
the version of the last release until the version is changed, so record the source
SHA as well as the version.
For GitHub Actions, `Obaaf/OBAAF/actions/setup-obaaf@<reviewed-full-commit-sha>`
installs that exact checkout using its dependency constraints. A new PyPI release
is a separate maintainer action after validation.

## Jenkins

Jenkinsfiles use the same file. `jenkins.files` adds pipelines with other names (globs from the
repository root), `jenkins.exclude` leaves out test fixtures, `agents.steps` names shared-library
steps that run an agent, and lane overrides and ignore entries name a stage as `file#stage` and
`job: <stage>`. See [Jenkins](jenkins.md).

## Egress

`OBAAF_EGRESS` records the egress policy an agent job is meant to run under. It documents intent, it is not enforcement. See `OBAAF-GHA-020`, [the controls the checker reads](#controls) and the agent lane templates for how egress is enforced.

## Reference

The full rule list, with the requirement and fix for each, is in [the pipeline checker rules](../spec/checker-rules.md).
