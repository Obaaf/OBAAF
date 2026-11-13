# The settings audit: `obaaf audit`

*Status: not in a release yet. The command reads a repository's GitHub settings, records what it read and what it could not, and applies fifteen rules, `OBAAF-SET-001` to `OBAAF-SET-015`: twelve compare a setting with what the repository's workflow files use, and three read settings only. A rule reports a finding, or "cannot tell" when a setting it needs was not read. With `--expected` it also reports [drift](#drift): a difference between the settings now and a snapshot you committed. **Every rule reads at least one setting that GitHub shows only to a token, most of them only to an administrator's, and the audit has never been run with such a token**: for those settings the rules are tested against answers written by hand. Five rules (`001`, `002` and `006` to `008`) can still give findings from what anyone may read. What has and has not been run against GitHub is listed [at the end](#what-has-been-run-and-what-has-not).*

`obaaf check` reads workflow files. Some of what decides whether a workflow is safe is not in any file: which branches may use an environment, who may bypass a ruleset, which checks are required, which events GitHub lets start a workflow. In the first adopter's first two days every real incident was one of those settings, and `obaaf check` saw none of them.

`obaaf audit` reads those settings through GitHub's REST API and compares them with the workflow files in a clone. It sends GET requests only. Whatever it could not read is listed by name with the reason, and a rule that needed it answers "cannot tell", so that "not read" is not mistaken for "nothing wrong". Where that is known not to hold yet, [the rules' limits](#what-the-rules-take-on-trust-and-what-they-do-not-do) say so.

## Run it

In a clone of a repository on github.com:

```bash
obaaf audit                          # OWNER/REPO from the origin remote; the workflow files from this clone
obaaf audit DIR --repo OWNER/REPO    # or name the clone and the repository
```

With no token this reads what GitHub shows anyone about a public repository: the repository itself, its rulesets and their rules, the rules in force on the default branch, whether GitHub calls that branch protected, and its environments with the branches that may deploy to each. That is enough for the open environment (`OBAAF-SET-001`) and, unless the branch has a classic protection rule whose checks GitHub does not show as enforced, for the three rules about required checks (`OBAAF-SET-006` to `OBAAF-SET-008`). `OBAAF-SET-002` can answer for a job that reads a secret. The other rules read a setting GitHub does not show without a token: where a workflow depends on it they say "cannot tell", naming the setting, and where none does they say "does not apply". On this repository that was 6 rules of 15 saying "cannot tell".

The report begins with the findings, then what the rules could not tell, then one line for every rule, then everything that was read and not read. This is the report for this repository, made on 2026-11-13 with no network from GitHub's answers of 2026-11-12 06:32 UTC to a caller with no token (they are kept as a test recording) and the workflow files as they were on 2026-11-13. It is shortened where `...` stands, and its second line, which says where the settings came from, is left out:

```text
Settings audit of Obaaf/OBAAF
Compared with 6 workflow files in the directory ".".

FINDINGS: 1 (0 high, 1 medium, 0 low). CANNOT TELL: 6, from 6 of 15 rules. "Cannot tell" is never a pass: nothing is established there.

  OBAAF-SET-008  A pull-request job whose failure does not block a merge
    MEDIUM  branch "main": job .github/workflows/ci.yml#dependency-lock
            .github/workflows/ci.yml#dependency-lock runs on every pull request into "main" and reports the check "dependency-lock", which is not required (8 checks are required there). A pull request can merge while the job is failing. The checks of the classic protection rule are taken from what GitHub shows anyone; the rule itself was not read.
    Fix: Add the job's check to the required checks. If the job is advisory, give it `continue-on-error: true` at job level, which says in the workflow that its failure is not meant to block.

CANNOT TELL: 6. A setting or a file the rule needs was not read, or was not in a form the rule understands.
  OBAAF-SET-004  Those who author changes can bypass the branch's rules
    CANNOT TELL  branch "main": classic protection
            Whether the branch has a classic protection rule, and whether administrators are held to it, is not known: "Classic branch protection" was not read (no_token).
  ...

RULES: 15, one line each. A rule with no finding says what it compared, or why it had nothing to compare.
  OBAAF-SET-001  no finding: 2 environments that jobs or the configuration name
  OBAAF-SET-002  does not apply: no job that outsiders' events can start names an environment
  ...
  OBAAF-SET-008  1 finding
  OBAAF-SET-009  cannot tell (1)
  ...

WHAT WAS READ. The rules above rest on this; what was not read is listed first.

NOT READ: 9 of 15. Nothing is known about these; they were not checked.
  Not requested, because no token was given and GitHub does not show these without one. Each is followed by what GitHub's reference says a token needs:
    Classic branch protection                                    "Administration" repository permission (read)
    Names of the secrets in each environment                     "Environments" repository permission (read)
    ...

READ: 5 of 15
  The repository
      public repository, default branch main, owned by the organisation Obaaf
  Rulesets and their rules
      no ruleset applies to this repository
  Rules in force on each audited branch
      "main": no active rule
  Each audited branch, as anyone may see it
      "main": GitHub calls it protected; required checks: Build resource site, actionlint, package, setup-action (macos-latest), setup-action (ubuntu-latest), setup-action (windows-latest), test (3.10), test (3.13) (enforcement: everyone)
  Environments: reviewers and which branches may deploy
      "github-pages": may deploy: branch main; no required reviewers
      "pypi": may deploy: tag v*; reviewers: FehintolaObafemi, Ofonna-N, seanudeke (self-review prevented); administrators may bypass these rules: no

DOES NOT APPLY: 1 of 15
  Who may bypass each ruleset
      no ruleset applies to this repository

15 settings: 5 read, 0 partly read, 9 not read, 1 that do not apply. ...
```

That one finding is real: this repository's own job `dependency-lock` runs on every pull request and is not among its eight required checks. It is a setting, and only a maintainer can change it.

With a token it tries everything in [the table below](#what-it-reads). The token is taken from the environment, never from the command line:

```bash
GH_TOKEN=... obaaf audit --repo OWNER/REPO
obaaf audit --repo OWNER/REPO --token-env AUDIT_TOKEN   # another variable
obaaf audit --repo OWNER/REPO --no-token                # ignore any token that is set
```

Save what was read, and report from the file later with no network:

```bash
obaaf audit --repo OWNER/REPO --snapshot-out settings.json
obaaf audit --from-snapshot settings.json
```

Other options: `--branch NAME` audits another branch as well as the default one (repeatable); `--format json` prints the results, the rules and the snapshot as one JSON document (`obaaf-settings-audit/v0.1`) instead of the text report; `-o FILE` writes the report to a file; `--no-fixes` leaves the fix out of each finding; `--record DIR` also saves GitHub's answers as they arrived, for a bug report (see [Recordings](#recordings)).

What ends the command with status 1 is chosen with three options:

- `--fail-on high|medium|low|never` (default `medium`, as for `obaaf check`): a finding at or above that severity.
- `--fail-on-cannot-tell`: any rule that answered "cannot tell". Without a token several rules do (4 of 15 on this repository), so this is for a run with a token that can read the administrative settings.
- `--fail-on-unread`: any setting that applies and was not read in full.

Exit codes:

| Code | When |
| --- | --- |
| 0 | The audit ran and no finding reached `--fail-on`, and with `--expected` nothing drifted. Rules may have answered "cannot tell" and settings may not have been read: the first line of the findings counts the former, and the latter are under NOT READ, after the list of rules |
| 1 | A finding at or above `--fail-on`; or `--fail-on-cannot-tell` and a rule could not tell; or `--fail-on-unread` and something was not read in full; or `--expected` and the settings differ from that snapshot, or something it holds could not be read now, or nothing could be compared (see [Drift](#drift)); or not even the repository could be read; or an output file could not be written; or a rule or the command failed in a way it did not foresee (it says so, and says that nothing was established) |
| 2 | A usage error, or a snapshot file that cannot be used (also the one given to `--expected`, or one of another repository or server) |

**A settings finding cannot be accepted yet.** `obaaf check` has acceptances with an owner, a reason and an expiry date; `obaaf audit` has none. Every finding names a change to a setting or a workflow that clears it, and the audit sees the change the next time it runs. Where that change is one a team will not make (a bypass kept for emergencies is still reported, at medium), the finding stays in the report, and the only way to keep it from failing a build is a higher `--fail-on`, which hides every other finding of that severity too.

### Which workflow files are compared

Twelve rules compare settings with workflow files, so the command has to know whose files it is reading. It reads them from the directory it is given (the current directory by default) when that directory is the top level of a clone whose origin remote names the repository being audited. A directory inside a clone does not count: its `.github/workflows` is not that repository's. It also reads them when you name the directory on the command line and it is not such a clone: whoever names a directory says whose files they are, and the report says that it took your word. What it does not do is compare the settings of `--repo OWNER/REPO` with the workflows of whichever clone the command happened to be started in: then the report says the workflow files were not read, the twelve rules answer "cannot tell", and the three that read settings only still answer. With `--api-url` (another server) a remote on github.com proves nothing, so there the directory always has to be named.

The files are read with the parser `obaaf check` uses, and the checker's configuration (`.github/obaaf.yml`) is read for `protected_secrets`. A workflow file that does not parse is counted in the report's third line, and so is one GitHub would refuse in a way the audit knows of (a job that is not a mapping, a job with neither `runs-on` nor `uses`, an event with both `branches` and `branches-ignore`, `tags` and `tags-ignore`, or `paths` and `paths-ignore`): none of its jobs runs, so none is counted as reporting a check; and every rule that reads workflow files says "cannot tell" for it. A configuration that cannot be read protects nothing that the audit can see: the two rules that use it say "cannot tell".

### In a workflow

A workflow's own token is refused the administrative settings, as it would be with no token, but it has its own rate limit (1,000 requests an hour for the repository, against 60 an hour for each IP address with no token), which matters on shared runners:

```yaml
permissions:
  contents: read
steps:
  - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
    with:
      persist-credentials: false
  - run: obaaf audit --repo "$GITHUB_REPOSITORY" --fail-on high --snapshot-out settings.json
    env:
      GITHUB_TOKEN: ${{ github.token }}
```

The checkout is what gives the rules the workflow files. With the workflow's own token the rules that need administrative settings answer "cannot tell". With `--fail-on high`, as here, the job fails on little: an environment open to every branch with no required reviewers, a job outsiders can start that names such an environment, and the high findings a better token would add. The findings about required checks, and an open environment behind reviewers, are medium; use `--fail-on medium` to fail on those.

[`.github/workflows/settings-audit-live.yml`](../.github/workflows/settings-audit-live.yml) is this repository's own use of it. A report printed in a job is in that job's log, which anyone can read for a public repository: with a token that may read the collaborators, the report says how many accounts hold each role (never who they are). To read the settings marked "Token" in the table from a workflow, the token has to come from somewhere else (a fine-grained personal access token or a GitHub App with the read permissions named there, stored as a secret in an environment limited to the default branch). OBAAF does not create tokens and does not ask for more than read access.

## The rules

Twelve rules compare a setting with something a workflow in the repository uses or assumes (plan decision F-23). Three read settings only: `OBAAF-SET-004` (who may bypass a branch's rules), `OBAAF-SET-005` (whether its required approvals can be given) and `OBAAF-SET-013` (whether a workflow can give one: a workflow on any branch can ask for the token, so the files here decide nothing). They are here because the checks and reviews they concern are what every workflow's result feeds, and they answer even when no workflow file was read. No rule judges a setting for its own sake: this is not a checklist for an organisation, and [the landscape](landscape.md) names tools that are.

A rule gives results about one thing at a time (an environment, a branch, a job), and each result is one of two kinds:

- a **finding**, with a severity (high: a way in is open; medium: a safeguard is missing or cannot work; low: hardening), when what was read shows the problem;
- **cannot tell**, when a setting or a workflow file the rule needs was not read, or was read and is not in a form the rule understands. It names the setting that was missing, or says only what is not known when a rule arrived from GitHub without its parameters. It is never counted as nothing wrong.

A rule with neither gets one line saying what it compared ("no finding: 8 required checks and the names the jobs report") or why it had nothing to compare ("does not apply: no job names an environment"). The report never says "pass": a rule that found nothing has shown only that.

| Rule | What it reports | Highest severity | Settings it reads | Compared with |
| --- | --- | --- | --- | --- |
| `OBAAF-SET-001` | An environment's secrets can be reached from any branch | high | `environments`, `environment_secrets` | the environment each job names |
| `OBAAF-SET-002` | A job outsiders can start gets an environment that asks nobody | high | `environments`, `environment_secrets`, `repository` | jobs started by pull_request_target, issue and comment events |
| `OBAAF-SET-003` | A secret kept behind an environment is also stored where every job can read it | high | `environment_secrets`, `repository_secrets`, `organization_secrets`, `environments` | protected_secrets in .github/obaaf.yml, and the secrets jobs read |
| `OBAAF-SET-004` | Those who author changes can bypass the branch's rules | high | `ruleset_bypass_actors`, `branch_rules`, `branch_protection`, `branches`, `rulesets`, `collaborators`, `repository` | nothing in the workflow files: it reads who may skip the checks and reviews their results feed |
| `OBAAF-SET-005` | Required approvals cannot be given | medium | `branch_rules`, `branch_protection`, `branches`, `collaborators` | nothing in the workflow files: it reads the approvals a branch requires and who can give them |
| `OBAAF-SET-006` | A required check that no workflow job reports | medium | `branch_rules`, `branch_protection`, `branches`, `workflow_permissions` | the check names the jobs report |
| `OBAAF-SET-007` | A required check that does not report on every pull request | medium | `branch_rules`, `branch_protection`, `branches`, `workflow_permissions` | the triggers of the job that reports each required check, and their filters |
| `OBAAF-SET-008` | A pull-request job whose failure does not block a merge | medium | `branch_rules`, `branch_protection`, `branches` | the jobs that run on every pull request |
| `OBAAF-SET-009` | An Actions policy blocks an event a workflow uses | medium | `actions_policies` | the events under each workflow's `on:` |
| `OBAAF-SET-010` | A pull_request_target workflow and GitHub's default policy of 2026-12-02 | medium | `actions_policies`, `repository` | workflows started by pull_request_target |
| `OBAAF-SET-011` | A reusable workflow is passed a secret its caller cannot read | medium | `environment_secrets`, `repository_secrets`, `organization_secrets` | the secrets a job passes to a reusable workflow |
| `OBAAF-SET-012` | Jobs with no permissions block get a token that can write | medium | `workflow_permissions` | jobs that declare no `permissions` |
| `OBAAF-SET-013` | A workflow can give a required approval | medium | `workflow_permissions`, `branch_rules`, `branch_protection`, `branches` | nothing in the workflow files: a workflow on any branch can ask for the token, so it reads whether workflows may approve and the approvals each branch requires |
| `OBAAF-SET-014` | Fork pull requests run on the repository's runners or with its secrets | high | `fork_pull_requests`, `repository` | the runners the jobs name (a fork's pull request runs its own copy of the workflows) |
| `OBAAF-SET-015` | Pinning actions to a commit: the setting and the workflows disagree | medium | `actions_permissions` | the actions each job's steps use |

### The six incidents

The rules were written from the settings behind the first adopter's incidents. Each is caught in `tests/test_settings_rules.py` from a recorded answer. For four of the six that answer was written by hand: three need an administrator's token (`004`, `009`, `011`), and `005` needs the count of accounts with write access, which a workflow's own token was given for this repository on 2026-11-12.

| Incident | Rule | Can it be seen with no token? |
| --- | --- | --- |
| A protected environment created with no branch restriction | `OBAAF-SET-001` (and `OBAAF-SET-002` for a job that pull requests or comments can start; `OBAAF-SET-003` when the secret is also stored for every job) | `OBAAF-SET-001`: yes, for a public repository. `OBAAF-SET-003` needs the names of the secrets |
| A bypass on the branch ruleset that lets the account that authors changes skip every required check | `OBAAF-SET-004` | No. GitHub shows the bypass list only to someone who could change it. With a token it also says whether the token's own account can bypass |
| Required approvals that the one shared account could never give | `OBAAF-SET-005` | No: it needs the number of accounts with write access |
| A required-checks list that named one check of the eleven that ran | `OBAAF-SET-008` (and `OBAAF-SET-006`, `OBAAF-SET-007` for a required check that nothing reports or that does not report on every pull request) | Yes, for a public repository, as far as GitHub shows a classic rule's checks |
| An Actions policy that allowed two events for a workflow that used a third | `OBAAF-SET-009` | No. GitHub's reference asks for write access even to read the policies, so this will usually be "cannot tell", with the events the workflows use listed for an administrator to compare |
| A reusable workflow that could not see its caller's environment secrets | `OBAAF-SET-011` | No: it needs the names of the secrets |

Also asked for by the plan: the default token permissions (`OBAAF-SET-012`), workflows that may approve pull requests (`OBAAF-SET-013`), approval for fork pull requests (`OBAAF-SET-014`), the pinning requirement (`OBAAF-SET-015`), and the `pull_request_target` change of 2026-12-02 (`OBAAF-SET-010`). For that last one, a public repository whose workflows use the event gets a finding (the policies were read and none that applies allows it), a "cannot tell" that names the date and the workflows (the policies were not read), or "no finding" when a policy that applies was read: one that allows the event, or one that blocks it, which `OBAAF-SET-009` reports. So an adopter learns that the change concerns them even when the policy cannot be read.

### What each rule looks at, exactly

- **`OBAAF-SET-001`.** Every environment that a job names with a fixed name, or that `protected_secrets` names. "Any branch or tag" is high with no required reviewers and medium with them. A branch pattern made only of `*` and `/` counts as no limit. Any other wildcard, and any tag pattern, is medium when there are no reviewers (anyone with write access can push a branch or tag of that name; whether a ruleset stops them is not read) and is not reported when there are. A limit to a branch that was not audited is "cannot tell" when there are no reviewers (`--branch NAME` has its rules read). "Protected branches only" is "cannot tell": which branches GitHub counts as protected is not read. An environment the settings show to hold no secret is low whatever its limit, and the finding says that what it guards was not read. An environment that a job names and the settings do not have is medium. A job that names its environment with an expression is "cannot tell", for this rule and the next.
- **`OBAAF-SET-002`.** Jobs that `pull_request_target`, `issue_comment`, `issues`, `workflow_run` and the other events people without write access can cause may start (the same list `obaaf check` uses; a job in a reusable workflow of this repository is reached by its callers' events), that name an environment with no required reviewers, where the environment holds a secret or the job reads one. Those events run as the default branch: for `pull_request_target` since 2025-12-08, when GitHub began to evaluate environment rules for it "against the default branch" whatever the pull request's base ([changelog of 2025-11-07](https://github.blog/changelog/2025-11-07-actions-pull_request_target-and-environment-branch-protections-changes/), read 2026-11-13; GitHub Enterprise Server may differ). So an environment whose branch limit names other branches and not the default branch is not reported. A caller of a workflow that was not read is "cannot tell". This is the check behind a sentence in OBAAF-GHA-001, which reports such a job at medium "because environment secrets are released only after required reviewers approve".
- **`OBAAF-SET-003`.** With `protected_secrets` in `.github/obaaf.yml`: a repository or organisation secret whose name matches an entry (high), an environment the entry names that does not exist (high), and an entry that matches nothing stored in its environment (low). Without it: a secret stored both in an environment and for every job, when a job reads it or can read every secret (medium). This is the part of OBAAF-GHA-024 that a workflow file cannot show.
- **`OBAAF-SET-004`.** Rulesets in force on an audited branch that ask for a check or a review, and its classic protection rule. A ruleset that only forbids deleting or force-pushing is not this rule's subject. A bypass that is not limited to merging a pull request is medium, and high when it covers every account that can push: by role, from the counts of collaborators, or because one account can push, it is an administrator, the repository belongs to an organisation and organisation administrators may bypass. A role in the list is counted for the accounts that hold exactly that role; whether GitHub extends it to higher roles is not established. A bypass only when merging a pull request is low. When the list was not read, what GitHub says of the token's own account is reported and the rule still says "cannot tell" for the list; any word GitHub uses there other than "always" and "never" is read as the narrower bypass. A classic rule that does not hold administrators to it is medium, high when every account that can push is an administrator; a classic rule that names who may skip its reviews is medium. Where the collaborator counts were not read, a bypass is reported at medium with a "cannot tell" for how many it covers.
- **`OBAAF-SET-005`.** The approvals a branch requires against the accounts with write access, less one for the author. A `pull_request` rule that came without its parameters is "cannot tell", not "0 approvals".
- **`OBAAF-SET-006` to `OBAAF-SET-008`.** The required checks, from the rules in force and from classic protection, against the names each job reports. A job reports its `name`, or its id. A matrix job reports `name (values)`, and the values are compared when the matrix is written out as lists of text or whole numbers with no `include` or `exclude`. A job that calls a workflow in this repository reports `name / called job`. A job in a workflow that is only called does not report under its own name. Where the names cannot be written out (an expression in the name or the matrix, a called workflow that was not read), a required check that fits their form is "cannot tell". `OBAAF-SET-006` reports a required check only when it is tied to GitHub Actions, every workflow file was read, and no job's token may write checks or statuses (a step with such a token can report a check under any name); a requirement tied to another app is "cannot tell". `OBAAF-SET-007` looks at how the job that reports a required check comes to run: a paths filter, or only some kinds of pull request activity (`types:` without both `opened` and `synchronize`), is a finding, and so is a trigger that never runs on a pull request's commit when no job's token may write checks or statuses (otherwise a step could report it, and that is "cannot tell"); a branch pattern, or a workflow that only a dispatch starts, is "cannot tell". A push trigger with no filter counts as running for every pull request, which holds for a branch in the repository and not for a fork. `OBAAF-SET-008` counts a job when its workflow has a `pull_request` or `pull_request_target` trigger with no paths filter, a branches filter that names the branch plainly or none (a `branches-ignore` that names it plainly leaves the job out), and no `types:` that leaves out `opened` or `synchronize`; where a pattern decides (`*`, `?`, `[`, `]`, `+`, or a `!` entry anywhere in the list), it is "cannot tell". Every check such a job reports must be required: one check of a matrix or of a called workflow being required leaves the others free to fail, and the finding names the checks nobody requires. A name required from another app (alone, or beside a requirement from any app) is "cannot tell": GitHub says a status from a different app prevents merging and that the most restrictive version of a rule applies, and how it weighs a check of that name from GitHub Actions there is not established. `OBAAF-SET-006` is "cannot tell" for such a requirement, and `OBAAF-SET-007` leaves it to `OBAAF-SET-006`. Where the job's check names cannot all be written out it is "cannot tell". It leaves out a job with `continue-on-error: true` at job level. Where no check at all is required it gives one finding for the branch, not one for each job.
- **`OBAAF-SET-009` and `OBAAF-SET-010`.** A policy is read only in the one form the reader has met: a list of workflow paths to include and exclude, and rules that carry a list of allowed events or a list of allowed actors. An enforced policy that applies to a workflow file and does not list one of its events is medium; one in evaluate mode is low. A disabled policy, and a policy whose rules are only about who may start a workflow, is left alone. A policy with a rule in any other form, or whose paths or enforcement are, is "cannot tell" for both rules. `workflow_call` is not counted as an event.
- **`OBAAF-SET-011`.** A secret a job passes by name to a reusable workflow, under `secrets:` or as an input under `with:`, that is stored only in an environment: reported whatever the called workflow declares and wherever it lives, and cleared by no longer passing it. For `secrets: inherit` and a workflow in the same repository, the secrets the called jobs read are compared; a called job that declares the environment is not reported, and one that names its environment with an expression, or can read every secret, is "cannot tell". With `secrets: inherit`, a workflow in another repository is "cannot tell".
- **`OBAAF-SET-012`.** Jobs with no `permissions` anywhere, when the default for the token is read and write. A default GitHub gives in a word the rule does not know is "cannot tell".
- **`OBAAF-SET-013`.** Reported for a branch that requires approvals when workflows may approve pull requests, whatever the jobs in the files say: a workflow can ask for `pull-requests: write` whatever the repository's default, and anyone who can push a branch can add one there. With a code owner's review required as well, two or more approvals are still a finding (the workflow's approval counts towards the number), and exactly one is "cannot tell" (it is cleared where every file has a code owner, and the CODEOWNERS file is not read). Where a rule about the branch's reviews was not read in full and the count known is one, it is "cannot tell" too: the unread rule may ask for more approvals or for a code owner. That matters for OBAAF's own templates: the effect lane needs the same switch to open its pull request ([GitHub settings](github-settings.md)).
- **`OBAAF-SET-014`.** A fork's pull request runs the workflow files of its own commit, so it can add a job, name any runner and read any secret it is sent; the jobs in these files decide nothing on their own. In a public repository where approval is not required for all outside contributors: a finding when a job here names a self-hosted runner (the label `self-hosted`, or a matrix written out that names it), which shows the repository has one; a runner group alone does not, because a group can hold larger GitHub-hosted runners; otherwise "cannot tell", because whether the repository has self-hosted runners is not read. In a private or internal repository: a finding when fork pull requests run workflows and are sent secrets or a write token, whatever the jobs here do.
- **`OBAAF-SET-015`.** Steps that use an action from another repository. Local actions, container images and the reusable workflow a job calls are left out; whether GitHub's requirement covers those was not established.

### What the rules take on trust, and what they do not do

- **Actions policies have never been seen.** The form the rules read (`conditions.workflow_path.include` and `exclude`, a rule with `allowed_events` or `allowed_actors`) is the one in a recording written by hand for slice 2b.1. GitHub's pages on policies could not be re-read when the rules were written (2026-11-13: the session's requests for them were not answered). How GitHub matches a path pattern, whether `schedule` is an event a policy governs, and whether its default policy appears in the list are not established. A real policy with a rule, a scope or an enforcement in another form gives "cannot tell"; a real policy in this form with other semantics could give a wrong finding.
- **What GitHub does, as the rules' texts state it, was not re-read for this slice.** These sentences in findings and fixes rest on the author's knowledge of GitHub, not on a page read on a date: that an author cannot approve their own pull request and that only accounts with write access count; that a required check nothing reports stays pending, and that a workflow skipped by a paths filter leaves its required check pending; that a job skipped by `if:` reports as passed; that a job which calls a reusable workflow cannot declare an environment; which copy of a secret a job gets when it is stored in two places; that a workflow using an unpinned action is refused when pinning is required; that an organisation's owners administer every repository and are in the collaborator list; that a workflow's approval is not a code owner's; that a token with `checks: write` or `statuses: write` can report a check under any name, attributed to GitHub Actions; how GitHub names the checks of a matrix job and of a called workflow; whether `continue-on-error` is accepted on a job that calls a reusable workflow; that the events people without write access can cause, other than `pull_request_target` (see `OBAAF-SET-002` above), run as the default branch; that a fork's pull request runs the workflow files of its own commit; and that GitHub refuses a workflow file with a job that is not a mapping or a job with neither `runs-on` nor `uses` (GitHub's workflow syntax page, read on 2026-11-13, says it refuses both `branches` and `branches-ignore` on one event, and the same for `tags` and `paths`; it does not call `runs-on` required). A reviewer who knows one of these to be wrong should say so on the pull request.
- **The date and reach of the `pull_request_target` change** are as [the landscape](landscape.md) recorded them on 2026-11-12 from GitHub's changelog, which words the reach in two ways.
- **Check names come from the workflow files, not from GitHub.** The audit does not read recent check runs, so a job that exists and never runs, or a check reported by something other than a workflow job, is outside what it sees.
- **`15368` is taken to be the id of the GitHub Actions app**, the value in GitHub's own answers for the first adopter's eleven required checks.
- **Role ids in a bypass list** are read as 5 admin, 4 write, 2 maintain, the ids GitHub's built-in roles carry. The reference was not re-read for this.
- **A branch whose public view says `protection.enabled: false`** is taken to have no classic protection rule. That is what GitHub sent for a branch protected only by a ruleset on 2026-11-12, seen once.
- **Branch and tag patterns are not evaluated**, apart from the all-stars case. `releases/*` and `v*` are reported as patterns, not resolved against the branches that exist; a branch pattern on a trigger is "cannot tell" where it decides something.
- **Collaborator counts are what GitHub listed** with `affiliation=all`. An account that gets access another way would not be in them.
- **Known places where a rule says less than it could.** `OBAAF-SET-007` takes an unfiltered push trigger as running for every pull request, which a fork's pull request does not get. `OBAAF-SET-014` does not read whether the repository has self-hosted runners; where no job here names one it says "cannot tell". `OBAAF-SET-015` says nothing of a reusable workflow called at a branch or tag. `OBAAF-SET-001` reports an environment with no secret at low without knowing what trusts its name.
- **Not looked at:** custom deployment protection rules, tag rulesets, deploy keys, OIDC trust, organisation-wide settings beyond the rulesets and policies that apply here, and whether the reusable workflows another repository provides declare an environment.

## What it reads

Each setting has a stable key, which is its name in the snapshot. "Anyone" means GitHub's reference says the endpoint "can be used without authentication or the aforementioned permissions if only public resources are requested"; for a private repository a token is needed for everything.

| Key | What | Endpoints (all GET) | Who can read it, per GitHub's reference |
| --- | --- | --- | --- |
| `repository` | Visibility, default branch, owner | `/repos/{owner}/{repo}` | Anyone, for a public repository ("Metadata", read) |
| `rulesets` | Every ruleset that applies, from the repository and from above it, with its rules, conditions and enforcement status | `/repos/{owner}/{repo}/rulesets`, `/repos/{owner}/{repo}/rulesets/{id}` | Anyone, for a public repository ("Metadata", read) |
| `ruleset_bypass_actors` | Who may bypass each ruleset | the `bypass_actors` field of `/repos/{owner}/{repo}/rulesets/{id}` | Only a caller with write access to the ruleset. See [below](#the-bypass-list) |
| `branch_rules` | The active rules on each audited branch, from every level together | `/repos/{owner}/{repo}/rules/branches/{branch}` | Anyone, for a public repository ("Metadata", read) |
| `branches` | Whether GitHub calls the branch protected, and the required checks it shows publicly | `/repos/{owner}/{repo}/branches/{branch}` | Anyone, for a public repository ("Contents", read) |
| `branch_protection` | Classic branch protection: required reviews and checks, whether administrators are held to them | `/repos/{owner}/{repo}/branches/{branch}/protection` | Token: "Administration" (read) |
| `environments` | Each environment's reviewers, wait timer, whether administrators may bypass those, and which branches and tags may deploy to it | `/repos/{owner}/{repo}/environments`, `/repos/{owner}/{repo}/environments/{name}/deployment-branch-policies` | Anyone, for a public repository ("Actions", read) |
| `environment_secrets` | The names of the secrets in each environment | `/repos/{owner}/{repo}/environments/{name}/secrets` | Token: "Environments" (read) |
| `repository_secrets` | The names of the repository's secrets, which every workflow on every branch can read | `/repos/{owner}/{repo}/actions/secrets` | Token: "Secrets" (read) |
| `organization_secrets` | The names of the organisation secrets this repository receives | `/repos/{owner}/{repo}/actions/organization-secrets` | Token: "Secrets" (read) |
| `actions_permissions` | Whether Actions is on, which actions may run, whether pinning to a commit is required | `/repos/{owner}/{repo}/actions/permissions`, `/repos/{owner}/{repo}/actions/permissions/selected-actions` | Token: "Administration" (read) |
| `workflow_permissions` | What the workflow token may do by default, and whether workflows may approve pull requests | `/repos/{owner}/{repo}/actions/permissions/workflow` | Token: "Administration" (read) |
| `fork_pull_requests` | Whose fork pull requests need approval before workflows run; on a private repository, whether they get secrets and write tokens | `/repos/{owner}/{repo}/actions/permissions/fork-pr-contributor-approval`, `/repos/{owner}/{repo}/actions/permissions/fork-pr-workflows-private-repos` | Token: "Administration" (read) |
| `actions_policies` | Actions policies (workflow execution protections): who and which events may start which workflows, including policies from the organisation or enterprise that apply here | `/repos/{owner}/{repo}/actions/policies`, `/repos/{owner}/{repo}/actions/policies/{id}` | Token: "Administration" (**write**). See [below](#what-needs-more-than-read) |
| `collaborators` | How many accounts hold each role. Counts only; the list is not kept | `/repos/{owner}/{repo}/collaborators` | Token of someone with write, maintain or admin access, by the reference. On 2026-11-12 GitHub also answered this repository's own workflow token |

Without a token the audit does not ask for the settings marked "Token": GitHub's reference says they need one, and each request would count against the 60 an hour GitHub allows an address with no token. They are recorded as not read, with the reason `no_token`. A run with no token sends five requests, plus one for each ruleset and one for each environment that limits deployment to named branches or tags (seven for this repository).

Lists are asked for 100 entries at a time, by page number. A list counts as read only when a page with fewer than 100 entries and no link to a next page ends it, and, where GitHub says how many entries there are, when that number matches. A list of 1,000 entries or more is recorded as not read. A list that carries no count is taken as whole when a page has fewer than 100 entries and no link to a next page, which rests on the server giving 100 to a page when asked.

The audit reads only settings that a repository's own workflows depend on (plan decision F-23). It is not a tool for checking a whole organisation against a standard; [the landscape](landscape.md) names tools that are.

### What needs more than read

Two things are shown only to a caller who could also change them. OBAAF never asks anyone for that access. With any token the audit asks for both, and a token that happens to have the access gets an answer; otherwise they are listed as not read and an administrator has to look in the repository's settings.

<a id="the-bypass-list"></a>
- **Who may bypass a ruleset.** GitHub's reference: "the `bypass_actors` property is only returned if the user making the API request has write access to the ruleset". When the field is missing the audit records the list as not read (`withheld`). A list with entries is recorded. **An empty list is never recorded as "nobody may bypass"**: the reference does not say whether a caller without write access gets no field or an empty one, and nothing in an answer shows which kind of caller the token is. So today the audit can show that someone may bypass, and cannot show that nobody may. One case has been seen: on 2026-11-12 GitHub sent a caller with no token no `bypass_actors` field at all for the first adopter's ruleset (the answer is kept as a test recording). What a token without write access gets has not been seen. One run by an administrator against a ruleset whose bypass list is known would settle it.
- **Actions policies.** GitHub's reference asks for the "Administration" permission with write access even to list them. This is the setting behind one of the adopter's incidents (a policy allowed two events for one workflow, so a third trigger failed before any job started), and a read-only audit will usually have to report it as not read.

## What "not read" looks like

Every setting is in the snapshot with one of four statuses:

| Status | Meaning |
| --- | --- |
| `read` | The value is in the snapshot |
| `partial` | Some of it was read. `problems` lists each part that was not, with a `key` that identifies it (a ruleset's id, a branch or environment name) |
| `unread` | It was not read. `reason_code` and `reason` say why, `needs` says what GitHub's reference asks of a caller, and `accepted_permissions` repeats GitHub's `X-Accepted-GitHub-Permissions` header when it sent one |
| `not_applicable` | The setting does not exist for this repository (organisation secrets of a user's repository, the bypass list when there is no ruleset) |

The reason codes:

| Code | Meaning |
| --- | --- |
| `no_token` | Not requested: no token was given and GitHub does not show this without one |
| `unauthorized` | GitHub did not accept the token (HTTP 401) |
| `forbidden` | GitHub refused (HTTP 403) |
| `not_found` | GitHub answered 404, which it also sends when the caller may not see something, "to avoid confirming the existence of private repositories" |
| `rate_limited` | GitHub's rate limit was reached. The audit stops asking at once; whatever it had not yet read is recorded under this code, under `depends` when it needed something that was not read, or under `no_token` when it would not have been asked for anyway |
| `network` | No answer was received |
| `server_error` | GitHub had an error (HTTP 5xx) |
| `unexpected` | The answer did not have the shape GitHub documents. The audit does not guess: a field whose absence could pass for "none" must be there. An environment whose answer has no `deployment_branch_policy` field is not taken to allow every branch, one with no list of protection rules is not taken to have no reviewers, and a ruleset with no list of rules is not taken to be empty. A collaborator whose permissions do not say whether they are an administrator is not counted in a lower role, and a rule in force that does not name its ruleset is not accepted. A value outside what the snapshot format allows (a wait of two million minutes, say) is not read either. An answer nested more than 100 levels deep is not examined and not used |
| `withheld` | GitHub left it out of an answer it otherwise gave, or may have (the bypass list) |
| `depends` | Not requested, because something it depends on was not read |

A rule that needs a setting that is not `read` answers "cannot tell" for what depended on it. Where a setting was partly read, a rule uses the part that is there and says "cannot tell" about the rest. A setting that only adds detail to a finding (the collaborator counts under a bypass, say) lowers nothing silently: the finding is reported with a "cannot tell" beside it for what could not be counted.

## Tokens

- The token is read from `GH_TOKEN`, then `GITHUB_TOKEN`, or from the variable named by `--token-env`. There is no option that takes a token on the command line, where it would end up in the shell's history and the process list.
- It is sent only to the API address the audit was started with. A redirect to another host, port or scheme is not followed. A redirect to the same host is followed, at most three times. No other address taken from an answer is fetched: the next page of a list is asked for by number, never from the address in a `Link` header. With `--api-url`, a token is used only if `--token-env` names it; the default variables are for github.com alone.
- Only GET requests are sent. The client has no other verb.
- TLS certificates are always verified. There is no option to turn that off.
- The token is not written to the report, the snapshot or a recording. Request headers are never recorded, and if a server ever sent the token back in an answer, it is cut out before anything else reads that answer. An answer nested more than 100 levels deep is not examined piece by piece and is not used: it is recorded as not read, and the reason says so. The token is cut out where it appears whole. A server that sent it back in pieces, or written another way (with an escape in the middle, or inside a broken character), would not be caught; nothing GitHub sends is known to do that. A token must be made of the characters GitHub's tokens use (letters, digits and `. _ ~ + / = -`); anything else is refused. `--token-env` takes the name of a variable, and what it is given is not repeated in an error message, in case someone puts the token itself there.
- A token with read access is enough for everything except the two things [above](#what-needs-more-than-read) and the collaborator count, which GitHub's reference gives only to someone with write, maintain or admin access to the repository. For a fine-grained personal access token, the repository permissions GitHub's reference names are "Administration", "Secrets", "Environments", "Actions" and "Contents", each with read access ("Metadata" comes with any of them).

## The snapshot

A snapshot is one JSON file, `obaaf-settings-snapshot/v0.1`, described by [a JSON Schema](../src/obaaf/data/schemas/settings-snapshot.schema.json) that covers the value of every setting. It holds:

- `settings`: one entry for each key above, as described under [What "not read" looks like](#what-not-read-looks-like).
- `viewer`: what GitHub said about the caller (whether a token was used, the caller's role on the repository, whether the caller may bypass each ruleset). It is kept apart from `settings` because it changes with who asks.
- `requests`: every path requested and the status of the answer.
- `repository`, `branches`, `api`, `api_version`, `taken_at`, `tool`.

Inside a value, three things are kept apart, so that a rule cannot take "not known" for "none":

- `null` means not known: GitHub did not give it, or it was not read.
- A part that does not apply is left out (the list of selected actions when every action is allowed).
- A known "none" is written out: `false`, `0`, an empty list, or a word such as `"any"` for an environment any branch may deploy to.

Two cases of the first: a rule's `parameters` are `null` when GitHub sent none (as it does for a rule such as `deletion`, which has none) and an empty object only when GitHub sent one; and an environment's `can_admins_bypass` is `null` when GitHub did not say.

The `settings` part depends only on the settings and on what the caller may see: values are cut down to what matters and put in a fixed order, so the same settings read with the same access give the same `settings`, whenever they are read and in whatever order GitHub lists rulesets, rules, environments, reviewers, checks and secrets. The one exception is inside a rule's `parameters` and a ruleset's or policy's `conditions`, which are kept as GitHub sent them, lists in GitHub's order. Every snapshot is checked against the schema before it is written or reported; a setting whose value the schema refuses is recorded as not read. The rest of the file (`taken_at`, `requests`, `viewer`) differs from run to run.

What is in it that you might not want to publish: the names of secrets (never their values; GitHub does not return them), and the logins and team names that the settings themselves name: environment reviewers, and the people, teams and apps on classic branch protection's push and review-bypass lists. For a public repository the environment reviewers are already public; the secret names and the classic protection lists are not. There is no token in it, and no list of collaborators, only how many hold each role.

A snapshot given to `--from-snapshot` is checked before it is used, because a committed snapshot can be edited by anyone who can open a pull request: it must be under 20 MB, strict JSON with no key given twice, not deeply nested, in this format, and every setting must be present with a value of the documented shape. Only three settings can be marked as not applying (the bypass list, environment secrets and organisation secrets); a file that says so of any other is refused. A file that fails is refused (exit 2). A file that passes still says only what it says, and the rules run on it as they would on a fresh reading; [drift](#drift) is what compares one with live settings. The format is a draft and may change before it is released.

### Recordings

`--record DIR` writes `DIR/responses.json`: each path requested, the status, a few response headers, and the body GitHub sent. It exists so that a wrong reading can be reported and turned into a test. It holds more than a snapshot (GitHub's full answers, including the logins of collaborators when that list was read), so look before sharing one. Request headers are not in it.

## Drift

A setting can change without any file in the repository changing: someone opens an environment to every branch, adds a bypass to a ruleset, drops a required check. In the first adopter's first two days, every real incident was a setting changed or set that way. Drift detection compares the settings as they are with a snapshot you committed when you last agreed with them, and reports every difference.

```bash
obaaf audit --snapshot-out .github/obaaf-settings.json    # once: commit this file in a reviewed pull request
obaaf audit --expected .github/obaaf-settings.json        # later: exit 1 if anything differs
```

`--expected FILE` takes a snapshot written by `--snapshot-out`. The settings are read as usual (or taken from `--from-snapshot`, to compare two files with no network), the branches the file covers are audited as well as the default one, and the report begins with the comparison, followed by the usual report of what was read.

This is what it printed for a copy of the first adopter's public settings, read with no token on 2026-11-12 (the recording `live-expectrail-no-token`), in which one environment had been opened to every branch, one approval was required where none had been, and one of the eleven required checks had been dropped (the list of what is not covered is shortened here):

```text
Settings drift of Expectrail/Expectrail
Expected: the snapshot expected.json, taken 2026-11-12 01:00 UTC without a token.
Now: the snapshot now.json, taken 2026-11-12 01:00 UTC without a token.
Branches: main

DRIFT: 2 part(s) of 2 setting(s) differ from the expected snapshot. Each is a finding (OBAAF-DRIFT-001).
  Rulesets and their rules
    ruleset 26914817 "Protect main"
      rules[pull_request].parameters.required_approving_review_count: was 0, now 1
      rules[required_status_checks].parameters.required_status_checks[test]: gone; the expected snapshot has {"context": "test", "integration_id": 15368}
  Environments: reviewers and which branches may deploy
    environment "main-only"
      branch_policies: gone; the expected snapshot has [{"name": "main", "type": "branch"}]
      deployment_branches: was "selected", now "any"
  If the change was meant, take a new snapshot with the same access and commit it in a reviewed pull request (obaaf audit --snapshot-out FILE). If it was not, put the setting back.

NOT COVERED: 10. Neither snapshot read these in full, so they were not compared, or only what both read was:
  Who may bypass each ruleset
  Classic branch protection
  ...

15 settings: 5 compared (3 match, 2 differ), 0 not compared, 10 not covered; 13 part(s) compared. 2 finding(s).
```

(In a real change of the ruleset, "Rules in force on each audited branch" would differ too; this example changed the rulesets only.)

### What counts

Each setting, and each part of one (a ruleset, an environment, a branch, a secret's name, a field), comes out one of four ways:

| Outcome | When | Fails the check |
| --- | --- | --- |
| **Matches** | Both snapshots read it and the values are the same | No |
| **Differs** | Both read it and something is not the same. Each part that differs is one finding, `OBAAF-DRIFT-001`, with every change in it listed | Yes |
| **Not compared** | One snapshot read it and the other did not. Whether it changed is not known | Yes |
| **Not covered** | Neither snapshot read it in full, so there is nothing to compare, or only what both read was compared | No; it is listed |

"Not compared" works in both directions on purpose. A part the committed snapshot holds and this run could not read has not been checked. A part this run read and the committed snapshot did not is not checked either: GitHub may have left it out when the snapshot was taken (an error, or a bypass list it never shows as empty), or someone may have marked it as not read in the file; either way a change in it would otherwise go unreported. The cure is the same: take the snapshot again, with the token the check uses.

The check also fails when no setting was compared at all. A difference in either direction counts, tighter as well as looser: the committed snapshot is the reviewed statement of what the settings are, and a setting that no longer matches it means one of the two is wrong. A difference has no severity and cannot be accepted with an owner and an expiry date the way a finding of `obaaf check` can; it is resolved by putting the setting back or by committing a new snapshot.

How values are compared:

- Only the `settings` part of a snapshot. The list of branches decides which branches each side audited. Who read it, when, and which requests were sent differ on every run and are not compared.
- **Lists are compared without regard to their order.** The snapshot keeps GitHub's order inside a rule's parameters and a ruleset's conditions, and no list in a snapshot means anything by its order. A list of objects is matched element by element by a field that names each one (an id, a name, a check's context, a rule's type), so a change is shown where it is; a list with no such field is compared as a multiset, so a duplicate counts.
- **Values are compared as JSON**, so `true` is not `1`, `1` is not `1.0`, and `null` (not known) is not `false` or an empty list.
- A setting that did not apply and now does (or the reverse) is a difference, as well as whatever parts it now has.
- A branch only one side audited (one named with `--branch` that the committed file does not cover, or a new default branch) is not compared, never "new".
- An environment both sides read only in part (its branch and tag patterns failed to load both times) has the rest of what was read compared, and a difference there counts; it is also listed as not covered, for the part neither read.

When a part is "not compared", in practice:

- **The two were read with different access.** Take the committed snapshot with the same token the scheduled job will use. A snapshot taken with an administrator's token, compared by a job that has only the workflow's token, reports every administrative setting as not compared; a snapshot taken with no token, compared by a job with the workflow's token, reports the collaborator count as not compared.
- **GitHub refused, rate-limited or failed** for something one side holds, now or when the snapshot was taken.
- **A ruleset's bypass list changed between empty and not empty.** GitHub's empty bypass list is never believed (see [the bypass list](#the-bypass-list)), so an empty list is recorded as not read: adding the first bypass actor, or removing the last, shows as "not compared". Check the ruleset in the repository's settings, then commit a new snapshot.

### What it can watch

Only what the token can read. With the workflow's own token, on a public repository, that is the repository, its rulesets and their rules, the rules in force on each audited branch, the public view of each branch (whether GitHub calls it protected, and the required checks a classic protection rule shows), the environments with their reviewers and branch rules, and how many accounts hold each role. **The bypass list of a ruleset, classic branch protection (its required reviews, whether administrators are held to it, force pushes and deletions), the names of secrets, the Actions permissions and policies, the default token permissions and the approval rule for fork pull requests are not readable with that token, so a scheduled job that uses it never watches them**: they stay "not covered". To watch them the job needs a token that can read them (a fine-grained token or a GitHub App with the read permissions in [the table above](#what-it-reads), kept in an environment limited to the default branch), and the bypass list and Actions policies need more than read access, which OBAAF never asks for.

The collaborator count is the number of accounts GitHub lists with access to the repository. Going by GitHub's reference (not tried), on an organisation's repository with a base permission that list includes every member of the organisation, so a member joining or leaving the organisation is a difference.

### The committed file

The file is read the way `--from-snapshot` reads one (size, strict JSON, the whole format, no number too large to be finite), and more is checked, because anyone who can open a pull request can change it: it must be of the repository being audited and read from the same API address, checked before any request is sent and again on what was read; no two rulesets, policies, environments or secrets in it may share an id or a name, which the schema does not forbid and which would hide one behind the other; the branch data it holds must be for exactly the branches it lists, as the reader writes it; and it may name at most 50 branches, each a plain branch name. A file that fails any of these is refused (exit 2) and nothing is compared. `--snapshot-out` and `--output` may not name the same file as `--expected`, so the record cannot be overwritten with what it is checked against. After GitHub renames the repository, take a new snapshot: the old one is refused as another repository's.

Whoever can change the file decides what counts as drift: a pull request that edits a value in it to match a weakened setting makes the difference disappear, and one that removes a branch from its list stops that branch from being audited. A part marked as not read in the file does not hide a change, as above. Review changes to the file like changes to a workflow, under a code owner.

### On a schedule

[`templates/github-actions/optional/obaaf-settings-drift.yml`](../templates/github-actions/optional/obaaf-settings-drift.yml) runs the comparison once a day and when the committed snapshot changes in a pull request, with the workflow's own read-only token. It is not installed by `obaaf templates install`, because it fails until a snapshot is committed. To start, with no file written by hand:

1. Copy it to `.github/workflows/` and pin `setup-obaaf` to an OBAAF release (`obaaf check` reports the placeholder until you do).
2. Run it once from the Actions tab. With no snapshot committed it fails on purpose and keeps what it read as the artifact `obaaf-settings-live`.
3. Download `obaaf-settings.json` from that artifact, read it (above all, whether anything you expected to be read is listed as not read), and commit it as `.github/obaaf-settings.json` in a pull request. That pull request runs the comparison, which shows whether the file matches the live settings. It is not a safeguard against a hostile change: a pull request runs its own copy of the workflow. Code-owner review is.

The template also asks for `actions: read`, because GitHub's reference names the Actions permission for reading environments; that matters on a private repository and has not been tried on one. A report and an artifact of a public repository can be read by anyone who can read the repository. With the workflow's token the snapshot holds what anyone can see plus how many accounts hold each role; with a token that can read more, it also holds the names (never the values) of secrets. GitHub turns off scheduled workflows in a public repository after 60 days without activity.

[`.github/workflows/settings-drift.yml`](../.github/workflows/settings-drift.yml) is this repository's own use of it, against [`.github/obaaf-settings.json`](../.github/obaaf-settings.json), which is what its first run read on 2026-11-13 with the workflow's token. This repository's `main` is protected by a classic protection rule and no ruleset, so its own job watches the required checks that rule shows publicly and not the rest of the rule.

The template needs an OBAAF that has `obaaf audit --expected`. No release has it yet (0.3.0 does not); until one does, it has to be pinned to a commit that has it.

With `--format json` and `--expected` the comparison is under `drift` in the audit's JSON report (`obaaf-settings-audit/v0.1`, beside the rules' results and the live snapshot under `snapshot`; the comparison keeps its own `format` field, `obaaf-settings-drift/v0.1`, so a reader can tell its shape): the summary, each difference with every change (`path`, `change`, and the `expected` and `live` values), and what was not compared and what was not covered, with the reasons. The text report begins with the comparison and shows the first 20 changes of a part; the JSON has them all.

The rules run in the same command, so a drift run also reports their findings. The template and this repository's job pass `--fail-on never`, so that they fail on drift and not on a rule's finding (the template checks out only the snapshot, so there the twelve rules that compare with workflow files answer "cannot tell"; `004`, `005` and `013` read settings only and still answer). Run the rules as a gate in a job of their own.

## What it does not read

Said plainly, so that nobody assumes otherwise:

- **Which checks actually report on pull requests.** The rules compare the required checks with the names in the workflow files. Recent check runs are not read.
- Custom deployment protection rules (gates run by a GitHub App), repository and environment variables, deploy keys, webhooks, tag protection other than rulesets, and the access level that lets other repositories call this one's reusable workflows.
- Organisation and enterprise settings, except rulesets and Actions policies from those levels that apply to this repository.
- Anything on GitHub Enterprise Server. `--api-url` exists, and has not been tried against one.

Two limits of the command itself:

- **There is no time limit for an audit as a whole**, only 60 seconds for the body of each answer and 20 seconds for each wait on the connection. A repository with many rulesets and environments means many requests; a workflow should set its own `timeout-minutes`.
- **The report does not wrap its own lines.** Every name is cut to a fixed length and cannot hold a line break or a control character, but a long line still wraps in a narrow terminal, and text at the start of a wrapped line can look like a line of the report. Read a report on a snapshot you do not trust with that in mind, or use `--format json`.

## Things the audit takes on trust

Each of these is a place where GitHub's reference did not settle the question. None has been confirmed against a live repository with an administrator's token.

- **A 404 from classic branch protection** means "this branch has no classic protection" only when GitHub's message is exactly "Branch not protected", compared as it came, character for character. GitHub's reference documents the 404 but not the message. Any other 404 is recorded as not read.
- **Sections missing from a classic branch protection** (required checks, required reviews, push restrictions) are recorded as not required. This is the one place where an absence is read as a value: GitHub leaves a section out when it is not configured, and the reading chosen is the one that reports less protection, never more. The list of who may bypass required reviews is the exception: when it is absent it is recorded as not known. The answer must still say whether administrators are held to the rule, or it is not taken for a protection at all.
- **`deployment_branch_policy: null`** means any branch or tag may deploy. GitHub's reference says so for setting the value ("To allow all branches to deploy, set to `null`"), not for reading it.
- **An empty bypass list** is not believed from anyone, as described [above](#the-bypass-list).
- **Collaborator roles** are read from each collaborator's `permissions` object, which must say true or false for all five of admin, maintain, push, triage and pull; if the object or one of the five is missing, the count is recorded as not read (`unexpected`), because an administrator whose `admin` field was missing would otherwise be counted in a lower role. That response's schema was not re-read on 2026-11-12. Seen on 2026-11-12 with the workflow's token: this repository's three collaborators, all administrators, were counted as "3 accounts: 3 admin".
- **What "protected" means** on the public view of a branch is not relied on. The flag is recorded as GitHub gives it. Seen on 2026-11-12: a branch protected only by a ruleset came back with `protected: true`, a `protection` object that says `enabled: false`, and an empty list of required checks, while the ruleset requires eleven. So the checks in this view are those of a classic protection rule only, and the report says "no required checks shown in this view" rather than "none". The checks a ruleset requires are under "Rules in force on each audited branch".
- **An environment limited to protected branches** is reported in those words ("only branches GitHub counts as protected may deploy"). Which branches that lets through depends on which have a protection rule, and the audit does not work that out.
- **"Administrators may bypass these rules"** on an environment is GitHub's `can_admins_bypass` field as it came, which GitHub sent to a caller with no token on 2026-11-12. The report says it only for an environment that has a reviewer, a wait timer or another protection rule. Whether it also lets an administrator past the limit on which branches may deploy is not something the audit claims.

<a id="what-has-been-run-and-what-has-not"></a>
## What has been run, and what has not

- **Run:** the tests in `tests/test_settings_audit.py` (the reader), `tests/test_settings_rules.py` (the rules) and `tests/test_settings_drift.py` (drift). They drive both from recordings in `tests/fixtures/settings/`; the rules are compared with the workflow files in `tests/fixtures/settings/incident-repo/`, a repository shaped after the first adopter's incidents, and with files the tests write. Three of the recordings were **written by hand** from the example responses in GitHub's REST reference: one for a caller with no token, one for a workflow's token and one for an administrator's. Three are **GitHub's own answers** to a caller with no token: this repository's from the run of 2026-11-12 06:32 UTC ([43168837657](https://github.com/Obaaf/OBAAF/actions/runs/43168837657)), and the first adopter's from the run of 01:33 UTC that day ([43135263367](https://github.com/Obaaf/OBAAF/actions/runs/43135263367)) and from the run of 2026-11-13 09:10 UTC ([43399109471](https://github.com/Obaaf/OBAAF/actions/runs/43399109471)). So everything a token is needed for, and above all everything an administrator's token would show, is still tested only against hand-written answers. The real HTTP client is tested against a server on the test machine: that it sends GET with no body, sends the token only when it has one, does not follow a redirect to another host, and survives an answer that breaks off.
- **Run on GitHub:** the workflow above, on every push to the pull request that added it on 2026-11-12, each time on the reader as it then was; all of them are on [the workflow's page](https://github.com/Obaaf/OBAAF/actions/workflows/settings-audit-live.yml), from [43129074849](https://github.com/Obaaf/OBAAF/actions/runs/43129074849) on the first version. What follows is from [run 43175468240](https://github.com/Obaaf/OBAAF/actions/runs/43175468240), at 07:28 UTC. On this repository with no token it read the five public settings in seven requests. With the workflow's own token it read the same and the collaborator count, and GitHub refused the other eight with HTTP 403, "Resource not accessible by integration", naming the permission it would accept (`administration=read`, `environments=read`, `secrets=read`, and `administration=write` for Actions policies). On the first adopter's repository, with no token, it read the ruleset that protects `main` with its eleven required checks, the rules in force on `main` and three environments, and recorded the ruleset's bypass list as not read. From the second run on, the job reads the adopter's repository as well and fails if any answer has an unexpected shape; every run since has passed. From that run of 07:28 UTC on, the job also requires the report to be the snapshot's own report to the character and the adopter's public settings to have been read, and the reader had by then become stricter about collaborators' permissions and about rules in force; GitHub's answers met all of it, then and in the later runs.
- **What the live runs changed.** Reading the reports of the second and third runs found four faults in the report that the hand-written recordings had not shown: a rule was cut off after 60 characters, so three of eleven required checks were named; a pattern for tags was printed like one for branches; nothing said whether administrators may bypass an environment's reviewers; and a branch protected only by a ruleset was described as having no required checks. All four are fixed and the answers behind them are now test recordings. The workflow runs again whenever the reader changes; the pull request that changes it links the run.
- **The rules, against GitHub's own answers.** Two things were run with the rules and real data, both with no token and no network at the time: this repository's recording with this repository's workflow files (one finding, shown at the top of this page), and the first adopter's recording of 2026-11-12 01:33 UTC with a clone of its workflow files at `776ddd3` (five medium findings and six "cannot tell": one environment any branch may use, behind a reviewer who may approve their own run, and four jobs that run on every pull request and are not among its eleven required checks). After the second review's changes, the same recording with its files at `8a3e83f` gives the same five medium findings and seven "cannot tell": `OBAAF-SET-013` now asks whether workflows may approve pull requests whatever the jobs say, which no token can read. On 2026-11-13 the live workflow read the adopter's settings afresh and ran the rules on its own workflow files, cloned in the same step at `36a7a8a` (plan slice 2b.4): four medium findings and seven "cannot tell"; one required check had been added since the first reading. That run, each finding judged against the adopter's files, and what could not be read are on [their own page](expectrail-settings-audit.md); the answers and the snapshot are kept in `tests/fixtures/settings/live-expectrail-2026-11-13/`.
- **Not run:** the audit with a token that has administrative read access, so every setting marked "Token" above except the collaborator count has only been read from hand-written recordings, **and every one of the fifteen rules lists at least one setting that has been read only from hand-written recordings; for `OBAAF-SET-001` that is the names of an environment's secrets, which only set its severity, and for `OBAAF-SET-006` to `OBAAF-SET-008` it is classic protection, which the public view of the branch stood in for**; a repository with classic branch protection read in full; a private repository; GitHub Enterprise Server; any repository with an Actions policy.

## Sources

GitHub's REST reference and documentation, read on 2026-11-12 (API version `2026-03-10`, the one the reference's examples use). The pages were read through a tool that summarises them, so long sentences were pieced together from fragments; the response schemas' field descriptions were not available.

- Rules: [REST API endpoints for rules](https://docs.github.com/en/rest/repos/rules)
- Branches: [branches](https://docs.github.com/en/rest/branches/branches), [protected branches](https://docs.github.com/en/rest/branches/branch-protection)
- Environments: [environments](https://docs.github.com/en/rest/deployments/environments), [deployment branch policies](https://docs.github.com/en/rest/deployments/branch-policies)
- Secrets: [Actions secrets](https://docs.github.com/en/rest/actions/secrets)
- Actions settings: [permissions](https://docs.github.com/en/rest/actions/permissions), [policies](https://docs.github.com/en/rest/actions/policies), [about Actions policies](https://docs.github.com/en/actions/concepts/about-actions-policies)
- Repository and collaborators: [repositories](https://docs.github.com/en/rest/repos/repos), [collaborators](https://docs.github.com/en/rest/collaborators/collaborators)
- Using the API: [rate limits](https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api), [API versions](https://docs.github.com/en/rest/about-the-rest-api/api-versions), [troubleshooting](https://docs.github.com/en/rest/using-the-rest-api/troubleshooting-the-rest-api), [permissions required for fine-grained personal access tokens](https://docs.github.com/en/rest/authentication/permissions-required-for-fine-grained-personal-access-tokens)
