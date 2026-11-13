# The settings audit: `obaaf audit`

*Status: not in a release yet. The command reads a repository's GitHub settings, records what it read and what it could not, and compares the settings with what the repository's workflow files use: fifteen rules, `OBAAF-SET-001` to `OBAAF-SET-015`. A rule reports a finding, or "cannot tell" when a setting it needs was not read. **Most of the rules need settings that only an administrator's token can read, and the audit has never been run with one**: those rules are tested against answers written by hand. What has and has not been run against GitHub is listed [at the end](#what-has-been-run-and-what-has-not).*

`obaaf check` reads workflow files. Some of what decides whether a workflow is safe is not in any file: which branches may use an environment, who may bypass a ruleset, which checks are required, which events GitHub lets start a workflow. In the first adopter's first two days every real incident was one of those settings, and `obaaf check` saw none of them.

`obaaf audit` reads those settings through GitHub's REST API and compares them with the workflow files in a clone. It sends GET requests only. Whatever it could not read is listed by name with the reason, and a rule that needed it answers "cannot tell", so "not read" can never be mistaken for "nothing wrong".

## Run it

In a clone of a repository on github.com:

```bash
obaaf audit                          # OWNER/REPO from the origin remote; the workflow files from this clone
obaaf audit DIR --repo OWNER/REPO    # or name the clone and the repository
```

With no token this reads what GitHub shows anyone about a public repository: the repository itself, its rulesets and their rules, the rules in force on the default branch, whether GitHub calls that branch protected, and its environments with the branches that may deploy to each. That is enough for four rules: the open environment (`OBAAF-SET-001`) and the three about required checks (`OBAAF-SET-006` to `OBAAF-SET-008`). `OBAAF-SET-002` can answer for a job that reads a secret. The others need more and say "cannot tell", each naming the setting it lacked.

The report begins with the findings, then what the rules could not tell, then one line for every rule, then everything that was read and not read. This is the report for this repository, made on 2026-11-13 with no network from GitHub's answers of 2026-11-12 06:32 UTC to a caller with no token (they are kept as a test recording) and the workflow files as they were on 2026-11-13. It is shortened where `...` stands, and its second line, which says where the settings came from, is left out:

```text
Settings audit of Obaaf/OBAAF
Compared with 5 workflow files in the directory ".".

FINDINGS: 1 (0 high, 1 medium, 0 low). CANNOT TELL: 4, from 4 of 15 rules. "Cannot tell" is never a pass: nothing is established there.

  OBAAF-SET-008  A pull-request job whose failure does not block a merge
    MEDIUM  branch "main": job .github/workflows/ci.yml#dependency-lock
            .github/workflows/ci.yml#dependency-lock runs on every pull request into "main" and reports the check "dependency-lock", which is not required (8 checks are required there). A pull request can merge while the job is failing. The checks of the classic protection rule are taken from what GitHub shows anyone; the rule itself was not read.
    Fix: Add the job's check to the required checks. If the job is advisory, give it `continue-on-error: true` at job level, which says in the workflow that its failure is not meant to block.

CANNOT TELL: 4. A setting or a file the rule needs was not read, or was not in a form the rule understands.
  OBAAF-SET-004  Those who author changes can bypass the branch's rules
    CANNOT TELL  branch "main": classic protection
            Whether the branch has a classic protection rule, and whether administrators are held to it, is not known: "Classic branch protection" was not read (no_token).
  ...

RULES: 15. Each compares a setting with what the workflow files use.
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
- `--fail-on-cannot-tell`: any rule that answered "cannot tell". Without a token most rules do, so this is for a run with a token that can read the administrative settings.
- `--fail-on-unread`: any setting that applies and was not read in full.

Exit codes:

| Code | When |
| --- | --- |
| 0 | The audit ran and no finding reached `--fail-on`. Rules may have answered "cannot tell" and settings may not have been read; both are listed before anything else |
| 1 | A finding at or above `--fail-on`; or `--fail-on-cannot-tell` and a rule could not tell; or `--fail-on-unread` and something was not read in full; or not even the repository could be read; or an output file could not be written; or a rule or the command failed in a way it did not foresee (it says so, and says that nothing was established) |
| 2 | A usage error, or a snapshot file that cannot be used |

**A settings finding cannot be accepted yet.** `obaaf check` has acceptances with an owner, a reason and an expiry date; `obaaf audit` has none. Every finding here is cleared by changing a setting or a workflow, and the audit sees the change the next time it runs. A finding you decide to live with stays in the report, and the only way to keep it from failing a build is a higher `--fail-on`.

### Which workflow files are compared

The rules compare settings with workflow files, so the command has to know whose files it is reading. It reads them from the directory it is given (the current directory by default) when that directory's origin remote names the repository being audited. It also reads them when you name the directory on the command line and its remote names another repository or none: whoever names a directory says whose files they are, and the report repeats what the remote said. What it never does is compare the settings of `--repo OWNER/REPO` with the workflows of whichever clone the command happened to be started in: then the report says the workflow files were not read, and every rule answers "cannot tell".

The files are read with the parser `obaaf check` uses, and the checker's configuration (`.github/obaaf.yml`) is read for `protected_secrets`. A workflow file that does not parse is listed, and every rule that found nothing in the other files says "cannot tell" for it.

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

The checkout is what gives the rules the workflow files. With the workflow's own token the rules that need administrative settings answer "cannot tell"; the job still fails on what anyone can read, such as an environment open to every branch.

[`.github/workflows/settings-audit-live.yml`](../.github/workflows/settings-audit-live.yml) is this repository's own use of it. A report printed in a job is in that job's log, which anyone can read for a public repository: with a token that may read the collaborators, the report says how many accounts hold each role (never who they are). To read the settings marked "Token" in the table from a workflow, the token has to come from somewhere else (a fine-grained personal access token or a GitHub App with the read permissions named there, stored as a secret in an environment limited to the default branch). OBAAF does not create tokens and does not ask for more than read access.

## The rules

Each rule compares a setting with something a workflow in the repository uses or assumes (plan decision F-23). A setting no workflow depends on is not judged: this is not a checklist for an organisation, and [the landscape](landscape.md) names tools that are.

A rule gives results about one thing at a time (an environment, a branch, a job), and each result is one of two kinds:

- a **finding**, with a severity (high: a way in is open; medium: a safeguard is missing or cannot work; low: hardening), when what was read shows the problem;
- **cannot tell**, when a setting or a workflow file the rule needs was not read, or was read and is not in a form the rule understands. It names what was missing. It is never counted as nothing wrong.

A rule with neither gets one line saying what it compared ("no finding: 8 required checks and the names the jobs report") or why it had nothing to compare ("does not apply: no job names an environment"). The report never says "pass": a rule that found nothing has shown only that.

| Rule | What it reports | Highest severity | Settings it reads | Compared with |
| --- | --- | --- | --- | --- |
| `OBAAF-SET-001` | An environment's secrets can be reached from any branch | high | `environments` | the environment each job names |
| `OBAAF-SET-002` | A job outsiders can start gets an environment that asks nobody | high | `environments`, `environment_secrets` | jobs started by pull_request_target, issue and comment events |
| `OBAAF-SET-003` | A secret kept behind an environment is also stored where every job can read it | high | `environment_secrets`, `repository_secrets`, `organization_secrets`, `environments` | protected_secrets in .github/obaaf.yml, and the secrets jobs read |
| `OBAAF-SET-004` | Those who author changes can bypass the branch's rules | high | `ruleset_bypass_actors`, `branch_protection`, `collaborators`, `branch_rules` | the required checks and reviews the workflows' results feed |
| `OBAAF-SET-005` | Required approvals cannot be given | medium | `branch_rules`, `branch_protection`, `collaborators` | pull requests into the branch |
| `OBAAF-SET-006` | A required check that no workflow job reports | medium | `branch_rules`, `branch_protection`, `branches` | the check name each job reports |
| `OBAAF-SET-007` | A required check that a path filter can skip | medium | `branch_rules`, `branch_protection`, `branches` | the paths filters on the workflows' triggers |
| `OBAAF-SET-008` | A pull-request job whose failure does not block a merge | medium | `branch_rules`, `branch_protection`, `branches` | the jobs that run on every pull request |
| `OBAAF-SET-009` | An Actions policy blocks an event a workflow uses | medium | `actions_policies` | the events under each workflow's `on:` |
| `OBAAF-SET-010` | A pull_request_target workflow and GitHub's default policy of 2026-12-02 | medium | `actions_policies`, `repository` | workflows started by pull_request_target |
| `OBAAF-SET-011` | A reusable workflow is passed a secret its caller cannot read | medium | `environment_secrets`, `repository_secrets`, `organization_secrets` | the secrets a job passes to a reusable workflow |
| `OBAAF-SET-012` | Jobs with no permissions block get a token that can write | medium | `workflow_permissions` | jobs that declare no `permissions` |
| `OBAAF-SET-013` | A workflow can approve pull requests | medium | `workflow_permissions`, `branch_rules` | jobs whose token can write to pull requests |
| `OBAAF-SET-014` | Fork pull requests run on the repository's runners or with its secrets | high | `fork_pull_requests`, `repository` | pull_request jobs on self-hosted runners, or that read secrets |
| `OBAAF-SET-015` | Pinning actions to a commit: the setting and the workflows disagree | medium | `actions_permissions` | the actions each job's steps use |

### The six incidents

The rules were written from the settings behind the first adopter's incidents. Each is caught in `tests/test_settings_rules.py` from a recorded answer; for the four that need an administrator's token the answer was written by hand.

| Incident | Rule | Can it be seen with no token? |
| --- | --- | --- |
| A protected environment created with no branch restriction | `OBAAF-SET-001` (and `OBAAF-SET-002` for a job that pull requests or comments can start; `OBAAF-SET-003` when the secret is also stored for every job) | `OBAAF-SET-001`: yes, for a public repository. `OBAAF-SET-003` needs the names of the secrets |
| A bypass on the branch ruleset that lets the account that authors changes skip every required check | `OBAAF-SET-004` | No. GitHub shows the bypass list only to someone who could change it. With a token it also says whether the token's own account can bypass |
| Required approvals that the one shared account could never give | `OBAAF-SET-005` | No: it needs the number of accounts with write access. A workflow's own token was given that count for this repository on 2026-11-12 |
| A required-checks list that named one check of the eleven that ran | `OBAAF-SET-008` (and `OBAAF-SET-006`, `OBAAF-SET-007` for a required check that nothing reports or that a paths filter can skip) | Yes, for a public repository |
| An Actions policy that allowed two events for a workflow that used a third | `OBAAF-SET-009` | No. GitHub's reference asks for write access even to read the policies, so this will usually be "cannot tell", with the events the workflows use listed for an administrator to compare |
| A reusable workflow that could not see its caller's environment secrets | `OBAAF-SET-011` | No: it needs the names of the secrets |

Also asked for by the plan: the default token permissions (`OBAAF-SET-012`), workflows that may approve pull requests (`OBAAF-SET-013`), approval for fork pull requests (`OBAAF-SET-014`), the pinning requirement (`OBAAF-SET-015`), and the `pull_request_target` change of 2026-12-02 (`OBAAF-SET-010`). For that last one, a public repository whose workflows use the event gets either a finding (the policies were read and none allows it) or a "cannot tell" that names the date and the workflows, so an adopter learns that the change concerns them even when the policy cannot be read.

### What each rule looks at, exactly

- **`OBAAF-SET-001`.** Every environment that a job names with a fixed name, or that `protected_secrets` names. "Any branch or tag" is high with no required reviewers and medium with them. A branch pattern made only of `*` and `/` counts as no limit. Any other wildcard, and any tag pattern, is medium when there are no reviewers (anyone with write access can push a branch or tag of that name; whether a ruleset stops them is not read) and is not reported when there are. "Protected branches only" is "cannot tell": which branches GitHub counts as protected is not read. An environment that a job names and the settings do not have is medium. An environment name that is an expression is not compared.
- **`OBAAF-SET-002`.** Jobs that `pull_request_target`, `issue_comment`, `issues`, `workflow_run` and the other events people without write access can cause may start (the same list `obaaf check` uses), that name an environment with no required reviewers, where the environment holds a secret or the job reads one. This is the check behind a sentence in OBAAF-GHA-001, which reports such a job at medium "because environment secrets are released only after required reviewers approve".
- **`OBAAF-SET-003`.** With `protected_secrets` in `.github/obaaf.yml`: a repository or organisation secret whose name matches an entry (high), an environment the entry names that does not exist (high), and an entry that matches nothing stored in its environment (low). Without it: a secret stored both in an environment and for every job, when a job reads it (medium). This is the part of OBAAF-GHA-024 that a workflow file cannot show.
- **`OBAAF-SET-004`.** Rulesets in force on an audited branch and its classic protection rule. A bypass that is not limited to merging a pull request is medium, and high when it covers every account that can push: by role, from the counts of collaborators, or because one account can push and GitHub says that account, the token's, can always bypass. A bypass only when merging a pull request is low. An organisation-administrator bypass is not counted towards "everyone", because the counts do not say which administrators are the organisation's.
- **`OBAAF-SET-005`.** The approvals a branch requires against the accounts with write access, less one for the author. A `pull_request` rule that came without its parameters is "cannot tell", not "0 approvals".
- **`OBAAF-SET-006` to `OBAAF-SET-008`.** The required checks, from the rules in force and from classic protection, against the name each job reports. A job reports its `name`, or its id; a matrix job is matched as `name (…)` and a job that calls a reusable workflow as `name / …`; a name built from an expression is not compared and is reported as "cannot tell". `OBAAF-SET-006` reports a required check only when it is tied to GitHub Actions and every workflow file was read. `OBAAF-SET-008` counts a job only when its workflow runs on every pull request into the branch (no paths filter, and a branches filter that names the branch or none), and leaves out a job with `continue-on-error: true` at job level.
- **`OBAAF-SET-009` and `OBAAF-SET-010`.** A policy is read only in the one form the reader has met: a list of workflow paths to include and exclude, and rules that carry a list of allowed events. An enforced policy that applies to a workflow file and does not list one of its events is medium; one in evaluate mode is low. A disabled policy, and a policy with no rule about events (one about who may start a workflow), is left alone. A policy with a rule about events whose paths, enforcement or list of events is in any other form is "cannot tell". `workflow_call` is not counted as an event.
- **`OBAAF-SET-011`.** Secrets a job passes by name to a reusable workflow, and, for `secrets: inherit` and a reusable workflow in the same repository, the secrets the called jobs read. A called job that declares the environment itself is not reported. A reusable workflow in another repository is "cannot tell".
- **`OBAAF-SET-012` to `OBAAF-SET-015`.** As the table says. `OBAAF-SET-014` looks only at `pull_request` jobs on self-hosted runners in a public repository, and at what a private repository sends fork pull requests. `OBAAF-SET-015` leaves out local actions and container images.

### What the rules take on trust, and what they do not do

- **Actions policies have never been seen.** The form the rules read (`conditions.workflow_path.include` and `exclude`, a rule with `allowed_events`) is the one in a recording written by hand for slice 2b.1. GitHub's pages on policies could not be re-read when the rules were written (2026-11-13: the session's requests for them were not answered). How GitHub matches a path pattern, whether `schedule` is an event a policy governs, and whether its default policy appears in the list are not established. A real policy in another form gives "cannot tell", not a wrong finding; a real policy in this form with other semantics could give a wrong one.
- **The date and reach of the `pull_request_target` change** are as [the landscape](landscape.md) recorded them on 2026-11-12 from GitHub's changelog, which words the reach in two ways.
- **Check names come from the workflow files, not from GitHub.** The audit does not read recent check runs, so a job that exists and never runs, or a check reported by something other than a workflow job, is outside what it sees.
- **`15368` is taken to be the id of the GitHub Actions app**, the value in GitHub's own answers for the first adopter's eleven required checks.
- **Role ids in a bypass list** are read as 5 admin, 4 write, 2 maintain, the ids GitHub's built-in roles carry. The reference was not re-read for this.
- **A branch whose public view says `protection.enabled: false`** is taken to have no classic protection rule. That is what GitHub sent for a branch protected only by a ruleset on 2026-11-12, seen once.
- **Whether an approval given by a workflow counts** towards a required approval is not something `OBAAF-SET-013` claims. It reports that a run can approve.
- **Branch and tag patterns are not evaluated**, apart from the all-stars case. `releases/*` and `v*` are reported as patterns, not resolved against the branches that exist.
- **Collaborator counts are what GitHub listed** with `affiliation=all`. An account that gets access another way would not be in them.
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

A rule that needs a setting that is not `read` answers "cannot tell", never "no finding". Where a setting was partly read, a rule uses the part that is there and says "cannot tell" about the rest.

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

A snapshot given to `--from-snapshot` is checked before it is used, because a committed snapshot can be edited by anyone who can open a pull request: it must be under 20 MB, strict JSON with no key given twice, not deeply nested, in this format, and every setting must be present with a value of the documented shape. Only three settings can be marked as not applying (the bypass list, environment secrets and organisation secrets); a file that says so of any other is refused. A file that fails is refused (exit 2). A file that passes still says only what it says, and the rules run on it as they would on a fresh reading; drift detection (slice 2b.3) is what compares one with live settings. The format is a draft and may change before it is released.

### Recordings

`--record DIR` writes `DIR/responses.json`: each path requested, the status, a few response headers, and the body GitHub sent. It exists so that a wrong reading can be reported and turned into a test. It holds more than a snapshot (GitHub's full answers, including the logins of collaborators when that list was read), so look before sharing one. Request headers are not in it.

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

- **Run:** the tests in `tests/test_settings_audit.py` (the reader) and `tests/test_settings_rules.py` (the rules). They drive both from recordings in `tests/fixtures/settings/`; the rules are compared with the workflow files in `tests/fixtures/settings/incident-repo/`, a repository shaped after the first adopter's incidents, and with files the tests write. Three of the recordings were **written by hand** from the example responses in GitHub's REST reference: one for a caller with no token, one for a workflow's token and one for an administrator's. Two are **GitHub's own answers** to a caller with no token: this repository's from the run of 2026-11-12 06:32 UTC ([43168837657](https://github.com/Obaaf/OBAAF/actions/runs/43168837657)) and the first adopter's from the run of 01:33 UTC ([43135263367](https://github.com/Obaaf/OBAAF/actions/runs/43135263367)). So everything a token is needed for, and above all everything an administrator's token would show, is still tested only against hand-written answers. The real HTTP client is tested against a server on the test machine: that it sends GET with no body, sends the token only when it has one, does not follow a redirect to another host, and survives an answer that breaks off.
- **Run on GitHub:** the workflow above, on every push to the pull request that added it on 2026-11-12, each time on the reader as it then was; all of them are on [the workflow's page](https://github.com/Obaaf/OBAAF/actions/workflows/settings-audit-live.yml), from [43129074849](https://github.com/Obaaf/OBAAF/actions/runs/43129074849) on the first version. What follows is from [run 43175468240](https://github.com/Obaaf/OBAAF/actions/runs/43175468240), at 07:28 UTC, the one the example at the top of this page is taken from. On this repository with no token it read the five public settings in seven requests, as shown at the top of this page. With the workflow's own token it read the same and the collaborator count, and GitHub refused the other eight with HTTP 403, "Resource not accessible by integration", naming the permission it would accept (`administration=read`, `environments=read`, `secrets=read`, and `administration=write` for Actions policies). On the first adopter's repository, with no token, it read the ruleset that protects `main` with its eleven required checks, the rules in force on `main` and three environments, and recorded the ruleset's bypass list as not read. From the second run on, the job reads the adopter's repository as well and fails if any answer has an unexpected shape; every run since has passed. From that run of 07:28 UTC on, the job also requires the report to be the snapshot's own report to the character and the adopter's public settings to have been read, and the reader had by then become stricter about collaborators' permissions and about rules in force; GitHub's answers met all of it, then and in the later runs.
- **What the live runs changed.** Reading the reports of the second and third runs found four faults in the report that the hand-written recordings had not shown: a rule was cut off after 60 characters, so three of eleven required checks were named; a pattern for tags was printed like one for branches; nothing said whether administrators may bypass an environment's reviewers; and a branch protected only by a ruleset was described as having no required checks. All four are fixed and the answers behind them are now test recordings. The workflow runs again whenever the reader changes; the pull request that changes it links the run.
- **The rules, against GitHub's own answers.** Two things were run with the rules and real data, both with no token and no network at the time: this repository's recording with this repository's workflow files (one finding, shown at the top of this page), and the first adopter's recording of 2026-11-12 01:33 UTC with a clone of its workflow files at `776ddd3` (five medium findings and six "cannot tell": one environment any branch may use, behind a reviewer who may approve their own run, and four jobs that run on every pull request and are not among its eleven required checks). Slice 2b.4 of the plan is the run against the adopter with the settings read afresh, and its findings belong to the case study, not to this page.
- **Not run:** the audit with a token that has administrative read access, so every setting marked "Token" above except the collaborator count has only been read from hand-written recordings, **and eleven of the fifteen rules have met only hand-written answers for at least one setting they need**; a repository with classic branch protection read in full; a private repository; GitHub Enterprise Server; any repository with an Actions policy.

## Sources

GitHub's REST reference and documentation, read on 2026-11-12 (API version `2026-03-10`, the one the reference's examples use). The pages were read through a tool that summarises them, so long sentences were pieced together from fragments; the response schemas' field descriptions were not available.

- Rules: [REST API endpoints for rules](https://docs.github.com/en/rest/repos/rules)
- Branches: [branches](https://docs.github.com/en/rest/branches/branches), [protected branches](https://docs.github.com/en/rest/branches/branch-protection)
- Environments: [environments](https://docs.github.com/en/rest/deployments/environments), [deployment branch policies](https://docs.github.com/en/rest/deployments/branch-policies)
- Secrets: [Actions secrets](https://docs.github.com/en/rest/actions/secrets)
- Actions settings: [permissions](https://docs.github.com/en/rest/actions/permissions), [policies](https://docs.github.com/en/rest/actions/policies), [about Actions policies](https://docs.github.com/en/actions/concepts/about-actions-policies)
- Repository and collaborators: [repositories](https://docs.github.com/en/rest/repos/repos), [collaborators](https://docs.github.com/en/rest/collaborators/collaborators)
- Using the API: [rate limits](https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api), [API versions](https://docs.github.com/en/rest/about-the-rest-api/api-versions), [troubleshooting](https://docs.github.com/en/rest/using-the-rest-api/troubleshooting-the-rest-api), [permissions required for fine-grained personal access tokens](https://docs.github.com/en/rest/authentication/permissions-required-for-fine-grained-personal-access-tokens)
