# The settings audit: `obaaf audit`

*Status: first part, not in a release yet. The command reads a repository's GitHub settings and records what it read and what it could not. **It applies no rule yet**, so it reports no findings; the rules are the next slice of the [flagship plan](flagship.md) (2b.2). What has and has not been run against GitHub is listed [at the end](#what-has-been-run-and-what-has-not).*

`obaaf check` reads workflow files. Some of what decides whether a workflow is safe is not in any file: which branches may use an environment, who may bypass a ruleset, which checks are required, which events GitHub lets start a workflow. In the first adopter's first two days every real incident was one of those settings, and `obaaf check` saw none of them.

`obaaf audit` reads those settings through GitHub's REST API. It sends GET requests only. Whatever it could not read is listed by name with the reason, so "not read" can never be mistaken for "nothing wrong".

## Run it

In a clone of a repository on github.com:

```bash
obaaf audit                      # finds OWNER/REPO from the origin remote
obaaf audit --repo OWNER/REPO    # or name it
```

With no token this reads what GitHub shows anyone about a public repository: the repository itself, its rulesets and their rules, the rules in force on the default branch, whether GitHub calls that branch protected, and its environments with the branches that may deploy to each. Everything else is listed under **NOT READ** with what GitHub's reference says a token would need, or under **DOES NOT APPLY** where the setting does not exist for the repository.

This is what it printed for this repository on 2026-11-12, with no token, in [its own workflow](https://github.com/Obaaf/OBAAF/actions/runs/43169162230) (the list of what was not requested is shortened here):

```text
Settings audit of Obaaf/OBAAF
Read 2026-11-12 06:35 UTC from https://api.github.com, without a token.
This command reads and records settings. It does not judge them yet: no rule runs on what it read.

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
      main: no active rule
  Each audited branch, as anyone may see it
      main: GitHub calls it protected; required checks: Build resource site, actionlint, package, setup-action (macos-latest), setup-action (ubuntu-latest), setup-action (windows-latest), test (3.10), test (3.13)
  Environments: reviewers and which branches may deploy
      "github-pages": may deploy: branch main; no required reviewers
      "pypi": may deploy: tag v*; reviewers: FehintolaObafemi, Ofonna-N, seanudeke (self-review prevented); administrators may bypass these rules: no

DOES NOT APPLY: 1 of 15
  Who may bypass each ruleset
      no ruleset applies to this repository

15 settings: 5 read, 0 partly read, 9 not read, 1 that do not apply. 7 requests sent, all GET.
```

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

Other options: `--branch NAME` audits another branch as well as the default one (repeatable); `--format json` prints the snapshot instead of the text report; `-o FILE` writes the report to a file; `--fail-on-unread` exits 1 if any setting that applies was not read in full; `--record DIR` also saves GitHub's answers as they arrived, for a bug report (see [Recordings](#recordings)).

Exit codes:

| Code | When |
| --- | --- |
| 0 | The audit ran. Some settings may not have been read; they are listed first in the report |
| 1 | Not even the repository could be read; or `--fail-on-unread` and something was not read in full; or an output file could not be written; or the command failed in a way it did not foresee (it says so, and says that nothing was established) |
| 2 | A usage error, or a snapshot file that cannot be used |

### In a workflow

A workflow's own token is refused the administrative settings, as it would be with no token, but it has its own rate limit (1,000 requests an hour for the repository, against 60 an hour for each IP address with no token), which matters on shared runners:

```yaml
permissions:
  contents: read
steps:
  - run: obaaf audit --repo "$GITHUB_REPOSITORY" --snapshot-out settings.json
    env:
      GITHUB_TOKEN: ${{ github.token }}
```

[`.github/workflows/settings-audit-live.yml`](../.github/workflows/settings-audit-live.yml) is this repository's own use of it. To read the settings marked "Token" in the table from a workflow, the token has to come from somewhere else (a fine-grained personal access token or a GitHub App with the read permissions named there, stored as a secret in an environment limited to the default branch). OBAAF does not create tokens and does not ask for more than read access.

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

When later rules are built on the snapshot, a rule that needs a setting that is not `read` must answer "cannot tell", never "pass".

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

The `settings` part depends only on the settings and on what the caller may see: values are cut down to what matters and put in a fixed order, so the same settings read with the same access give the same `settings`, whenever they are read and in whatever order GitHub lists them. Every snapshot is checked against the schema before it is written or reported; a setting whose value the schema refuses is recorded as not read. The rest of the file (`taken_at`, `requests`, `viewer`) differs from run to run.

What is in it that you might not want to publish: the names of secrets (never their values; GitHub does not return them), and the logins and team names that the settings themselves name: environment reviewers, and the people, teams and apps on classic branch protection's push and review-bypass lists. For a public repository the environment reviewers are already public; the secret names and the classic protection lists are not. There is no token in it, and no list of collaborators, only how many hold each role.

A snapshot given to `--from-snapshot` is checked before it is used, because a committed snapshot can be edited by anyone who can open a pull request: it must be under 20 MB, strict JSON with no key given twice, not deeply nested, in this format, and every setting must be present with a value of the documented shape. Only three settings can be marked as not applying (the bypass list, environment secrets and organisation secrets); a file that says so of any other is refused. A file that fails is refused (exit 2). A file that passes still says only what it says; drift detection (slice 2b.3) is what compares one with live settings. The format is a draft and may change before it is released.

### Recordings

`--record DIR` writes `DIR/responses.json`: each path requested, the status, a few response headers, and the body GitHub sent. It exists so that a wrong reading can be reported and turned into a test. It holds more than a snapshot (GitHub's full answers, including the logins of collaborators when that list was read), so look before sharing one. Request headers are not in it.

## What it does not read

Said plainly, so that nobody assumes otherwise:

- **It applies no rule.** It does not yet say that an environment open to every branch is a problem, or that required approvals cannot be met. That is slice 2b.2.
- **Which checks actually report on pull requests.** Comparing the required checks with what workflows report needs recent check runs, which are not a setting. Slice 2b.2.
- Custom deployment protection rules (gates run by a GitHub App), repository and environment variables, deploy keys, webhooks, tag protection other than rulesets, and the access level that lets other repositories call this one's reusable workflows.
- Organisation and enterprise settings, except rulesets and Actions policies from those levels that apply to this repository.
- Anything on GitHub Enterprise Server. `--api-url` exists, and has not been tried against one.

## Things the audit takes on trust

Each of these is a place where GitHub's reference did not settle the question. None has been confirmed against a live repository with an administrator's token.

- **A 404 from classic branch protection** means "this branch has no classic protection" only when GitHub's message is exactly "Branch not protected". GitHub's reference documents the 404 but not the message. Any other 404 is recorded as not read.
- **Sections missing from a classic branch protection** (required checks, required reviews, push restrictions) are recorded as not required. This is the one place where an absence is read as a value: GitHub leaves a section out when it is not configured, and the reading chosen is the one that reports less protection, never more. The list of who may bypass required reviews is the exception: when it is absent it is recorded as not known. The answer must still say whether administrators are held to the rule, or it is not taken for a protection at all.
- **`deployment_branch_policy: null`** means any branch or tag may deploy. GitHub's reference says so for setting the value ("To allow all branches to deploy, set to `null`"), not for reading it.
- **An empty bypass list** is not believed from anyone, as described [above](#the-bypass-list).
- **Collaborator roles** are read from each collaborator's `permissions` object, which must say true or false for all five of admin, maintain, push, triage and pull; if the object or one of the five is missing, the count is recorded as not read (`unexpected`), because an administrator whose `admin` field was missing would otherwise be counted in a lower role. That response's schema was not re-read on 2026-11-12. Seen on 2026-11-12 with the workflow's token: this repository's three collaborators, all administrators, were counted as "3 accounts: 3 admin".
- **What "protected" means** on the public view of a branch is not relied on. The flag is recorded as GitHub gives it. Seen on 2026-11-12: a branch protected only by a ruleset came back with `protected: true`, a `protection` object that says `enabled: false`, and an empty list of required checks, while the ruleset requires eleven. So the checks in this view are those of a classic protection rule only, and the report says "no required checks shown in this view" rather than "none". The checks a ruleset requires are under "Rules in force on each audited branch".
- **An environment limited to protected branches** is reported in those words ("only branches GitHub counts as protected may deploy"). Which branches that lets through depends on which have a protection rule, and the audit does not work that out.
- **"Administrators may bypass these rules"** on an environment is GitHub's `can_admins_bypass` field as it came, which GitHub sent to a caller with no token on 2026-11-12. The report says it only for an environment that has a reviewer, a wait timer or another protection rule. Whether it also lets an administrator past the limit on which branches may deploy is not something the audit claims.

<a id="what-has-been-run-and-what-has-not"></a>
## What has been run, and what has not

- **Run:** the tests in `tests/test_settings_audit.py`. They drive the reader from recordings in `tests/fixtures/settings/`. Three of the recordings were **written by hand** from the example responses in GitHub's REST reference: one for a caller with no token, one for a workflow's token and one for an administrator's. Two are **GitHub's own answers** to a caller with no token: this repository's from the run of 2026-11-12 06:32 UTC ([43168837657](https://github.com/Obaaf/OBAAF/actions/runs/43168837657)) and the first adopter's from the run of 01:33 UTC ([43135263367](https://github.com/Obaaf/OBAAF/actions/runs/43135263367)). So everything a token is needed for, and above all everything an administrator's token would show, is still tested only against hand-written answers. The real HTTP client is tested against a server on the test machine: that it sends GET with no body, sends the token only when it has one, does not follow a redirect to another host, and survives an answer that breaks off.
- **Run on GitHub:** the workflow above, four times on 2026-11-12, each on the reader as it then was (runs [43129074849](https://github.com/Obaaf/OBAAF/actions/runs/43129074849), [43135263367](https://github.com/Obaaf/OBAAF/actions/runs/43135263367), [43168837657](https://github.com/Obaaf/OBAAF/actions/runs/43168837657) and [43169162230](https://github.com/Obaaf/OBAAF/actions/runs/43169162230)). What follows is the last, at 06:35 UTC. On this repository with no token it read the five public settings in seven requests, as shown at the top of this page. With the workflow's own token it read the same and the collaborator count, and GitHub refused the other eight with HTTP 403, "Resource not accessible by integration", naming the permission it would accept (`administration=read`, `environments=read`, `secrets=read`, and `administration=write` for Actions policies). On the first adopter's repository, with no token, it read the ruleset that protects `main` with its eleven required checks, the rules in force on `main` and three environments, and recorded the ruleset's bypass list as not read. From the second run on, the job reads the adopter's repository as well and fails if any answer has an unexpected shape; those three runs passed.
- **What the live runs changed.** Reading the reports of the second and third runs found four faults in the report that the hand-written recordings had not shown: a rule was cut off after 60 characters, so three of eleven required checks were named; a pattern for tags was printed like one for branches; nothing said whether administrators may bypass an environment's reviewers; and a branch protected only by a ruleset was described as having no required checks. All four are fixed and the answers behind them are now test recordings. The workflow runs again whenever the reader changes; the pull request that changes it links the run.
- **Not run:** the audit with a token that has administrative read access, so every setting marked "Token" above except the collaborator count has only been read from hand-written recordings; a repository with classic branch protection read in full; a private repository; GitHub Enterprise Server.

## Sources

GitHub's REST reference and documentation, read on 2026-11-12 (API version `2026-03-10`, the one the reference's examples use). The pages were read through a tool that summarises them, so long sentences were pieced together from fragments; the response schemas' field descriptions were not available.

- Rules: [REST API endpoints for rules](https://docs.github.com/en/rest/repos/rules)
- Branches: [branches](https://docs.github.com/en/rest/branches/branches), [protected branches](https://docs.github.com/en/rest/branches/branch-protection)
- Environments: [environments](https://docs.github.com/en/rest/deployments/environments), [deployment branch policies](https://docs.github.com/en/rest/deployments/branch-policies)
- Secrets: [Actions secrets](https://docs.github.com/en/rest/actions/secrets)
- Actions settings: [permissions](https://docs.github.com/en/rest/actions/permissions), [policies](https://docs.github.com/en/rest/actions/policies), [about Actions policies](https://docs.github.com/en/actions/concepts/about-actions-policies)
- Repository and collaborators: [repositories](https://docs.github.com/en/rest/repos/repos), [collaborators](https://docs.github.com/en/rest/collaborators/collaborators)
- Using the API: [rate limits](https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api), [API versions](https://docs.github.com/en/rest/about-the-rest-api/api-versions), [troubleshooting](https://docs.github.com/en/rest/using-the-rest-api/troubleshooting-the-rest-api), [permissions required for fine-grained personal access tokens](https://docs.github.com/en/rest/authentication/permissions-required-for-fine-grained-personal-access-tokens)
