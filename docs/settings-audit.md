# The settings audit: `obaaf audit`

*Status: first part. The command reads a repository's GitHub settings and records what it read and what it could not. **It applies no rule yet**, so it reports no findings; the rules are the next slice of the [flagship plan](flagship.md) (2b.2). What has and has not been run against GitHub is listed [at the end](#what-has-been-run-and-what-has-not).*

`obaaf check` reads workflow files. Some of what decides whether a workflow is safe is not in any file: which branches may use an environment, who may bypass a ruleset, which checks are required, which events GitHub lets start a workflow. In the first adopter's first two days every real incident was one of those settings, and `obaaf check` saw none of them.

`obaaf audit` reads those settings through GitHub's REST API. It sends GET requests only. Whatever it could not read is listed by name with the reason, so "not read" can never be mistaken for "nothing wrong".

## Run it

In a clone of a repository on github.com:

```bash
obaaf audit                      # finds OWNER/REPO from the origin remote
obaaf audit --repo OWNER/REPO    # or name it
```

With no token this reads what GitHub shows anyone about a public repository: the repository itself, its rulesets and their rules, the rules in force on the default branch, whether GitHub calls that branch protected, and its environments with the branches that may deploy to each. Everything else is listed under **NOT READ** with what GitHub's reference says a token would need.

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

Other options: `--branch NAME` audits another branch as well as the default one (repeatable); `--format json` prints the snapshot instead of the text report; `--fail-on-unread` exits 1 if any setting that applies was not read in full; `--record DIR` also saves GitHub's answers as they arrived, for a bug report (see [Recordings](#recordings)).

Exit codes: 0 when the audit ran, even if some settings were not read (they are listed first in the report); 1 when not even the repository could be read, or with `--fail-on-unread` when something was not read in full; 2 for a usage error or a snapshot file that cannot be used.

### In a workflow

A workflow's own token can read no more of a public repository's settings than anyone can, but it has its own rate limit (1,000 requests an hour for the repository, against 60 an hour for each IP address with no token), which matters on shared runners:

```yaml
permissions:
  contents: read
steps:
  - run: obaaf audit --repo "$GITHUB_REPOSITORY" --snapshot-out settings.json
    env:
      GITHUB_TOKEN: ${{ github.token }}
```

[`.github/workflows/settings-audit-live.yml`](../.github/workflows/settings-audit-live.yml) is this repository's own use of it. To read the settings marked "token" in the table from a workflow, the token has to come from somewhere else (a fine-grained personal access token or a GitHub App with the read permissions named there, stored as a secret in an environment limited to the default branch). OBAAF does not create tokens and does not ask for more than read access.

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
| `environments` | Each environment's reviewers, wait timer, and which branches and tags may deploy to it | `/repos/{owner}/{repo}/environments`, `/repos/{owner}/{repo}/environments/{name}/deployment-branch-policies` | Anyone, for a public repository ("Actions", read) |
| `environment_secrets` | The names of the secrets in each environment | `/repos/{owner}/{repo}/environments/{name}/secrets` | Token: "Environments" (read) |
| `repository_secrets` | The names of the repository's secrets, which every workflow on every branch can read | `/repos/{owner}/{repo}/actions/secrets` | Token: "Secrets" (read) |
| `organization_secrets` | The names of the organisation secrets this repository receives | `/repos/{owner}/{repo}/actions/organization-secrets` | Token: "Secrets" (read) |
| `actions_permissions` | Whether Actions is on, which actions may run, whether pinning to a commit is required | `/repos/{owner}/{repo}/actions/permissions`, `/repos/{owner}/{repo}/actions/permissions/selected-actions` | Token: "Administration" (read) |
| `workflow_permissions` | What the workflow token may do by default, and whether workflows may approve pull requests | `/repos/{owner}/{repo}/actions/permissions/workflow` | Token: "Administration" (read) |
| `fork_pull_requests` | Whose fork pull requests need approval before workflows run; on a private repository, whether they get secrets and write tokens | `/repos/{owner}/{repo}/actions/permissions/fork-pr-contributor-approval`, `/repos/{owner}/{repo}/actions/permissions/fork-pr-workflows-private-repos` | Token: "Administration" (read) |
| `actions_policies` | Actions policies (workflow execution protections): who and which events may start which workflows, including policies from the organisation or enterprise that apply here | `/repos/{owner}/{repo}/actions/policies`, `/repos/{owner}/{repo}/actions/policies/{id}` | Token: "Administration" (**write**). See [below](#what-needs-more-than-read) |
| `collaborators` | How many accounts hold each role. Counts only; no login is kept | `/repos/{owner}/{repo}/collaborators` | Token of someone with write, maintain or admin access |

Without a token the audit does not ask for the settings marked "Token": the answer is known, and each request would count against the 60 an hour GitHub allows an address with no token. They are recorded as not read, with the reason `no_token`. A run with no token sends about eight requests, plus one for each ruleset and one for each environment that limits deployment to named branches.

The audit reads only settings that a repository's own workflows depend on (plan decision F-23). It is not a tool for checking a whole organisation against a standard; [the landscape](landscape.md) names tools that are.

### What needs more than read

Two things are shown only to a caller who could also change them. OBAAF never asks for that access. With a token that happens to have it, the audit reads them; otherwise they are listed as not read and an administrator has to look in the repository's settings.

<a id="the-bypass-list"></a>
- **Who may bypass a ruleset.** GitHub's reference: "the `bypass_actors` property is only returned if the user making the API request has write access to the ruleset". When the field is missing the audit records the list as not read (`withheld`). An **empty** list is recorded as "nobody may bypass" only when it comes with a token whose owner GitHub reports as an administrator of the repository, for a ruleset that belongs to the repository. In every other case an empty list is recorded as not read, because it has not been established here that GitHub leaves the field out, rather than sending it empty, for a caller without write access. A list with entries is always recorded.
- **Actions policies.** GitHub's reference asks for the "Administration" permission with write access even to list them. This is the setting behind one of the adopter's incidents (a policy allowed two events for one workflow, so a third trigger failed before any job started), and a read-only audit will usually have to report it as not read.

## What "not read" looks like

Every setting is in the snapshot with one of four statuses:

| Status | Meaning |
| --- | --- |
| `read` | The value is in the snapshot |
| `partial` | Some of it was read; `problems` names each part that was not (one ruleset out of three, one environment's branch patterns) |
| `unread` | It was not read. `reason_code` and `reason` say why, `needs` says what GitHub's reference asks of a caller, and `accepted_permissions` repeats GitHub's `X-Accepted-GitHub-Permissions` header when it sent one |
| `not_applicable` | The setting does not exist for this repository (organisation secrets of a user's repository, the bypass list when there is no ruleset) |

The reason codes:

| Code | Meaning |
| --- | --- |
| `no_token` | Not requested: no token was given and GitHub does not show this without one |
| `unauthorized` | GitHub did not accept the token (HTTP 401) |
| `forbidden` | GitHub refused (HTTP 403) |
| `not_found` | GitHub answered 404, which it also sends when the caller may not see something, "to avoid confirming the existence of private repositories" |
| `rate_limited` | GitHub's rate limit was reached. The audit stops asking at once and records everything it had not yet read under this code |
| `network` | No answer was received |
| `server_error` | GitHub had an error (HTTP 5xx) |
| `unexpected` | The answer did not have the shape GitHub documents. The audit does not guess: an environment whose answer has no `deployment_branch_policy` field is not taken to allow every branch, and a ruleset with no list of rules is not taken to be empty |
| `withheld` | GitHub left it out of an answer it otherwise gave (the bypass list) |
| `depends` | Not requested, because something it depends on was not read |

When later rules are built on the snapshot, a rule that needs a setting that is not `read` must answer "cannot tell", never "pass".

## Tokens

- The token is read from `GH_TOKEN`, then `GITHUB_TOKEN`, or from the variable named by `--token-env`. There is no option that takes a token on the command line, where it would end up in the shell's history and the process list.
- It is sent only to the API address the audit was started with. A redirect to another host is not followed. With `--api-url`, a token is used only if `--token-env` names it; the default variables are for github.com alone.
- Only GET requests are sent. The client has no other verb.
- TLS certificates are always verified. There is no option to turn that off.
- The token is not written to the report, the snapshot or a recording. Request headers are never recorded.
- A token with read access is enough for everything except the two things [above](#what-needs-more-than-read). For a fine-grained personal access token, the repository permissions GitHub's reference names are "Administration", "Secrets", "Environments", "Actions" and "Contents", each with read access ("Metadata" comes with any of them). The collaborator count also needs the token's owner to have write access to the repository.

## The snapshot

A snapshot is one JSON file, `obaaf-settings-snapshot/v0.1`, described by [a JSON Schema](../src/obaaf/data/schemas/settings-snapshot.schema.json). It holds:

- `settings`: one entry for each key above, as described under [What "not read" looks like](#what-not-read-looks-like). Values are cut down to what matters and put in a fixed order, so two snapshots of unchanged settings are the same text.
- `viewer`: what GitHub said about the caller (whether a token was used, the caller's role on the repository, whether the caller may bypass each ruleset). It is kept apart from `settings` because it changes with who asks.
- `requests`: every path requested and the status of the answer.
- `repository`, `branches`, `api`, `api_version`, `taken_at`, `tool`.

What is in it that you might not want to publish: the names of secrets (never their values; GitHub does not return them), the logins and team names of environment reviewers, and the lists of who may bypass rules. For a public repository the reviewers and rules are already public; the secret names and bypass lists are not. There is no token in it.

A snapshot loaded with `--from-snapshot` is checked before it is used: the format must be this one, every setting must be present with a known status, and nothing unknown may be in it. A file that fails is refused (exit 2). The format is a draft and may change before it is released.

### Recordings

`--record DIR` writes `DIR/responses.json`: each path requested, the status, a few response headers, and the body GitHub sent. It exists so that a wrong reading can be reported and turned into a test. It holds more than a snapshot (GitHub's full answers, including the logins of collaborators when that list was read), so look before sharing one. Request headers are not in it.

## What it does not read

Said plainly, so that nobody assumes otherwise:

- **It applies no rule.** It does not yet say that an environment open to every branch is a problem, or that required approvals cannot be met. That is slice 2b.2.
- **Which checks actually report on pull requests.** Comparing the required checks with what workflows report needs recent check runs, which are not a setting. Slice 2b.2.
- Custom deployment protection rules (gates run by a GitHub App), repository and environment variables, deploy keys, webhooks, who may push under classic "restrictions" beyond their names, tag protection other than rulesets, and the access level that lets other repositories call this one's reusable workflows.
- Organisation and enterprise settings, except rulesets and Actions policies from those levels that apply to this repository.
- Anything on GitHub Enterprise Server. `--api-url` exists, and has not been tried against one.

## Things the audit takes on trust

Each of these is a place where GitHub's reference did not settle the question, and the audit chose the reading that cannot turn "unknown" into "fine". None has been confirmed against a live repository with an administrator's token.

- **A 404 from classic branch protection** means "this branch has no classic protection" only when GitHub's message is exactly "Branch not protected". GitHub's reference documents the 404 but not the message. Any other 404 is recorded as not read.
- **`deployment_branch_policy: null`** means any branch or tag may deploy. GitHub's reference says so for setting the value ("To allow all branches to deploy, set to `null`"), not for reading it.
- **An empty bypass list** is believed only from a repository administrator, as described [above](#the-bypass-list).
- **Collaborator roles** are read from each collaborator's `permissions` object (admin, maintain, push, triage, pull). That response's schema was not re-read on 2026-11-12; if the object is missing the count is recorded as not read (`unexpected`).

<a id="what-has-been-run-and-what-has-not"></a>
## What has been run, and what has not

- **Run:** the tests in `tests/test_settings_audit.py`. They drive the reader from recordings in `tests/fixtures/settings/`, which were **written by hand** from the example responses in GitHub's REST reference; they are not recordings of a live repository. The real HTTP client is tested against a server on the test machine: that it sends GET, sends the token only when it has one, and does not follow a redirect to another host.
- **Run on GitHub:** see the pull request that added this page for the result of the live workflow on this repository, with the workflow's own token and with no token.
- **Not run:** the audit with a token that has administrative read access, so every setting marked "Token" above has only been read from hand-written recordings; a private repository; a repository whose rulesets come from an organisation or enterprise; GitHub Enterprise Server.

## Sources

GitHub's REST reference and documentation, read on 2026-11-12 (API version `2026-03-10`, the one the reference's examples use). The pages were read through a tool that summarises them, so long sentences were pieced together from fragments; the response schemas' field descriptions were not available.

- Rules: [REST API endpoints for rules](https://docs.github.com/en/rest/repos/rules)
- Branches: [branches](https://docs.github.com/en/rest/branches/branches), [protected branches](https://docs.github.com/en/rest/branches/branch-protection)
- Environments: [environments](https://docs.github.com/en/rest/deployments/environments), [deployment branch policies](https://docs.github.com/en/rest/deployments/branch-policies)
- Secrets: [Actions secrets](https://docs.github.com/en/rest/actions/secrets)
- Actions settings: [permissions](https://docs.github.com/en/rest/actions/permissions), [policies](https://docs.github.com/en/rest/actions/policies), [about Actions policies](https://docs.github.com/en/actions/concepts/about-actions-policies)
- Repository and collaborators: [repositories](https://docs.github.com/en/rest/repos/repos), [collaborators](https://docs.github.com/en/rest/collaborators/collaborators)
- Using the API: [rate limits](https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api), [API versions](https://docs.github.com/en/rest/about-the-rest-api/api-versions), [troubleshooting](https://docs.github.com/en/rest/using-the-rest-api/troubleshooting-the-rest-api), [permissions required for fine-grained personal access tokens](https://docs.github.com/en/rest/authentication/permissions-required-for-fine-grained-personal-access-tokens)
