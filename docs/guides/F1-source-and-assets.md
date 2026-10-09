# F1 Source and assets

Control family F1 keeps every change that can reach a release reviewed and attributable, including build scripts, CI configuration, and engine and plugin code. It covers profile requirements [G1.1](../../spec/profile.md#g11-protect-release-branches-and-streams), [G1.2](../../spec/profile.md#g12-treat-the-build-definition-as-code) and [G1.3](../../spec/profile.md#g13-attribute-every-change).

This is draft guidance for OBAAF version 0.1. The studio pilot will test and revise it. Terms are explained in the [glossary](../glossary.md).

<a id="item-1-6"></a>
## Item 1.6: Protected release branches

**Why.** A change that can skip review can put anything into a release. A protected release branch is the barrier the other controls in this family build on.

**Do this.**

- List the branches or streams you release from, such as `main` and `release/*`.
- On GitHub, add a ruleset or branch protection to each: require a pull request before merging, require at least one approval, and block force pushes and deletion. See [GitHub settings](../github-settings.md#protect-release-branches). For a private repository this needs a paid plan; on GitHub Free there is no way to enforce it, so answer no until it is enforced.
- In Perforce (P4), restrict who can submit to release streams in the protections table. Requiring a review before submit takes P4 Code Review (formerly Helix Swarm) with a workflow that enforces reviews and its server triggers installed; the protections table alone cannot require a review.
- In other systems, use the equivalent: no direct pushes, a review before merge.

**Keep as evidence.** A screenshot or export of the protection settings for each release branch or stream.

<a id="item-1-7"></a>
## Item 1.7: Individual accounts

**Why.** History only says who changed what when every person has an individual account. Shared logins also make it impossible to remove one contractor's access without disrupting everyone.

**Do this.**

- Export the user list of your version control and CI systems.
- Replace every shared account used by people with individual accounts. Keep separate, named accounts for automation, such as a build account.
- Give contractors and porting partners their own accounts too (see [F9](F9-partners.md#item-2-8)).

**Keep as evidence.** The user list, with each account mapped to one person or one automated service.

<a id="item-2-2"></a>
## Item 2.2: Reviewed build-script changes

**Why.** Build scripts, packaging steps and CI configuration decide what ships. A change to them should need a second person, as a change to game code does (G1.2).

**Do this.**

- Keep build graphs, packaging and signing steps in version control. Build hosts should read their configuration only from there, not from local edits.
- On GitHub, add a CODEOWNERS file that names owners for `.github/workflows/`, build scripts and engine and plugin code, and turn on "Require review from Code Owners" for release branches. Start from [CODEOWNERS.example](../../templates/github-actions/CODEOWNERS.example).
- In Perforce, put build scripts under path-level protections, and use P4 Code Review workflows (as for item 1.6) to require a review by someone other than the author.
- Run `obaaf check` in CI: rule `OBAAF-REPO-001` reports workflow files with no code owner.

**Keep as evidence.** The protection rules on those paths, and the three most recent changes to them with their approvers.

<a id="item-4-1"></a>
## Item 4.1: Two approvers for release branches

**Why.** One reviewer can be busy, fooled or compromised. Two approvals make a single person's mistake or account takeover insufficient. This goes beyond SLSA Source Level 4, which asks for review by one trusted person other than the author.

**Do this.**

- Raise the required approvals on release branches to two.
- On GitHub, also turn on "Dismiss stale pull request approvals when new commits are pushed" and "Require approval of the most recent reviewable push", so the last change is always reviewed.
- Make sure no one can bypass the rule, including administrators, except through a documented emergency process.
- Make sure each code-owner team can give two approvals without the author: if authors come from the team, it needs at least three people.

**Keep as evidence.** The branch rules showing two required approvals.
