# F8 Automation and AI agents

Control family F8 lets a studio use AI agents and bots in its pipeline without lending them the pipeline's authority. An agent follows instructions found in the text it reads, and outsiders can write that text: a player's bug report, a community post, a partner's delivery, an issue or a pull request. The rule is *taint-bounded authority*: an agent may do no more than the least-trusted author of anything it reads could do directly. It covers profile requirements [G8.1](../../spec/profile.md#g81-bound-agent-authority-by-input-trust), [G8.2](../../spec/profile.md#g82-protect-agent-instructions-as-code) and [G8.3](../../spec/profile.md#g83-attest-agent-runs-and-verify-them-before-release), which are the [agent controls R1–R8](../../spec/agent-controls.md).

This is draft guidance for OBAAF version 0.1. The studio pilot will test and revise it. Terms are explained in the [glossary](../glossary.md).

<a id="item-3-6"></a>
## Item 3.6: Agents without secrets

**Why.** In the [Clinejection case](https://adnanthekhan.com/posts/clinejection/), any GitHub user could start an AI triage workflow; an issue title steered it into poisoning a cache that release jobs used, and publishing tokens were stolen. In the [PromptPwnd disclosures](https://www.aikido.dev/blog/promptpwnd-github-actions-ai-agents), issue text made agents expose the credentials their workflows held.

**Do this.**

- Find every agent and bot that player, community or partner content can start. In GitHub Actions, `obaaf check --lanes` lists the jobs it recognizes as agents; it knows common agent actions and command-line tools, so check the list against what you run, and add your own patterns to `.github/obaaf.yml`. Agents outside GitHub Actions need the same review by hand.
- Give each a read-only token, no secrets, no permission to request cloud credentials, no caches shared with release jobs, and no write access. The [agent lane template](../../templates/github-actions/workflows/obaaf-agent-propose.yml) does this.
- Keep the model credential in an inference proxy outside the job ([inference proxy](../inference-proxy.md)), so a steered agent cannot leak it. The job still holds a read-only token for the repository, which in a private repository can read its source: that is why the agent runs at the level of everything it reads.
- Let the agent only *propose*: a patch, comment text or labels. A separate job applies proposals after a person approves ([effect lane template](../../templates/github-actions/workflows/obaaf-agent-apply.yml)).
- Answer N/A only if you use no AI agents. If you use agents but none is started by public, player or partner content, the answer is yes.

**Keep as evidence.** The workflow permissions of each agent, and a clean `obaaf check` result.

<a id="item-3-7"></a>
## Item 3.7: Code-owner protection of agent files

**Why.** Files that steer agents (instruction files, rules files, MCP configuration, and the workflows that start agents) persist across runs. Hidden characters in a rules file were the vector in the [Rules File Backdoor case](https://www.pillar.security/blog/new-vulnerability-in-github-copilot-and-cursor-how-hackers-can-weaponize-code-agents).

**Do this.**

- Name owners for every agent instruction file and agent workflow in CODEOWNERS ([CODEOWNERS.example](../../templates/github-actions/CODEOWNERS.example)), and require code-owner review on protected branches.
- Load instructions from the protected base branch, never from the change under review. The agent lane template runs on issue events, so its base is the default branch: it checks that branch out and gives the agent a pull request's changes only as data.
- Run `obaaf check` in CI: it scans instruction files for hidden and direction-changing characters (`OBAAF-INS-001`) and reports instruction files without owners (`OBAAF-REPO-002`).
- Answer N/A only if you use no AI agents.

**Keep as evidence.** The protection rules on those paths.

<a id="item-4-5"></a>
## Item 4.5: Attested and verified agent runs

**Why.** In the Amazon Q extension case, code committed with an over-scoped token reached a release; nothing tied the release to how that change was made. A signed record of each agent run lets the release lane refuse changes that did not come through the approved agent path.

**Do this.**

- Use the agent templates and the publish template together. The agent lane signs an agent-run record. The effect lane checks it, signs an approval record, and commits both with the change, in `.obaaf/records/`.
- Before upload, the publish workflow's `obaaf verify release` checks every agent-authored commit since the policy's `agents.since` commit. Each must add a valid record of its own, used once, that matches the change. Its approval must come from someone other than the requester or the authors of the agent's inputs.
- The effect lane opens the agent's pull request with the job's own token, and GitHub starts no workflows for that. Close and reopen the pull request to start its required checks.
- Merge agent pull requests unchanged, in a way that keeps the commit and its message: a merge commit, a rebase, or a squash of the single commit. With `require_exact_diff: true` (the default), a change edited after approval blocks the release. Make follow-up changes in a separate pull request.
- Answer N/A only if you use no AI agents.

**Keep as evidence.** The attestations for agent-authored commits in the latest release.
