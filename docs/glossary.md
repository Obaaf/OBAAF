# Glossary

Plain-language meanings of the terms the guides and specifications use. The first five rows follow the specification's own terms table.

| Term | Meaning |
| --- | --- |
| Build pipeline (CI/CD) | The automated system that turns a team's source code and assets into the files players install, and publishes them |
| Provenance | A signed record of how a file was built: from which source, with which tools, on which machine |
| SSDF | NIST's Secure Software Development Framework (SP 800-218), the federal baseline for secure software development |
| SLSA | Supply-chain Levels for Software Artifacts, an industry framework for build integrity with graded levels for builds (Build track) and for source control (Source track) |
| Taint-bounded authority | Paper 1's rule: an AI agent may do no more than the least-trusted author of anything it reads could do directly |
| Agent | A program, usually built on a large language model, that reads text and takes actions such as editing code or posting comments. Agents follow instructions found in what they read, which is how prompt injection works |
| MCP | Model Context Protocol: a common way to give an agent extra tools, such as access to an issue tracker. Its configuration files steer what an agent can do, so OBAAF protects them like instruction files |
| Prompt injection | Instructions hidden in text an AI agent reads, which the agent may follow as if they came from its operator |
| Attestation | A signed statement about a file, identified by its digest: for example, that a workflow built it, or that a person approved it. OBAAF's attestations use the in-toto format |
| in-toto | An open format for attestations: a statement listing the files it is about (subjects) and a body of claims (predicate) |
| DSSE | Dead Simple Signing Envelope: the signed wrapper around an in-toto statement, used when signing with your own key (`signing: keys`) |
| Sigstore | An open service for signing without long-lived keys: a signer proves its identity and receives a short-lived certificate. GitHub's artifact attestations use it: for public repositories through Sigstore's public instance, which records each signature in a public transparency log, and for private repositories through GitHub's own instance, which does not |
| cosign | Sigstore's command-line tool for signing and verifying, which can also sign with a key held in a key service |
| OpenID Connect (OIDC) | A standard way for a CI job to prove its identity to another service and receive a short-lived credential, instead of storing a password or key |
| Digest | A short fingerprint of a file (OBAAF uses SHA-256). Any change to the file changes its digest |
| Vendored | Third-party code or binaries copied into your own repository, rather than fetched by a package manager at build time |
| Binary manifest | OBAAF's list of every vendored engine, SDK and plugin file with its digest, so an unrecorded change fails the build (item 2.6) |
| Keystore | A file that holds signing keys, such as an Android upload key; a file can be copied, so keys belong in hardware or a key service |
| Derived data | Files an engine generates from source assets, such as compiled shaders and cooked content, often kept in a shared cache to save build time |
| Content-addressed | Stored and looked up by digest, so an entry cannot be swapped without its address changing |
| Cache poisoning | Writing a malicious entry into a cache that a later, more trusted build reads |
| Egress | Network traffic leaving a machine. An egress allow-list permits only named destinations |
| Ephemeral | Used for one job and then destroyed, so nothing an attacker leaves behind survives |
| Isolation tier A and B | Paper 2's levels of build isolation: Tier A, a fresh environment per build; Tier B, persistent hosts dedicated to the release lane and reimaged on a schedule, reported as below SLSA Build Level 3 |
| Self-assessment tier | One of the four levels (Accounted, Controlled, Verified, Assured) a studio reaches by answering yes to every item at that level and below. Separate from isolation tiers |
| Lane | A separate CI job or workflow with its own identity and permissions: untrusted, agent, effect or release |
| Trust level | Public, Contributor, Maintainer or Release: how far the author of some text, or a job, is trusted |
| Integrity level | The lowest trust level among everything an agent run can read; the run gets no more authority than that |
| Snapshot | The record, taken before an agent starts, of everything it will read, with each item's digest and trust level |
| Proposal bundle | What an agent may produce: a patch, comment text, or label changes. A separate job applies it after approval |
| Agent record | The file committed with an agent-authored change, holding the proposal and its signed agent-run and approval records |
| GitHub Actions | GitHub's CI system. A **workflow** file defines **jobs**, each made of **steps**, which run on a **runner** |
| Jenkins | A self-hosted CI server. A **Jenkinsfile** defines a pipeline of **stages**, which run on **agents** that a **controller** schedules. `obaaf check` reads Jenkinsfiles as an advisory auditor ([Jenkins](jenkins.md)) |
| Runner | The machine that runs a job. GitHub-hosted runners are new for every job; self-hosted runners are your own machines and keep state unless set up as ephemeral |
| Fork | A copy of a repository under another account. Pull requests from forks get no secrets and a read-only token by default |
| Default branch | The repository's main branch, usually `main`, which GitHub uses for workflows started by issues, comments and other workflows |
| CODEOWNERS | A file naming the people or teams who must approve changes to given paths, when "Require review from Code Owners" is on |
| Ruleset | GitHub's rules for branches or tags, such as requiring reviews before merging or limiting who can create release tags |
| Stream | Perforce's equivalent of a branch, such as a release stream |
| SARIF | A standard file format for the results of code-checking tools; GitHub can show SARIF results in a repository's Security tab |
| Environment (GitHub) | A named deployment target with its own secrets and protection rules, such as required reviewers who must approve before a job runs |
| `pull_request_target`, `workflow_run`, `issue_comment` | Workflow triggers that run with the repository's own permissions even though outsiders can cause them, so they need care |
| Script injection | Text an outsider controls, such as an issue title, pasted into a script with `${{ }}` and run as commands |
| Cohen's kappa | A measure of how often two people give the same answer, beyond what chance would produce; 0.61 or higher is conventionally read as substantial agreement |
