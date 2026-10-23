# Threat modeling autonomous AI agents in CI/CD pipelines

*An OBAAF white paper. Draft version 0.1.*

This paper states the threat model behind OBAAF's agent controls in a self-contained form, for a security working group, a conference audience, or a studio deciding whether the risk is real for them. It condenses the argument of the companion paper *Untrusted Text, Trusted Tokens* (Paper 1) and the machine-readable model in `src/obaaf/data/`. The controls it refers to are specified in full in [the agent controls](../spec/agent-controls.md) and placed in the pipeline in [the architecture](architecture.md).

Nothing here is a guarantee. The claim throughout is narrower and, we think, more useful: under stated assumptions, each control removes a specific precondition that documented attacks relied on.

## 1. Summary

Autonomous coding agents now read issues, pull-request comments and third-party documentation, and then act inside build pipelines that can ship software to millions of devices. The supply-chain frameworks the industry already relies on — SLSA, in-toto, SSDF, Scorecard — were built around human developers and deterministic runners. They do not have a primitive for an actor whose behaviour is steered at run time by text an attacker wrote.

The core failure is simple to state: **adding text to an agent's context must never add authority.** When it does, an outside author who can leave a comment can borrow the pipeline's power. Most of the 2025–2026 incidents below reduce to a version of that sentence.

OBAAF's answer is **taint-bounded authority**: every capability an agent invocation can exercise must be one its least-trusted influencer could already exercise directly. The eight agent controls (R1–R8) realise that principle on a real platform (GitHub Actions first), and each agent run produces a signed record so that what the agent saw, could do, and did is auditable after the fact.

## 2. Scope

**In scope.** Autonomous or semi-autonomous agents invoked inside CI/CD — triage bots, coding agents that open pull requests, release assistants — on hosted or self-hosted runners, reachable by repository events (issues, comments, pull requests) and by the content those events carry.

**Out of scope, and treated as assumptions.** Training-time model poisoning; compromise of the model provider, the CI platform itself, or a developer's workstation; and a publisher who ships malware deliberately. OBAAF assumes the platform enforces the boundaries it is configured with. Section 8 states what the model does *not* defend against, in full — the honest boundary matters as much as the claims.

**Audience.** Security engineers and maintainers evaluating agent risk; studios (OBAAF's first adopters) whose updates reach phones, consoles and PCs and whose teams rarely include security staff; and standards and funding reviewers.

## 3. Why agents break the existing trust model

A conventional pipeline rests on two assumptions:

1. The actors are **identifiable principals** — people and service accounts — whose authority is set in advance.
2. The build steps are **deterministic**: given the same inputs, they do the same thing.

An autonomous agent violates both. Its behaviour is a function of its context window, and that context is assembled at run time from whatever the triggering event dragged in — an issue body, a comment, a linked document, a tool's output. An attacker who can influence any of that can influence what the agent does. The agent is not a principal whose authority you set once; it is a conduit whose effective authority is whatever the most-privileged thing it can reach will do on its behalf.

Existing standards still apply to everything around the agent, and OBAAF builds on them rather than replacing them (Section 9). What they lack is the one new primitive: a way to bound an agent's authority by the trust of the text that steered it.

## 4. Assets and trust levels

What an attacker ultimately wants is the pipeline's **publishing authority** — the ability to put a build in front of users — and the materials that protect it: signing keys, release credentials, repository secrets, and write access to protected branches and to the files that steer agents.

OBAAF orders principals and the content they influence on a four-level chain (Paper 1, §3.2):

| Level | Can, at this level |
| --- | --- |
| **Public** | Comment on a public issue; open a pull request from a fork |
| **Contributor** | Push to a non-protected branch; apply labels |
| **Maintainer** | Merge to a protected branch; edit workflow or agent-instruction files; read repository secrets |
| **Release** | Approve or publish a release; use a signing key |

Public ⊑ Contributor ⊑ Maintainer ⊑ Release. The integrity level of an agent invocation is the level of the **least-trusted** principal able to influence anything the agent reads. A run that reads a public comment is a Public run, whatever account launched it.

## 5. Adversaries and attack paths

Three agent adversaries (Paper 1, §3.3):

- **A1 — outside author.** Can leave public content: an issue, a comment, a fork pull request, a linked page.
- **A2 — upstream supplier.** Controls a tool, action, container, MCP server or model the pipeline consumes.
- **A3 — low-privilege insider.** Has Contributor-level access but not Maintainer or Release.

These sit alongside the build-pipeline attack paths OBAAF's game profile already addresses ([architecture](architecture.md)): **AP1** build environment, **AP2** signing material, **AP3** publishing/update channel, **AP4** third-party component. The agent path is the newest entry: outside text steering a privileged automated actor.

## 6. Root causes

Every incident in Section 7 traces to one or more of three root causes. They are the spine of the model; the controls exist to remove them.

- **RC1 — authority from untrusted context.** The agent's effective authority is decided by content an attacker can influence, because inputs are not labelled by provenance or are read after authority is set.
- **RC2 — standing or ambient authority.** The run holds power the task did not need: long-lived credentials, write scopes, secrets, reachable metadata endpoints, or caches shared with trusted jobs.
- **RC3 — no verifiable record.** There is no tamper-evident account of what the agent saw, what authority it held, and what it produced, so compromise is neither prevented nor cleanly audited.

## 7. Threat classes

Each class names the mechanism, the root cause, and the controls that answer it. The controls are specified in [the agent controls](../spec/agent-controls.md).

### 7.1 Indirect prompt injection via workflow context
An issue title, a pull-request comment, or third-party documentation carries instructions that the agent treats as its own task. *Root cause:* RC1. *Answer:* label inputs by provenance and bind the snapshot (R1); derive authority from the labels so an injected, untrusted input cannot unlock write scopes or secrets (R2); contain the blast radius (R7).

### 7.2 Tool-calling and egress escalation
An agent with shell or network tools reaches beyond the repository — cloud metadata endpoints, internal services, exfiltration channels. *Root cause:* RC2. *Answer:* default-deny egress and run isolation (R7); per-invocation, narrowly scoped, short-lived identity so a stolen token is nearly worthless (R3).

### 7.3 Instruction-plane drift and poisoning
The files that steer agents — system prompts, rule files, tool allow-lists, MCP configs, and the workflows that invoke agents — are modified to change behaviour, sometimes subtly across a multi-commit pull request or with hidden characters. *Root causes:* RC1, RC3. *Answer:* treat the instruction plane as code — protected branch, code-owner review, hidden-character scanning, and loaded from the protected base branch rather than from the change under review (R5).

### 7.4 Provenance and identity confusion
A run's authority is decided by who launched it rather than by the trust of what it read; or an agent's output is later mistaken for a trusted human's. *Root causes:* RC1, RC2. *Answer:* authority from input labels, not invoker (R2); a distinct workload identity per invocation (R3); separation of proposal from effect so agent output is never silently trusted (R4).

### 7.5 Cross-lane cache and state bleed
A low-trust run writes a cache or shared state that a release or effect job later consumes, turning a triage run into a release compromise. *Root cause:* RC2. *Answer:* isolation with no writable state shared with release jobs (R7); release caches not writable by untrusted builds (build profile).

### 7.6 Supply chain of tools and models
A compromised action, container, MCP server, tool description, or model shifts agent behaviour. *Root cause:* RC1. *Answer:* pin tools by immutable digest and verify provenance; treat descriptions and outputs from unverified servers as untrusted input (R6).

### 7.7 Unrecorded action
Even when an attack is contained, without a signed record there is no way to know what an agent saw or did. *Root cause:* RC3. *Answer:* a signed agent-run attestation whose trusted fields are produced by jobs the agent cannot influence; release verification refuses changes made through the agent path without one (R8).

## 8. The principle and the controls

**Taint-bounded authority.** For every capability *c* reachable from an agent invocation α, the lowest trust level allowed to cause *c* must dominate the integrity level of α — the level of the least-trusted principal able to influence anything α reads. Reads of private source and of secrets are themselves capabilities, so they are withheld from any invocation that untrusted text can steer.

The eight controls realise this, each answering a root cause:

| Control | In one line | Root cause |
| --- | --- | --- |
| **R1** | Label inputs by provenance; bind the snapshot the agent reads | RC1 |
| **R2** | Derive token scopes, secrets and network from the input labels | RC1, RC2 |
| **R3** | Give each invocation its own short-lived, narrowly scoped identity | RC2 |
| **R4** | Separate proposals from effects; a different identity applies them after independent approval | RC2 |
| **R5** | Protect the instruction plane as code | RC1, RC3 |
| **R6** | Verify tools and models as supply-chain inputs | RC1 |
| **R7** | Isolate the run; deny egress by default | RC2 |
| **R8** | Attest every agent run; verify at release | RC3 |

A structural consequence: the pipeline is split into **lanes** — untrusted, agent, effect, release — each a separate job with its own identity, so the platform, not the agent or the build, enforces the boundary. The agent lane's only output is a proposal; a separate effect lane applies it, under a different identity, after someone other than the requester approves. Integrity rises only through certified endorsement.

## 9. Documented incidents

The model is checked against real cases rather than asserted. For each, OBAAF records the root causes and which controls would have **prevented** (removed the precondition) or **contained** (limited the damage) the outcome, under the assumptions in Section 10. The distinction is deliberate: "prevent" and "contain" are different, and neither is "guarantee."

| Case | Disclosed | Status | Root causes | Prevented by | Contained by |
| --- | --- | --- | --- | --- | --- |
| Rules File Backdoor | 2025-03 | Demonstrated | RC1, RC3 | R5 (if the file entered through review) | R4, R8 |
| GitHub MCP | 2025-05 | Demonstrated | RC1, RC2 | R2 | R1, R3 |
| GitLab Duo | 2025-05 | Demonstrated | RC1, RC2 | R2 | R7 |
| Gemini CLI | 2025-07 | Demonstrated | RC1, RC2 | — | R2, R7 |
| Amazon Q extension | 2025-07 | Exploited | RC2, RC3 | R3, R4, R5 | R8 |
| Nx "s1ngularity" | 2025-08 | Exploited | RC1, RC2, RC3 | R1, R2, R3, R4 | R8 |
| CamoLeak | 2025-10 | Demonstrated | RC1, RC2 | R2 | R7 |
| PromptPwnd | 2025-12 | Demonstrated | RC1, RC2 | R2, R3 | R4, R7 |
| Claude Code action | 2026-02 | Demonstrated | RC1, RC2 | R1 | R2 |
| Clinejection | 2026-02 | Exploited | RC1, RC2, RC3 | R7 | R2, R3, R8 |

A reproducible counterpart to this table lives in the repository as a corpus of risky workflow fixtures under `tests/fixtures/workflows/`, modelled on these incidents, which OBAAF's checker flags. That corpus — not a claim of stopping every attack — is the honest basis for any benchmark.

## 10. What this model does not defend against

Stated plainly, because a threat model that omits its boundary is marketing:

- **Harm at the adversary's own level.** A steered Public-level agent can still post a misleading comment or waste its budget. Comment filters, label allow-lists and (in a later version) an inference proxy's budget limit this.
- **Endorsement failure.** A human reviewer can approve a malicious proposal. Records make agent-authored changes identifiable so they get extra scrutiny; they do not make reviewers infallible.
- **Labelling errors.** Labels must match the platform's real settings — who may comment, who holds which role. A wrong label is a wrong authority.
- **Platform, provider, or workstation compromise**, and a publisher who ships malware on purpose.
- **A tier is not a guarantee.** It describes controls in place, not an assurance that software is safe.

## 11. Standards alignment

OBAAF is interoperable by design — it builds on in-toto, SLSA, OIDC and Sigstore rather than inventing cryptography, and maps to the frameworks teams already report against. The profile and agent controls carry mappings to **NIST SSDF (SP 800-218)**, **SLSA v1.2**, and relevant **NIST NCCoE** topics ([the agent controls](../spec/agent-controls.md)).

The crosswalk below is added by this paper, to **OWASP Top 10 for LLM Applications (2025)**, in the CI/CD context. It is deliberately explicit about partial and out-of-scope coverage.

| OWASP LLM (2025) | OBAAF controls | Coverage |
| --- | --- | --- |
| LLM01 Prompt Injection | R1, R2, R7 | Core — bound authority by input trust; contain |
| LLM02 Sensitive Information Disclosure | R2, R3, R7 | Strong — no secrets/egress for tainted runs |
| LLM03 Supply Chain | R6 + build profile | Strong — pin and verify tools; provenance |
| LLM04 Data and Model Poisoning | R5, R6 | Partial — instruction/tool integrity; training-data poisoning is out of scope |
| LLM05 Improper Output Handling | R4, R1 | Strong — agent output is a proposal, never a silent effect |
| LLM06 Excessive Agency | R2, R3, R4 | Core — the taint-bounded-authority principle itself |
| LLM07 System Prompt Leakage | R5, R2 | Partial — integrity of the instruction plane; OBAAF bounds authority rather than relying on prompt secrecy |
| LLM08 Vector/Embedding Weaknesses | R1 | Out of scope mostly — retrieved context is labelled if it enters the snapshot; RAG store security is not addressed |
| LLM09 Misinformation | R8, R4 | Partial — provenance and human endorsement; OBAAF does not judge output correctness |
| LLM10 Unbounded Consumption | R3, R7 | Partial — scoped identity and egress; budget limits arrive with the inference proxy (planned) |

## 12. Using the model

1. **Assess.** Run the 34-question self-assessment to get a tier and a ranked list of fixes (`obaaf assess`). Answers stay on your machine.
2. **Check.** Run the pipeline checker on your workflows (`obaaf check`).
3. **Adopt the lanes.** Install the reference templates and make the agreed checks block merges and releases.
4. **Verify.** Require signed provenance, approvals and agent records before a build is published (`obaaf verify`).

See [the adoption guide](adoption-guide.md) and [the architecture](architecture.md). OBAAF is in active adoption with pilot teams; broader platform validation continues, and more pilot teams and reviewers are welcome — see [the project README](../README.md).

## 13. Known gaps

Honesty about current limits (tracked in [DECISIONS.md](../DECISIONS.md) and [CHANGELOG.md](../CHANGELOG.md)):

- **Egress enforcement (R7)** is declared but, by default, enforced only by a monitor or network policy rather than a hard boundary; the strongest isolation needs self-hosted ephemeral runners or a dedicated runtime.
- **The inference proxy** that holds the model credential and enforces a budget is specified, not yet built.
- **Model pinning (R6)** by digest is not yet implemented; hosted models expose no stable hash.
- **Live platform tests** confirming behaviours such as a fork pull request being denied secrets have not been run on a sandbox repository yet.

These are design boundaries, not surprises; naming them is part of the model.

## 14. References

- Companion paper: *Untrusted Text, Trusted Tokens* — agent assurance (the source of R1–R8). See `papers/`.
- [The agent controls](../spec/agent-controls.md) · [The architecture](architecture.md) · [Attestation formats](attestations.md)
- NIST SP 800-218 (SSDF): https://doi.org/10.6028/NIST.SP.800-218
- SLSA v1.2: https://slsa.dev/spec/v1.2/
- in-toto attestation framework: https://github.com/in-toto/attestation
- Sigstore: https://www.sigstore.dev/
- OWASP Top 10 for LLM Applications (2025): https://genai.owasp.org/
