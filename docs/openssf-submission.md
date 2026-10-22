# Proposal: an in-toto predicate for AI-agent runs in CI/CD

*Draft submission to the OpenSSF (AI/ML Security and Supply Chain Integrity working groups). For community review.*

## What we propose

We propose the **OBAAF agent-run predicate** (and its companion approval predicate) as a candidate interoperable, in-toto–compatible schema for recording and verifying the actions of autonomous AI coding agents inside build pipelines. The goal is a common, vendor-neutral way to answer, cryptographically and after the fact: *what did this agent see, what authority did it hold, what did it produce, and who endorsed applying it?*

We are seeking review of the schema and its field choices, feedback on alignment with existing work, and — if the working group finds it useful — a path toward community stewardship of the predicate under an open license.

## Why now

Autonomous coding agents (Copilot Workspace, Devin, OpenHands, Claude Code, and others) increasingly act inside CI/CD. The supply-chain frameworks the ecosystem relies on — SLSA, in-toto, Scorecard, SSDF — were designed for human developers and deterministic runners. They have no primitive for an actor whose behaviour is steered at run time by untrusted text (an issue, a comment, a fetched document). A run of 2025–2026 incidents (Amazon Q, Nx "s1ngularity", Clinejection, and others) turned on exactly that gap. Provenance that records *an agent ran here, steered by these inputs, with this authority* is missing, and it is the natural next predicate above build provenance.

## What already exists (reference implementation)

This is not a concept paper; a working reference implementation exists under the Apache-2.0–licensed OBAAF project:

- **JSON Schemas:** `agent-run.schema.json` and `agent-approval.schema.json`.
- **Producers/verifiers:** `obaaf attest agent-run | approval` and `obaaf verify agent-run`, signing through GitHub's **keyless Sigstore** (Fulcio + the public Rekor transparency log) with no long-lived key.
- **A control model:** the eight agent controls (R1–R8) and a [threat model](threat-model.md), grounded in a companion research paper.
- **A conformance surface:** a checker, reference GitHub Actions templates, and an offline test suite.

## The predicate, in brief

The agent-run predicate binds, for one invocation:

- `trigger` — event, repository, and the triggering principal with its trust level;
- `inputs` — each input the agent read, by digest, channel, and provenance label, plus the computed **integrity level** (the lowest label present);
- `authority` — the token permissions, named secrets, network policy, and identity the job actually held, read from the protected workflow definition;
- `agent` — the actions/harness by digest, and the model identity as reported out-of-band;
- `trace` — the agent's own account of its tool calls, explicitly marked **untrusted**;
- and, in the approval predicate, the human endorsement by someone other than the requester.

**The design principle worth standardizing:** every trusted field is produced by a job the agent cannot influence; the only agent-authored field is labelled untrusted. That separation — trusted context around an untrusted actor — is what makes an agent-run record meaningful, and it is what a shared schema should enforce.

## How it complements existing work

| Layer | Owner | OBAAF's relation |
| --- | --- | --- |
| Attestation envelope and statement | in-toto | Uses it; the predicate is an in-toto predicate type |
| Build provenance | SLSA | Complements it; agent-run sits above build provenance for the agent step |
| Keyless signing + transparency | Sigstore (Fulcio, Rekor) | Uses it as the default signing path |
| Secure development practices | NIST SSDF | Crosswalked (PO.5, PS.1–PS.3, PW.7) |

OBAAF invents no cryptography. It contributes one missing predicate and the control model around it.

## The ask

1. Review the agent-run and approval schemas as a candidate interoperable predicate for AI-agent provenance.
2. Advise on field alignment with in-toto predicate conventions and with any emerging OpenSSF AI-supply-chain work, so implementations converge rather than fork.
3. Consider a path to **community stewardship**: the specification and schemas are available under CC BY 4.0, and the maintainers would welcome moving the predicate's governance to a neutral body so it can become a shared standard rather than one project's format.

## Open questions we want input on

- **Predicate type URIs.** Currently provisional under a reserved domain; a neutral namespace would be better (what does the WG recommend?).
- **Model identity.** Hosted models expose no stable digest; how should `agent.model` be bound credibly?
- **Egress and isolation.** Default-deny egress for agents is specified but platform-dependent; is there appetite for a shared conformance profile?

## References

- Agent controls (R1–R8): [spec/agent-controls.md](../spec/agent-controls.md)
- Threat model: [docs/threat-model.md](threat-model.md)
- Attestation formats: [docs/attestations.md](attestations.md)
- Schemas: `src/obaaf/data/schemas/`
- Companion papers: `papers/`
- in-toto attestations: https://github.com/in-toto/attestation · SLSA: https://slsa.dev/ · Sigstore: https://www.sigstore.dev/ · OpenSSF: https://openssf.org/
