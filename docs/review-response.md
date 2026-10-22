# Response to the OBAAF v2.0 technical review

*Working memo, 2026-10-21. Maps an external technical review of OBAAF against the current repository, and sets the resulting backlog.*

An external reviewer produced a "Technical Review, Architecture v2.0, and Engineering Roadmap" for OBAAF. It is well-read and directionally useful, and it is worth answering carefully. This memo records what it gets right, where it is mistaken, and what from it is worth doing — with file-level evidence, so the conclusions can be checked rather than taken on trust.

## 1. Verdict

The review is a competent, security-literate document that correctly names the direction of travel: evidence should be cryptographically verifiable, not self-reported; agents need bounded authority, ephemeral identity, isolation and attestation; and a credible project builds on Sigstore, in-toto, OIDC and SLSA rather than inventing its own cryptography.

It has one structural problem that colours everything else: **it reviews the public website — the v0.1 "field guide" — and not the repository.** Every example it cites is from the site or the self-assessment (`obaaf assess`, `answers.yaml`, the four tiers). It does not reference a single artifact from the codebase: not the snapshot step, the lanes, the agent-run predicate schema, the DSSE verification, the proposal checker, the documented-incident table, the FR1–FR12 tests, or the decisions log. As a result it proposes building, as "v2.0," a large set of things the repository **already contains** — in several cases in a more rigorous and more honest form than the review describes — while the genuine gaps it identifies are ones the project **already documents openly** in its own decisions log.

The practical consequence: "build OBAAF v2.0 from this document" would mean re-implementing, and in places downgrading, work that already exists. The right move is the opposite — surface what exists, close the few real gaps, and keep the framework adoptable. This memo does that.

## 2. Central finding, with evidence

The review's premise is that OBAAF v0.1 "relies heavily on self-reported questionnaires and static YAML inspection" and must "pivot from a passive, questionnaire-based framework into an active, cryptographically grounded runtime authority protocol." The repository already is that protocol, in specification and in working tools:

| Review's claim about v0.1 | Repository reality | Evidence |
| --- | --- | --- |
| "Absence of cryptographic primitives… self-attestation" | Each agent run emits a signed in-toto attestation; release verification refuses unsigned agent-path changes | `obaaf attest agent-run`, `obaaf verify release`, `src/obaaf/verify/dsse.py` |
| "Lacks runtime telemetry or execution-time… identity" | Per-invocation OIDC identity, read-only token, no secrets, egress to an inference proxy — specified as R3/R7 | [agent controls](../spec/agent-controls.md), `docs/inference-proxy.md` |
| "Static vs dynamic enforcement gap" | Authority is derived from input trust labels at job start, enforced by lane separation, not by inspecting declared intent | R1/R2, `obaaf snapshot`, D-008 |
| "Define the OBAAF in-toto predicate" | The agent-run predicate schema exists and is validated | `src/obaaf/data/schemas/agent-run.schema.json`, `src/obaaf/predicates.py` |

The point is not that the reviewer is careless. It is that the website was written to be non-intimidating, and it succeeded so well that a serious reader concluded the project was only the website.

## 3. What the review gets right

- **The diagnosis of self-attestation's limits.** For high assurance, evidence must be signed and verifiable. OBAAF agrees and already implements it; the review is a useful outside confirmation of the direction.
- **Interoperability over reinvention.** "Build on Sigstore, in-toto, OIDC" is exactly OBAAF's stance.
- **The three threat blind spots** — indirect prompt injection via workflow context, tool-calling/egress escalation, and instruction drift in multi-commit pull requests — are the real, current threats. They are now the spine of the new [threat-model white paper](threat-model.md).
- **OWASP Top 10 for LLM.** A fair catch: the repository mapped to SSDF, SLSA and NIST NCCoE but not to the OWASP LLM list. That crosswalk is now added (threat-model white paper, Section 11).
- **The award criteria** (empirical rigor, zero-friction usability, vendor-neutral governance, interoperability) are broadly right.

## 4. "Build this for v2.0" → current status

| Review recommendation | Status | Evidence / reason |
| --- | --- | --- |
| Define the OBAAF in-toto predicate | **Exists** | `agent-run.schema.json`; `predicates.py`; R8 |
| Sigstore / Cosign keyless attestation | **Exists** | DSSE verify (`verify/dsse.py`); `signing: sigstore`; GitHub `attest` in templates |
| Instruction-integrity checker | **Exists** | checker rules INS-001, REPO-001/002, GHA-012; `tests/test_fr09_instructions.py`; R5 |
| Dual-control execution decoupling | **Exists** | `obaaf proposal check`, `obaaf attest approval`; propose/apply templates; D-018, D-028, D-029; R4 |
| Ephemeral / OIDC workload identity | **Specified** | R3; per-job OIDC, audience-restricted token exchange; inference-proxy contract (proxy not yet built) |
| Input lineage / taint tracking | **Exists** | `obaaf snapshot`, integrity levels, trust labels; R1; D-008 |
| SLSA / SSDF compliance crosswalk | **Exists** | R-table + profile mappings; `frameworks.yaml` (SSDF, SLSA v1.2, NCCoE) |
| OWASP LLM Top 10 crosswalk | **Added now** | [threat-model white paper](threat-model.md), §11 |
| Threat-model RFC / white paper | **Added now** | [threat-model white paper](threat-model.md) |
| Apache-2.0 license transition | **Prepared now** | `LICENSE`, `LICENSE-docs`, `NOTICE`, `pyproject.toml`; D-003 (Proposed); pending maintainer acceptance |
| "AgentPoison" benchmark, "prevents all 10" | **Exists, honestly** | 10-incident table + 13 reproducible risky-workflow fixtures with prevent/contain mapping; see §5 on the claim |
| Policy-as-code (OPA / Rego) | **Defer** | enforcement is by lane structure + org policy today; a Rego engine is an enterprise multi-repo feature, not an early-adopter studio need |
| Rewrite CLI in Go / Rust | **Reject** | D-013: Python runs on every CI runner, few dependencies, auditable; a rewrite buys nothing a studio values and costs months |
| Micro-sandboxing (Firecracker / gVisor / eBPF) | **Genuine gap — don't build own** | R7 is declared, not hard-enforced (D-020, traceability); use existing ephemeral runners / network policy, not bespoke microVM infra |
| Inference proxy (model credential + budget) | **Genuine gap — planned** | specified; D-020 schedules the reference proxy for v0.2 |
| Model pinning by digest | **Genuine gap** | FR10; hosted models expose no stable hash yet |
| Predicate type URIs (`obaaf.org/attestation/v2`) | **Known** | repo uses provisional `obaaf.example/attestation/agent-run/v0.1` pending a domain (D-007) |
| OpenSSF working-group submission | **Do** | high value, low cost; the white paper is the submission artifact |
| Black Hat Arsenal / Briefings; DEF CON; RSA Sandbox; Pwnie | **Selective** | see §5 |
| Advisory board / vendor-neutral governance | **Later** | right idea; hard to recruit for a two-person pre-pilot project |

## 5. Where the review is wrong for this project

- **The runtime-platform pivot is the wrong lane.** A full runtime-enforcement platform (microVMs, eBPF egress, a GitHub App holding branch-protection keys) competes directly with funded platforms and foundations. A two-person project does not win there. OBAAF's defensible position is the **standard** the larger tools map to, plus a lightweight checker and reference lanes — which is what it already is. The review's own "5-minute test" (Part 4) contradicts its architecture: that architecture cannot be adopted in five minutes. Resolve the contradiction toward adoptability.
- **Go/Rust rewrite, OPA/Rego, SPIFFE/SPIRE, Firecracker/eBPF built in-house.** Each trades the project's actual advantage — an honest, auditable, adoptable Python framework — for specialist infrastructure it cannot staff. Where hard isolation is needed, point to existing runtimes; do not build one.
- **"AgentPoison… prevents all 10."** Two problems. First, "prevents all 10" is the kind of absolute claim that is discounted by careful reviewers and, in an immigration or awards context, reads as puffery; OBAAF's existing table is deliberately "prevent **or** contain, under stated assumptions," which is stronger because it is credible. Second, *AgentPoison* is, to the best of our knowledge, already the name of a 2024 academic agent-poisoning attack — reusing it would look derivative. Keep the honest incident corpus; rename any benchmark; never claim totality.
- **Award targeting is half-miscalibrated.** Black Hat **Arsenal** (an open-tool showcase) is a realistic, good target. The **Pwnie Awards** are mostly offensive-research and failure awards — not the home for a defensive framework. **RSA Innovation Sandbox** requires a company, which does not exist. **OpenSSF** engagement is the right, achievable, high-value play.

## 6. The genuine backlog

Drawn from the review's valid points *and* the project's own open decisions, ordered by value-to-effort for a two-person team.

1. **Adopt the license** (prepared in this change; D-003). One commit unblocks studio adoption, OSS-security funding, and OSI-license award criteria.
2. **Publish the threat-model white paper** (added) and **submit to the OpenSSF** supply-chain integrity / AI working groups. Highest-value recognition step; no entity required.
3. **Finalize predicate type URIs** (D-007): acquire a domain, replace the provisional `obaaf.example` URIs before any "released" attestation. Small, unblocks a released format.
4. **Run the live acceptance tests** (LAT-01…11) on a sandbox repository. Converts "specified" claims (fork pull requests denied secrets, egress, approvals) into "demonstrated." High evidence value; moderate effort.
5. **Land the independent-studio pilot.** The single highest-impact item for adoption, for a funding case, and for any petition — it turns a framework into demonstrated impact.
6. **Egress enforcement (R7):** document and template a concrete reference — self-hosted ephemeral runner with a network policy, or a runtime egress monitor — rather than a bespoke microVM stack.
7. **Inference proxy (v0.2)** and **model pinning:** as scheduled; both are honestly deferred, not hidden.

## 7. Suggested posture toward the reviewer

Thank them for the direction — the threat emphases and the OWASP catch are genuinely useful — and send them the repository, the [threat-model white paper](threat-model.md), and the [agent controls](../spec/agent-controls.md), with a note that most of the v2.0 architecture already exists and the real open items are the four in the backlog above. It reframes the exchange from "here is what you are missing" to "here is what is built; here is where outside help would move the needle" — which is the stronger position, and the true one.

## 8. Evidence index

| File | Shows |
| --- | --- |
| [spec/agent-controls.md](../spec/agent-controls.md) | R1–R8, taint-bounded authority, lanes, SSDF/SLSA/NCCoE mappings, the agent-run record, the 10-incident table |
| `src/obaaf/data/schemas/agent-run.schema.json` | the in-toto agent-run predicate the review says to define |
| `src/obaaf/predicates.py` | predicate type URIs (provisional, D-007) |
| `src/obaaf/verify/dsse.py`, `src/obaaf/verify/release.py` | DSSE/Sigstore verification; release gating |
| `src/obaaf/attest/` | snapshot, proposal, agent-run / approval / build records |
| `tests/test_fr09_instructions.py`, `tests/fixtures/workflows/` | instruction-plane tests; the risky-workflow incident corpus |
| [DECISIONS.md](../DECISIONS.md), [CHANGELOG.md](../CHANGELOG.md) | the open gaps the review "discovers," already tracked |
| [docs/threat-model.md](threat-model.md) | the new white paper + OWASP-LLM crosswalk |
