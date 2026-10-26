# OBAAF: response to review #2, and the road to a gold standard

*Working strategy memo, 2026-10-21. Optional to commit — a planning document, not part of the specification.*

## Executive summary

The second external review is a marked improvement: it inspected the codebase and reached the right diagnosis — *the engineering is far ahead of the website; OBAAF is underselling itself by ~90%.* That is correct, and the website overhaul in this change set acts on it.

The deeper point this memo makes is about the road to "gold standard," which the reviewer frames as a feature and packaging punch-list. **OBAAF's remaining gaps are not technical.** The specification, the controls, the attestation predicate, and the verification tooling are already standard-grade. What stands between OBAAF and *the reference* status is **distribution, adoption, independent validation, and — above all — neutral governance.** The work ahead is mostly not more code. Getting that ordering right is the difference between an impressive repository and an industry standard.

## Part 1 — Verdict on each review #2 recommendation

### Website (Part 2 of the review)

| Recommendation | Verdict | What was done |
| --- | --- | --- |
| Hero overhaul | **Built** | New hero: "Authority & attestation for AI agents in CI/CD," with a real quickstart. Wording kept honest — OBAAF is positioned as *a* framework and proposed standard, not asserted to already *be* "the standard" before adoption. |
| Showcase the GitHub Action | **Built, corrected** | The toolchain and action are surfaced, shown **SHA-pinned** per OBAAF's own R6 — not the review's `@v1`, which would contradict the framework. Marketplace listing prepared (branding + runbook). |
| Embed the self-assessment | **Already done** | The site already builds and serves `assessment.html`; the CTA is now more prominent. |
| Dual-lane architecture visual | **Built** | An inline SVG on the homepage: agent (untrusted, read-only) → signed proposal → authority boundary → human approval (≠ requester) → effect. This is the clearest statement of "propose without push access." |
| Papers front and center | **Built** | A "Research & Standards" section links the two papers, the threat model, the interop story, and the incident mapping. |
| Clarify Apache-2.0 status | **Built, gated** | The site now states Apache-2.0 (code) / CC BY 4.0 (docs). This ships **with** the license grant (D-003) — do not publish the site line without committing the grant, or the site would claim a license the repo has not granted. |

### "Next level / award" (Part 3 of the review)

| Recommendation | Verdict | Reasoning |
| --- | --- | --- |
| Publish to PyPI | **Prepared** | Runbook + OIDC trusted-publishing workflow in `docs/releasing.md`; `pip install obaaf` works after your one-time PyPI setup. The biggest real "simple to adopt" lever. |
| Marketplace listing for `setup-obaaf` | **Prepared** | `branding` added; release steps documented. Examples keep SHA pinning (R6), not `@v1`. |
| Pre-built CLI binaries | **Declined (for now)** | Every CI runner has Python; a wheel on PyPI serves the use case. Binaries add build/signing/supply-chain surface a two-person team should not own pre-pilot. Revisit if non-Python users appear. |
| Sigstore / Rekor keyless | **Already done** | The templates sign every attestation through GitHub's keyless Sigstore (Fulcio cert via OIDC, public Rekor log) in a job the agent cannot influence. `dsse.py` is only the fallback for studios on other CI. The review's premise here is mistaken; corrected in the docs. |
| Live reference exploits ("benchmark") | **Built, honestly** | `docs/reference-exploits.md` maps real incidents and the committed fixtures to the controls that prevent or contain them, and walks the live agent-injection scenario — **without** "prevents all" claims. A credible demo runs the live acceptance tests; totality claims would be a liability. |
| Submit papers to tier-1 conferences | **Partly / strategy** | Paper 1 already targets ACM DTRAP (peer-reviewed) — good. Black Hat Arsenal (a tool showcase) and an OpenSSF event add visibility and are achievable; a top-tier venue (S&P/CCS/USENIX) is a bigger lift that needs the empirical evaluation first. See Part 3. |
| Upstream to OpenSSF | **Built (draft)** | `docs/openssf-submission.md` proposes the agent-run predicate for community review and stewardship. This is the highest-leverage gold-standard move; see Part 2. |

## Part 2 — What actually makes a gold standard

Look at what became durable standards — SLSA, Sigstore, in-toto, SSDF, the OWASP lists, CIS Benchmarks. They share seven traits. OBAAF's honest position against each:

| Trait of a standard | OBAAF today | Gap |
| --- | --- | --- |
| A crisp, implementable spec others can build to | Strong — R1–R8, JSON schemas, a conformance checker | — |
| Interoperability with the ecosystem | Strong — in-toto, SLSA, Sigstore, SSDF | — |
| Independent validation | Partial — papers (in review), incident mapping | Live tests not run; no external audit yet |
| A reference implementation | Strong — the CLI, templates, tests | On PyPI since 0.1.0; Marketplace listing prepared |
| Demonstrated adoption, with names | **Weak** — zero public adopters | The pilot is the seed; needs case studies |
| **Neutral governance** | **Weak** — a two-person project | The single biggest structural gap |
| A forcing function / timing | Strong — the agent-in-CI wave, EU CRA, SSDF attestation | Needs to be connected explicitly |

The pattern is unambiguous: **OBAAF's gaps are governance, adoption, and validation — not engineering.** A specification owned by two people is adopted as "a project," not "the standard," no matter how good. This is why the OpenSSF submission matters more than any feature on the review's list.

**The innovative core to bet on.** OBAAF's genuinely novel contribution is the **agent-run attestation predicate** and the **taint-bounded-authority** model behind it. The winning strategy is not to out-build runtime-enforcement platforms (Chainguard et al. will win that); it is to make OBAAF's predicate *the schema everyone emits* for agent provenance. Become the format, not the platform. That is both the most defensible position for a small team and the most plausible route to "standard."

## Part 3 — The sequenced road

### Phase 0 — A credible, adoptable open project (now → weeks)
Mostly done or prepared in this change set.
- Grant the license (D-003); ship the website overhaul; enable PyPI (`pip install obaaf`) and the Marketplace listing.
- **Land the interested studio pilot.** This is the seed of everything in Phase 1.
- *Outcome:* a stranger can adopt OBAAF in ~20 minutes, and it looks like what it is.

### Phase 1 — Proof and validation (1–3 months)
Turn claims into evidence.
- **Run the live acceptance tests** (LAT-01…11) on a sandbox repo — converts "specified" into "demonstrated" (fork PRs denied secrets, egress, approvals).
- **Publish the pilot as a case study** — the first named adopter.
- **Submit Paper 1** (DTRAP, in progress) and present at **Black Hat Arsenal** or an **OpenSSF Day**; publish `reference-exploits.md` as the public walkthrough.
- *Outcome:* independent evidence, not assertions.

### Phase 2 — Standardization and governance (3–9 months)
The gold-standard inflection.
- **Submit the agent-run predicate to the OpenSSF** (draft ready) and engage in-toto/SLSA so it is *referenced, not forked*.
- **Resolve the predicate namespace** (D-007): done in 0.2; the types live under `https://www.obaaf.com/` and resolve to format pages.
- **Recruit two or three outside contributors**; open a lightweight RFC process.
- **Explore contributing the spec to a neutral body** (OpenSSF sandbox / a working-group deliverable). Yes, this means ceding sole control — that is the price of "standard," and it is worth paying.
- *Outcome:* OBAAF becomes "the agent-run predicate," stewarded beyond its authors.

### Phase 3 — Adoption weight and the forcing function (9–18 months)
- Several named adopters; a published conformance profile.
- Map explicitly to **EU Cyber Resilience Act** and **SSDF attestation** expectations, so OBAAF is the concrete way to satisfy an agent-provenance requirement.
- Pursue an external audit (e.g., OSTIF) and get the predicate referenced by a platform or larger framework.
- *Outcome:* OBAAF shows up in procurement and compliance conversations — the real mark of a standard.

## Part 4 — Three honest cautions

1. **Governance is the hard part, not the code.** The instinct will be to keep building features (the review's list). Resist it. The marginal hour is better spent on the pilot, the live tests, and the OpenSSF submission than on binaries or more tooling.
2. **Credibility is the moat.** For a standard, one overclaim is expensive. Keep the "prevent or contain, under stated assumptions" discipline everywhere; never ship "prevents all," "the standard," or a demo that only shows wins.
3. **Bandwidth is the binding constraint.** Two people cannot do the whole punch-list. The sequence above is ordered by leverage on purpose; do it in order.

## What to do first

1. Decide and commit the **license** (unblocks everything, including the honest website).
2. Push the **website overhaul** and prepare the **PyPI** release.
3. Give the **studio pilot** a concrete first task (run the assessment + `obaaf check`, capture the result).
4. Send the **OpenSSF submission** to the working group.
5. Schedule the **live acceptance tests** on a sandbox repo.

Everything else — conferences, binaries, further tooling — waits behind these five.
