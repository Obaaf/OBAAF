# Website claims and their evidence

Task 4.1, part of #90. Audited on 2026-11-13 UTC against `flagship` commit `e87d376981ba1ec39767c7b079f24d5ec65924ee`. This page changes no website content or deployment. Its decisions are instructions for later website slices, not a statement that those edits have shipped.

The inventory covers homepage metadata, prose, diagram labels, all four JavaScript demo states, and the generated assessment and record-format pages. Repeated assertions share a row. Calls to action, decorative section numbers and questions asking a respondent about their own controls are not assertions that OBAAF has those controls. Generated claims about scoring, effort and prevention are included. Links establish that a resource is referenced; they do not establish that a remote page or mailbox is available now. The deployed website was not fetched.

**Backed** means the cited source supports the claim with the qualification in its decision cell. It does not turn a historical document into a run made here. **Partly backed** means narrower wording is needed. **Out of date** means the current wording conflicts with this checkout or observed released package. **Unbacked** always means **cut**. Claims of implemented behavior cite session runs below; implementation or design evidence alone is labelled accordingly. Source links are pinned to the audited commit. Source extracts follow the command evidence.

## 1. Current claims

| ID | Current assertion | Placement | Verdict | Evidence | Publication decision |
| --- | --- | --- | --- | --- | --- |
| C001 | OBAAF is an open framework and command-line toolchain. | Metadata, hero, overview, footer [index][S001] | Backed | [LICENSING.md:3][S002]; B02; R02-R03. | Keep. Avoid turning the product description into a security guarantee. |
| C002 | Authority and attestation for AI agents in CI/CD. | Title, social titles, hero [index][S003] | Partly backed | [docs/landscape.md:453][S004]; [src/obaaf/cli.py:420][S005]; [docs/traceability.md:3][S006] | Narrow the lead to workflow checks and evidence. Signing and enforcement need configured pipelines. |
| C003 | AI agents change, build and release software with real authority. | Hero [index][S007] | Backed | [papers/OBAAF-Paper1-Agent-Assurance-LaTeX/README.md:1][S008]; [src/obaaf/data/compromises.yaml:4][S009] | Keep as the documented motivation, not a statement about an OBAAF deployment. |
| C004 | OBAAF bounds agent authority. | Description, social description, hero [index][S007] | Partly backed | [templates/github-actions/workflows/obaaf-agent-propose.yml:117][S010]; [docs/checker-configuration.md:177][S011]; B11. | Say it reports authority in workflow configuration; configured lane templates restrict access. Installation does not change permissions. |
| C005 | OBAAF cryptographically attests every agent run. | Description, social description, hero [index][S001] | Partly backed | [src/obaaf/cli.py:403][S012]; [templates/github-actions/workflows/obaaf-agent-propose.yml:229][S013]; B17. | Replace with: writes records for a configured attestation step to sign. No automatic coverage of every agent run. |
| C006 | OBAAF catches workflow prompt injection. | Description, social description, hero [index][S001] | Unbacked | [src/obaaf/checker/__init__.py:411][S014]; [src/obaaf/data/compromises.yaml:4][S009]; B11 finds authority patterns, not malicious prompt meaning. | Cut the general detection claim. Describe concrete workflow risks and supported rules. |
| C007 | An agent can propose changes without holding push access. | Hero, adoption route, lanes [index][S007] | Partly backed | [templates/github-actions/workflows/obaaf-agent-propose.yml:117][S010]; [templates/github-actions/workflows/obaaf-agent-apply.yml:250][S015]; B13 effect-lane tests. | Keep as the reference architecture, with required settings, a stub agent and unconfirmed platform behavior stated. |
| C008 | Version 0.3 is in active adoption with pilot teams. | Banner, brand, scope, footer [index][S016] | Partly backed | R03: obaaf 0.3.0; [docs/landscape.md:451][S017]; [pyproject.toml:25][S018] | Keep the exact release version. Cut plural pilot teams and broad maturity language; a documented adopter is not independent production validation. |
| C009 | A working toolchain and specification are available. | Banner, overview, ready-today [index][S016] | Backed | B01-B20; [src/obaaf/catalog.py:32][S019]; [docs/traceability.md:3][S006] | Keep with explicit tested-version and scope labels. |
| C010 | pip install obaaf installs the package from PyPI. | Hero, engineer path [index][S020] | Backed | R02 exited 0 in a fresh environment; R03 returned 0.3.0; [pyproject.toml:10][S021] | Keep. State Python 3.10 or later; installation downloads packages. |
| C011 | obaaf check scans GitHub Actions workflows and Jenkinsfiles. | Hero, route, overview, toolbox [index][S022] | Backed | [src/obaaf/checker/__init__.py:411][S014]; [tests/test_jenkins_cli.py:77][S023]; B08-B12. | Keep GitHub Actions scope and Jenkins advisory qualifier together. |
| C012 | Nothing leaves the machine during the local check. | Hero code comment [index][S022] | Partly backed | [src/obaaf/checker/__init__.py:411][S014]; [docs/traceability.md:34][S024] | Scope this to local assessment/checking. Do not extend it to installation, API auditing or Sigstore verification. |
| C013 | The assessment has 34 questions. | Metadata, route, overview, toolbox [index][S025] | Backed | B03: assessment_items 34; B04-B07; [src/obaaf/catalog.py:32][S019] | Keep; derive the count from the selected assessment version. |
| C014 | One command flags risky settings in GitHub Actions and Jenkins. | Adoption route [index][S025] | Partly backed | [docs/settings-audit.md:3][S026]; [tests/test_jenkins_cli.py:77][S023]; B11-B12. | Say workflow configuration. GitHub repository settings use the separate unreleased audit command; Jenkins controller settings remain unknown. |
| C015 | No provenance, no upload. | Adoption route [index][S025] | Partly backed | [tests/test_fr06_verifier.py:42][S027]; B14-B16. | Only when the upload step is gated by successful verification. The CLI cannot block another upload path. |
| C016 | The assessment returns a tier. | Overview, toolbox, start [index][S028] | Backed | [tests/test_fr02_assessment.py:56][S029]; B05 returned Tier 0; B06 returned Tier 1. | Keep as a score of supplied answers, not a verified security rating. |
| C017 | The assessment ranks fixes. | Overview, toolbox, start [index][S028] | Backed | [tests/test_fr02_assessment.py:62][S030]; B05-B06. | Keep the ordering rule: lower tiers, then effort, then mapped cases. Do not call it measured risk reduction. |
| C018 | The checker inspects code-ownership coverage. | Overview [index][S028] | Backed | [src/obaaf/checker/__init__.py:411][S014]; [src/obaaf/checker/rules.py:1101][S031] | Keep as a file-based check; it does not prove that code-owner approval is enforced. |
| C019 | The checker inspects agent instruction files. | Overview [index][S028] | Partly backed | [src/obaaf/checker/rules.py:1132][S032]; [R5 requirement][S033] | Say it checks recognized paths, ownership and hidden characters. It does not understand every malicious instruction. |
| C020 | Signing and verification tools produce and check records of every build and agent run. | Overview [index][S028] | Partly backed | [docs/attestations.md:3][S034]; [docs/attestations.md:107][S035]; B14-B17. | Remove every. Operators must supply records and configure which commits and artifacts are covered. |
| C021 | Reference pipeline templates put the architecture into practice. | Overview [index][S028] | Partly backed | [docs/architecture.md:20][S036]; [templates/github-actions/agent/agent.sh:21][S037]; B13. | Describe reference workflows, with setup and implementation gaps. Do not imply a working model integration out of the box. |
| C022 | The checker does not scan application source for vulnerabilities. | Scope [index][S028] | Backed | [src/obaaf/checker/__init__.py:411][S014]; [src/obaaf/checker/__init__.py:143][S038] | Keep. It may read repository scripts for agent detection, which is not application vulnerability scanning. |
| C023 | A passing check is not a security certification. | Scope [index][S028] | Backed | [docs/architecture.md:69][S039]; B12 advisory output. | Keep beside findings and tier results. |
| C024 | Jenkins checking is advisory and lists controller-only facts as unknown. | Scope, toolbox [index][S028] | Backed | [tests/test_jenkins_cli.py:77][S023]; B12: 1 fail, 1 unknown, 2 pass, 11 not applicable. | Keep. Exit 0 is not a Jenkins conformance decision. |
| C025 | Reference templates target GitHub Actions. | Scope [index][S028] | Out of date | [CHANGELOG.md:236][S040] | Qualify: the agent templates and keyless signing target GitHub Actions; Jenkins release and audit templates also exist. |
| C026 | Other CI systems can use the CLI records with their own signing key. | Scope [index][S028] | Partly backed | [docs/attestations.md:3][S034]; B14-B16 use local DSSE keys. | Say externally held keys and supported DSSE verification; platform integrations still need configuration. No live key service ran here. |
| C027 | The framework is at version 0.3 and evolving. | Scope, footer [index][S028] | Partly backed | R03: 0.3.0; B01: 0.4.0.dev0; [src/obaaf/render.py:65][S041] | Separate released tool, development checkout and versioned record formats. Apply the version decision below. |
| C028 | Four commands make up one small package. | Toolbox heading [index][S042] | Partly backed | B02-B03: 14 top-level development commands; [pyproject.toml:30][S043] | Say four featured commands. Cut small/auditable as measured quality claims; list dependencies if useful. |
| C029 | Assessment runs locally and answers are not uploaded. | Toolbox [index][S042] | Backed | [tests/test_fr02_assessment.py:142][S044]; [tests/test_fr02_assessment.py:155][S045]; B13. | Keep for the assessment implementation. Exporting, emailing or opening external links is separate. |
| C030 | check lints against R1-R8 controls behind real attacks. | Toolbox [index][S042] | Partly backed | [src/obaaf/data/compromises.yaml:4][S009]; [src/obaaf/checker/__init__.py:411][S014]; [docs/traceability.md:3][S006] | State that selected rules map to controls and documented cases. It neither implements every control nor validates all attacks. |
| C031 | check emits text, JSON and SARIF. | Toolbox [index][S042] | Backed | B08 and B10; [src/obaaf/cli.py:736][S046] | Keep. Output format is not a claim of complete detection. |
| C032 | attest writes a signed in-toto record through GitHub Sigstore. | Toolbox [index][S042] | Out of date | [src/obaaf/cli.py:403][S012]; [templates/github-actions/workflows/obaaf-agent-propose.yml:229][S013]; B17: no signatures field. | Replace signed with unsigned predicate/statement; the GitHub attestation action signs it separately. |
| C033 | Keyless signing needs no long-lived signing key. | Toolbox [index][S042] | Partly backed | [tests/test_fr11_keys.py:33][S047]; [templates/github-actions/workflows/obaaf-agent-propose.yml:229][S013] | Keep only for the configured GitHub keyless attestation path. DSSE uses an external signing key. |
| C034 | verify blocks releases or agent-authored changes unless provenance, approvals and records check out. | Toolbox [index][S042] | Partly backed | [tests/test_fr06_verifier.py:262][S048]; [docs/attestations.md:55][S049]; B14-B16. | Name verify release, verify agent-run and proposal checks separately; enforcement requires the caller to honor failure. |
| C035 | The Python package has few dependencies. | Toolbox caption [index][S042] | Partly backed | [pyproject.toml:30][S043]; R06. | Use exact direct dependencies: PyYAML and jsonschema, plus optional cryptography. Do not count transitive dependencies as zero. |
| C036 | All code and answers stay on the machine. | Toolbox caption [index][S042] | Unbacked | [docs/traceability.md:34][S024]; [docs/settings-audit.md:3][S026] | Cut as a toolchain-wide promise. assess/check are local; audit and Sigstore mode communicate with GitHub. |
| C037 | The full CLI and schemas are on GitHub. | Toolbox caption [index][S042] | Backed | [src/obaaf/cli.py:420][S005]; [src/obaaf/data/schemas/agent-run.schema.json:5][S050]; [src/obaaf/data/schemas/agent-approval.schema.json:5][S051]; [src/obaaf/data/schemas/build-record.schema.json:5][S052] | Keep. |
| C038 | The CI platform enforces separate agent and effect lanes. | Lanes prose and diagram [index][S053] | Partly backed | [docs/architecture.md:20][S036]; [templates/github-actions/workflows/obaaf-agent-propose.yml:117][S010]; B13. | Describe the configured design. Local fixture tests do not establish live platform isolation, branch protection or administrator behavior. |
| C039 | The agent has no secrets, no write access and no OIDC token. | Lanes prose and diagram [index][S054] | Partly backed | [templates/github-actions/workflows/obaaf-agent-propose.yml:117][S010]; B13. | Say the reference agent job has read-only repository permissions and no declared secrets or id-token permission. It writes local proposal files; no write is otherwise misleading. |
| C040 | The agent produces only a proposal. | Lanes [index][S053] | Partly backed | [templates/github-actions/agent/agent.sh:21][S037]; [docs/inference-proxy.md:3][S055]; B18-B19. | Say only the validated proposal bundle is accepted by the effect lane. Do not promise the model cannot send other output: the proxy is absent and egress is optional. |
| C041 | A different identity applies the proposal only after approval by someone other than the requester. | Lanes prose and diagram [index][S053] | Partly backed | [docs/attestations.md:73][S056]; [templates/github-actions/workflows/obaaf-agent-apply.yml:250][S015]; B13. | Keep as the configured reference workflow and approval policy, including input authors and rerun initiators where relevant. No live approval or merge was performed. |
| C042 | The effect lane runs no model. | Lane diagram [index][S057] | Backed | [templates/github-actions/workflows/obaaf-agent-apply.yml:250][S015]; B13 effect-lane tests. | Keep as a statement about the supplied template. Do not extend to an arbitrary adopter workflow. |
| C043 | A proposal is signed before application. | Lane diagram [index][S058] | Partly backed | [templates/github-actions/workflows/obaaf-agent-propose.yml:229][S013]; [docs/attestations.md:55][S049]; B13. | Say a separate attestation job signs a statement binding the proposal files. The agent does not sign the diff itself. |
| C044 | The agent network is meant to reach only an inference proxy. | Lane caption [index][S054] | Backed | [docs/inference-proxy.md:3][S055]; [docs/egress-control.md:128][S059] | Keep only as planned architecture. The proxy is not shipped. The optional command wrapper has DNS, allowed-host and platform limits. |
| C045 | The agent cannot influence the attestation job. | Lane caption [index][S054] | Partly backed | [templates/github-actions/workflows/obaaf-agent-propose.yml:117][S010]; [templates/github-actions/workflows/obaaf-agent-propose.yml:229][S013]; B13. | Say the design runs trusted code separately and treats agent trace/output as untrusted. The absolute claim depends on protected workflow sources and platform isolation. |
| C046 | Integrity rises only through certified endorsement and an ordinary reviewed merge. | Lane caption [index][S054] | Partly backed | [docs/attestations.md:73][S056]; [templates/github-actions/workflows/obaaf-agent-apply.yml:250][S015] | Describe the required approval and protected merge settings. Cut certified unless it is explicitly defined as the paper's integrity model, not an external certification. |
| C047 | The browser assessment needs no terminal. | Start [index][S060] | Backed | [tests/test_fr02_assessment.py:155][S045]; [src/obaaf/form_template.html:287][S061]; B07 and B13. | Keep. Form generation and JavaScript scoring were run; interactive browser accessibility was not run. |
| C048 | All items in a tier and below must be satisfied to earn that tier. | Start, generated form [index][S060] | Partly backed | [tests/test_fr02_assessment.py:56][S029]; [tests/test_fr02_assessment.py:72][S062]; B13. | State yes or an allowed not-applicable answer. Unknown/no does not satisfy a required item. |
| C049 | The tiers are Accounted, Controlled, Verified and Assured. | Tier strip [index][S060] | Backed | B03; [src/obaaf/data/assessment.yaml:23][S063] | Keep as names in the self-assessment rubric. They are not independently verified capabilities of a respondent. |
| C050 | The assessment scores supplied answers and does not verify evidence. | Start caption [index][S060] | Backed | [docs/self-assessment-walkthrough.md:3][S064]; B05-B06. | Keep next to any score, tier or badge. |
| C051 | The assessment works for any team that ships software. | Start caption [index][S060] | Unbacked | [docs/self-assessment-walkthrough.md:3][S064]; [docs/traceability.md:3][S006] | Cut universal applicability. Say game studios are the worked example; other teams must review applicability. |
| C052 | Game studios are the worked example. | Start caption [index][S060] | Backed | [papers/OBAAF-Paper2-Build-Assurance-Games-LaTeX/README.md:1][S065]; [docs/self-assessment-walkthrough.md:3][S064] | Keep. This does not establish a real studio deployment. |
| C053 | A movable action tag is not an immutable revision. | Demo default and risk state [index][S066] | Backed | B08/R04 flag the tag; B09/R05 accept the full commit; [docs/checker-demonstration.md:6][S067] | Keep; pinning selects code and does not prove that code is safe. |
| C054 | The build demo application check and build passed in both revisions. | Demo default and JS build states [main.js][S068] | Backed | [docs/checker-demonstration.md:27][S069]; [docs/checker-demonstration.md:40][S070] | Keep only as a historical report. The linked GitHub runs were not fetched or rerun in this session. |
| C055 | The build demo audit failed before the pin correction and passed afterward. | Demo build states [main.js][S071] | Backed | [docs/checker-demonstration.md:27][S069]; [docs/checker-demonstration.md:40][S070]; B08-B09 reproduce the finding with a low gate. | Keep version, gate threshold and recorded-run date explicit. The fresh local example is a different workflow. |
| C056 | The historical build demo merge gate was blocked and then allowed. | Demo build states [main.js][S072] | Backed | [docs/checker-demonstration.md:27][S069]; [docs/checker-demonstration.md:40][S070] | Attribute to the recorded demonstration, not a gate tested now. A local CLI exit alone does not demonstrate branch protection. |
| C057 | The build demo finding was medium in OBAAF 0.1. | Demo default and captions [index][S066] | Backed | [docs/checker-demonstration.md:6][S067]; R04 and B08 report LOW. | Retain only as a labelled historical result. Current read-only unprivileged sample uses low severity and --fail-on low. |
| C058 | The build demo carries an exception for the trusted auditor private-access key. | Demo captions [index][S066] | Backed | [docs/checker-demonstration.md:53][S073] | Keep its expiry and trust boundary if reusing that record. Do not present the demo as zero-risk or exception-free. |
| C059 | Unpinned agent, effect and release actions are still high severity. | Demo caption [index][S066] | Backed | [docs/checker-demonstration.md:6][S067]; B11 reports HIGH GHA-008; baseline includes lane severity tests. | Keep with rule and version. The ordinary read-only job can be low. |
| C060 | The recorded build demo is not full framework or studio validation. | Demo captions [index][S066] | Backed | [docs/checker-demonstration.md:53][S073]; [docs/traceability.md:3][S006] | Keep whenever the demonstration is shown. |
| C061 | The synthetic agent demo has four high findings and one low before correction. | Agent-risk JS state [main.js][S074] | Backed | [docs/agent-checker-demonstration.md:7][S075]; [docs/agent-checker-demonstration.md:20][S076] | Historical 0.1.0 report only. Do not substitute the fresh B11 fixture, which reports six high, one medium and one low. |
| C062 | The synthetic agent demo has no high/medium findings and one low after correction. | Agent-fix JS state [main.js][S077] | Backed | [docs/agent-checker-demonstration.md:7][S075]; [docs/agent-checker-demonstration.md:20][S076] | Historical 0.1.0 report only. A passing medium gate leaves a low finding; it is not full R1-R8 enforcement. |
| C063 | The synthetic agent was not run. | Agent states and captions [main.js][S078] | Backed | [docs/agent-checker-demonstration.md:20][S076] | Keep: no model, application build or protected merge gate was exercised. |
| C064 | The agent demonstration was an anonymous pilot contribution hosted by OBAAF. | Agent caption [main.js][S079] | Backed | [docs/agent-checker-demonstration.md:20][S076] | Attribute to the demonstration document. Do not turn it into independent adoption or production-validation evidence. |
| C065 | Adding text to agent context must never add authority. | Controls [index][S080] | Backed | [papers/OBAAF-Paper1-Agent-Assurance-LaTeX/README.md:1][S008]; [docs/architecture.md:20][S036] | Keep as a design requirement, not a blanket claim that OBAAF prevents every escalation. |
| C066 | Eight controls make that principle enforceable. | Controls [index][S080] | Partly backed | [docs/traceability.md:3][S006]; [docs/inference-proxy.md:3][S055]; [docs/egress-control.md:128][S059] | Say the framework defines requirements. Some have implementations, some require platform configuration, and proxy/model guarantees are incomplete. |
| C067 | Installing the checker does not enforce every control. | Controls [index][S080] | Backed | [src/obaaf/checker/__init__.py:411][S014]; [docs/traceability.md:3][S006] | Keep. Reporting, settings inspection and runtime enforcement are separate. |
| C068 | R1 requires labelled input trust and an exact input snapshot. | Control R1 [index][S080] | Backed | [R1 requirement][S081]; [docs/traceability.md:3][S006] | Keep as a normative requirement. Do not label all of it implemented or verified by a passing check. |
| C069 | R2 requires permission limits based on the trust of inputs. | Control R2 [index][S080] | Backed | [R2 requirement][S082]; [docs/traceability.md:3][S006] | Keep as a normative requirement. Do not label all of it implemented or verified by a passing check. |
| C070 | R3 requires narrowly scoped temporary run identities. | Control R3 [index][S080] | Backed | [R3 requirement][S083]; [docs/traceability.md:3][S006] | Keep as a normative requirement. Do not label all of it implemented or verified by a passing check. |
| C071 | R4 requires separate checking and application of proposals. | Control R4 [index][S080] | Backed | [R4 requirement][S084]; [docs/traceability.md:3][S006] | Keep as a normative requirement. Do not label all of it implemented or verified by a passing check. |
| C072 | R5 requires reviewed instructions from a protected source. | Control R5 [index][S080] | Backed | [R5 requirement][S033]; [docs/traceability.md:3][S006] | Keep as a normative requirement. Do not label all of it implemented or verified by a passing check. |
| C073 | R6 requires immutable tool dependencies and provenance checks where available. | Control R6 [index][S080] | Backed | [R6 requirement][S085]; [docs/traceability.md:3][S006] | Keep as a normative requirement. Do not label all of it implemented or verified by a passing check. |
| C074 | R7 requires isolated runs and restricted shared state/network access. | Control R7 [index][S080] | Backed | [R7 requirement][S086]; [docs/traceability.md:3][S006] | Keep as a normative requirement. Do not label all of it implemented or verified by a passing check. |
| C075 | R8 requires signed records binding inputs, authority, outputs and approvals. | Control R8 [index][S080] | Backed | [R8 requirement][S087]; [docs/traceability.md:3][S006] | Keep as a normative requirement. Do not label all of it implemented or verified by a passing check. |
| C076 | The R6 heading implies OBAAF verifies models. | Control R6 heading [index][S080] | Partly backed | [docs/attestations.md:53][S088]; [docs/inference-proxy.md:3][S055]; B17 model fields are null. | Qualify as a requirement. Model identity is not independently established by the supplied stub. |
| C077 | Reassess after 90 days. | Adoption lead path [index][S089] | Backed | [docs/adoption-guide.md:17][S090] | Keep as a suggested interval, not a measured outcome or service commitment. |
| C078 | Install and check both read code locally. | Adoption engineer path [index][S089] | Out of date | R02 downloaded the package and dependencies; [docs/traceability.md:34][S024] | Say installation downloads dependencies; the local checker reads files. |
| C079 | setup-obaaf can install a pinned version in CI. | Adoption engineer path [index][S091] | Partly backed | [actions/setup-obaaf/action.yml:51][S092]; [actions/setup-obaaf/action.yml:16][S093] | Keep documented setup requirements. Baseline installs constrained dependencies; no hosted macOS/Windows action ran here. |
| C080 | An agreed audit status can be required before merging. | Adoption engineer path [index][S091] | Partly backed | [docs/checker-demonstration.md:53][S073]; [docs/settings-audit.md:3][S026] | Keep as an operator setup step. Neither pip install nor check creates that repository rule. |
| C081 | Pinned templates and environments set up agent and release lanes. | Adoption engineer path [index][S091] | Partly backed | [src/obaaf/cli.py:620][S094]; [templates/github-actions/agent/agent.sh:21][S037]; [docs/attestations.md:73][S056] | Explain that template installation needs repository template sources and operator configuration. No turnkey model integration is shipped. |
| C082 | Private access credentials must be kept away from untrusted PR code. | Adoption engineer path [index][S091] | Backed | [templates/github-actions/workflows/obaaf-agent-propose.yml:117][S010]; [docs/checker-demonstration.md:53][S073] | Keep as a requirement; installation does not certify credential separation. |
| C083 | There is no managed onboarding service to buy. | Adoption, pilot invitation [index][S091] | Unbacked | [LICENSING.md:3][S002] establishes licensing, not a service offering or its absence. | Cut the service claim unless a maintainer supplies an authoritative current offering statement. Keep free/open licensing. |
| C084 | Each component can be adopted independently. | Adoption caption [index][S091] | Backed | [docs/architecture.md:3][S095]; independent B05/B08/B17 commands. | Keep. Independent adoption does not mean every dependency or integration is bundled. |
| C085 | Two companion research papers underpin the controls. | Research [index][S096] | Backed | [papers/OBAAF-Paper1-Agent-Assurance-LaTeX/README.md:1][S008]; [papers/OBAAF-Paper2-Build-Assurance-Games-LaTeX/README.md:1][S065] | Keep titles and repository-supported DOI links. Do not imply peer review, publication acceptance or independent validation. |
| C086 | Paper 1 addresses agent authority in build pipelines and defines R1-R8. | Research Paper 1 [index][S096] | Backed | [papers/OBAAF-Paper1-Agent-Assurance-LaTeX/README.md:1][S008]; [R1 requirement][S081] | Keep as a description of the manuscript. |
| C087 | Paper 2 maps build-integrity requirements to SSDF and SLSA using game builds. | Research Paper 2 [index][S096] | Backed | [papers/OBAAF-Paper2-Build-Assurance-Games-LaTeX/README.md:1][S065]; [src/obaaf/data/frameworks.yaml:10][S097] | Keep as a profile/crosswalk, not standards certification. |
| C088 | OBAAF interoperates with in-toto and SLSA records. | Research interoperability [index][S096] | Backed | [docs/attestations.md:3][S034]; B14-B17. | Say statements carrying predicates. The local fixture exercises supported record shapes, not every ecosystem producer. |
| C089 | OBAAF has SLSA v1.2 and NIST SSDF crosswalks. | Research interoperability [index][S096] | Backed | [src/obaaf/data/frameworks.yaml:10][S097] | Keep as mapping metadata, not conformance or a SLSA level award. |
| C090 | OBAAF uses existing cryptographic systems rather than a new algorithm. | Research [index][S096] | Backed | [pyproject.toml:30][S043]; [templates/github-actions/workflows/obaaf-agent-propose.yml:229][S013]; B13-B16. | Describe cryptography/DSSE and GitHub Sigstore integration separately; hosted signing was not run here. |
| C091 | Ten mapped entries are real 2025-2026 compromises. | Research threats [index][S096] | Partly backed | B03: ten agent-case entries, seven Demonstrated and three Exploited; [src/obaaf/data/compromises.yaml:4][S009] | Replace with ten documented agent cases, including demonstrations and exploited incidents. The catalog also has separate game and transfer groups. |
| C092 | Mapped controls prevent or contain each listed case. | Research threats [index][S096] | Unbacked | [src/obaaf/data/compromises.yaml:4][S009] contains analytical mappings; [docs/traceability.md:3][S006] denies production validation. | Cut causal assurance. Say cases are mapped to potentially relevant controls; mappings are not reproduced prevention tests. |
| C093 | Agent-run and approval schemas are proposed for community review. | Research caption [index][S096] | Backed | [src/obaaf/data/schemas/agent-run.schema.json:5][S050]; [src/obaaf/data/schemas/agent-approval.schema.json:5][S051] | Keep proposed and draft explicit. Do not call them an adopted community standard. |
| C094 | The walkthrough contains commands, fictional answers and scoring explanations. | Resources [index][S098] | Backed | [docs/self-assessment-walkthrough.md:3][S064] | Keep as a description of the linked resource; apply its limitations to any extracted copy. |
| C095 | The adoption guide describes work through the tiers. | Resources [index][S098] | Backed | [docs/adoption-guide.md:17][S090] | Keep as a description of the linked resource; apply its limitations to any extracted copy. |
| C096 | The demo record contains commits, run links and limits. | Resources [index][S098] | Backed | [docs/checker-demonstration.md:53][S073] | Keep as a description of the linked resource; apply its limitations to any extracted copy. |
| C097 | The agent-control specification contains requirements and implementation gaps. | Resources [index][S098] | Backed | [docs/traceability.md:3][S006] | Keep as a description of the linked resource; apply its limitations to any extracted copy. |
| C098 | Pilots are underway and broader platform validation continues. | Ready today [index][S098] | Unbacked | [docs/landscape.md:451][S017]; [docs/traceability.md:3][S006] | Cut ongoing/plural adoption claims without a dated maintainer-supported record. A request for pilots is not a completed pilot. |
| C099 | Agent egress is not enforced by default. | Ready today [index][S098] | Backed | [docs/egress-control.md:11][S099]; [CHANGELOG.md:141][S100] | Keep. Also disclose the optional development-only wrapper and its limits; it is not a general guarantee. |
| C100 | OBAAF ships no inference proxy. | Ready today [index][S098] | Backed | [docs/inference-proxy.md:3][S055]; [templates/github-actions/agent/agent.sh:21][S037] | Keep prominently next to model and runtime-enforcement claims. |
| C101 | Code is Apache-2.0 and documents are CC BY 4.0. | Resources, footer [index][S098] | Backed | [LICENSING.md:3][S002] | Keep and link the full license rules, including data and attribution distinctions. |
| C102 | OBAAF is in active development and requests pilot teams. | Get involved [index][S101] | Backed | [pyproject.toml:25][S018]; [docs/flagship.md:271][S102] | Keep the invitation as an invitation. Cut first if it conflicts with the documented author-owned adopter; do not infer a pilot count. |
| C103 | Using OBAAF and reporting problems is the fastest way to improve it. | Get involved [index][S101] | Unbacked | No comparative measurement is recorded; [CONTRIBUTING.md:3][S103] | Cut fastest. Ask for reproducible findings without claiming measured development speed. |
| C104 | Contributors may propose controls, checks or documentation improvements. | Get involved [index][S101] | Backed | [CONTRIBUTING.md:3][S103] | Keep; ordinary bugs and false positives can go to issues. |
| C105 | Security vulnerabilities should follow the disclosure policy. | Get involved [index][S101] | Backed | [SECURITY.md:7][S104] | Keep separate from public issue feedback. |
| C106 | Pipeline details will not be shared without asking. | Pilot invitation [index][S101] | Unbacked | A mailto link is not a technical confidentiality control or independently documented service policy. | Cut as a product assurance. A maintainer may state a human handling commitment separately after confirming it. |
| C107 | The pilot contact is hello@obaaf.com. | Pilot invitation [index][S101] | Partly backed | [index][S101] defines the address only. | Keep only as the configured contact link; delivery and mailbox ownership were not tested. |
| C108 | Sean led research and Ofonna led implementation, testing and GitHub integration, with Sean contributing across the project. | Footer [index][S105] | Backed | [LICENSING.md:25][S106] | Keep the attribution stated in LICENSING.md; it does not imply external endorsement. |
| C109 | The form consists of 34 yes-or-no questions. | Generated assessment intro [src/obaaf/form_template.html:143][S107] | Partly backed | B03-B07; [tests/test_fr02_assessment.py:72][S062] | Say questions with yes, no, unknown and eligible not-applicable answers. |
| C110 | The form tier describes controls actually in place. | Generated assessment intro [src/obaaf/form_template.html:143][S107] | Partly backed | [docs/self-assessment-walkthrough.md:3][S064]; B05-B06. | Say controls reported in the answers, not controls OBAAF verified. |
| C111 | Form answers can be saved and scored by the CLI. | Generated assessment export [src/obaaf/form_template.html:287][S061] | Backed | [tests/test_fr02_assessment.py:188][S108]; B13 tests 60 generated answer cases and CLI parity. | Keep format/version compatibility explicit. Browser download interaction was not exercised. |
| C112 | The generated form names the current development tool version. | Generated assessment version note [src/obaaf/render.py:65][S041] | Backed | B01 and B07; [site/build.py:145][S109] | Keep truthful labels now; adopt the stable-form decision below in a later site slice. |
| C113 | The record-format pages publish three predicate schemas at their declared IDs. | Generated record pages [site/build.py:92][S110] | Backed | [src/obaaf/data/schemas/agent-run.schema.json:5][S050]; [src/obaaf/data/schemas/agent-approval.schema.json:5][S051]; [src/obaaf/data/schemas/build-record.schema.json:5][S052]; site/build.py passed. | Keep; local build and link validation are not proof of deployed URL availability. |
| C114 | Proposal or artifact subjects are identified by SHA-256 digests. | Generated record pages [site/build.py:113][S111] | Backed | [docs/attestations.md:3][S034]; B14-B17. | Keep. A digest binds bytes; it does not establish that the bytes are safe. |
| C115 | Record fields other than trace come from a job the agent cannot influence. | Generated agent-run description [src/obaaf/data/schemas/agent-run.schema.json:5][S050] | Partly backed | [templates/github-actions/workflows/obaaf-agent-propose.yml:117][S010]; [templates/github-actions/workflows/obaaf-agent-propose.yml:229][S013]; B13. | Qualify as the reference workflow trust model. A schema alone cannot guarantee which process supplied a field. |
| C116 | The approval record binds an independent approver to the proposal. | Generated approval description [src/obaaf/data/schemas/agent-approval.schema.json:5][S051] | Partly backed | [docs/attestations.md:73][S056]; B13-B15. | Keep with configured identity verification and policy. A filled JSON field is not an authenticated human approval. |
| C117 | The build record lists source, materials, tools and produced artifacts. | Generated build description [src/obaaf/data/schemas/build-record.schema.json:5][S052] | Backed | [docs/attestations.md:3][S034]; M03 build-record tests and B14-B16. | Keep as the record content, not independent proof of every dependency or a reproducible build. |
| C118 | Reference jobs sign the record through GitHub Sigstore with workflow identity. | Generated record pages [site/build.py:114][S112] | Partly backed | [templates/github-actions/workflows/obaaf-agent-propose.yml:229][S013]; B13. | Keep as a configured integration. No GitHub signing, online identity check or transparency-log request ran here. |
| C119 | Format v0.1 remains at its URI when a changed format gets a new URI. | Generated format version caption [site/build.py:117][S113] | Backed | [DECISIONS.md:86][S114] | Keep as a versioning policy, not a guarantee of permanent hosting. Do not confuse format v0.1 with package 0.3.0. |
| C120 | Generic SLSA provenance can be emitted for CI without native provenance. | Generated build-type page [site/build.py:126][S115] | Backed | [src/obaaf/cli.py:476][S116]; M07-M08 generated and inspected a generic SLSA statement. | Keep as a supported record shape; no external CI integration was run. |
| C121 | GitHub reference release workflows use GitHub-generated provenance. | Generated build-type page [site/build.py:126][S115] | Backed | [templates/github-actions/workflows/obaaf-release.yml:89][S117] | Keep scoped to the reference workflow. No hosted release was executed. |
| C122 | Generic SLSA fields contain source/ref parameters, no internal parameters, and the built commit as a dependency. | Generated build-type field descriptions [site/build.py:129][S118] | Backed | [src/obaaf/attest/records.py:276][S119]; M07-M08. | Keep the published field contract; it does not certify a builder or SLSA level. |
| C123 | An assessment fix would have prevented its mapped cases. | Generated assessment fix list [src/obaaf/form_template.html:273][S120] | Unbacked | [src/obaaf/data/compromises.yaml:4][S009]; B05 contains the same counterfactual label. | Cut causal certainty. Label these as analytical case mappings, not observed prevention; changing the shared renderer needs a separately allowed task. |
| C124 | An assessment fix detects or limits its mapped cases. | Generated assessment fix list [src/obaaf/form_template.html:274][S121] | Partly backed | [src/obaaf/data/compromises.yaml:4][S009]; B06. | Describe suggested control relevance rather than demonstrated outcomes. |
| C125 | Assessment effort labels estimate how long a fix takes. | Generated assessment item tags and fix list [src/obaaf/form_template.html:239][S122] | Partly backed | [docs/adoption-guide.md:3][S123] | Label them catalogue estimates. Cut any claim that hours or days were measured for an adopter. |
| C126 | The form can print or save a PDF. | Generated assessment button [src/obaaf/form_template.html:169][S124] | Partly backed | [src/obaaf/form_template.html:342][S125] | The source invokes browser printing. Browser print/PDF interaction was not run; verify in 4.4 before claiming tested export. |
| C127 | The released assessment is in use with pilot teams. | Released form version note [src/obaaf/render.py:65][S041] | Unbacked | R07/M04 reproduced that exact 0.3.0 note; [docs/landscape.md:451][S017] | Cut the plural adoption assertion. A stable-form switch must not republish it without qualification or a maintained presentation fix. |
| C128 | Tier 1 means knowing who and what can publish or sign. | Homepage tier strip and generated tier 1 summary [index][S060] | Backed | [src/obaaf/data/assessment.yaml:24][S126]; [docs/self-assessment-walkthrough.md:3][S064] | Keep as a summary of the rubric and supplied answers. It is not verification that these controls are in place. |
| C129 | Tier 2 means separating trusted release work from untrusted work. | Homepage tier strip and generated tier 2 summary [index][S060] | Backed | [src/obaaf/data/assessment.yaml:27][S127]; [docs/self-assessment-walkthrough.md:3][S064] | Keep as a summary of the rubric and supplied answers. It is not verification that these controls are in place. |
| C130 | Tier 3 means producing and checking build evidence. | Homepage tier strip and generated tier 3 summary [index][S060] | Backed | [src/obaaf/data/assessment.yaml:30][S128]; [docs/self-assessment-walkthrough.md:3][S064] | Keep as a summary of the rubric and supplied answers. It is not verification that these controls are in place. |
| C131 | Tier 4 adds independent verification. | Homepage tier strip and generated tier 4 summary [index][S060] | Backed | [src/obaaf/data/assessment.yaml:33][S129]; [docs/self-assessment-walkthrough.md:3][S064] | Keep as a summary of the rubric and supplied answers. It is not verification that these controls are in place. |
| C132 | Every build-record field identifies who reported it. | Generated build-record description [src/obaaf/data/schemas/build-record.schema.json:5][S052] | Partly backed | [src/obaaf/attest/records.py:205][S130]; [src/obaaf/data/schemas/build-record.schema.json:13][S131]; M03. | Say source, assets, manifest, SDK entries and isolation carry reporter labels. Builder/run metadata and version/time fields do not each have reportedBy; a label alone does not authenticate a reporter. |

## Version decision

Keep editorial website deployment from `main`, as [.github/workflows/pages.yml:7][S132] specifies. Do not rebuild the entire website from an old release tag: that would couple copy corrections to package releases and could restore claims this table rejects.

Build the default public assessment from an explicitly pinned stable package release matching the quickstart. In this session that release was **0.3.0** (R02-R03); the checkout and current generated form were **0.4.0.dev0** (B01/B07/M04). This is a recommendation for a later build slice, not an implemented change. Pin a reviewed version and artifact hash, record the source commit, and update it deliberately; do not resolve an unrecorded moving latest during deployment. Keep any development form at a separately labelled preview URL. Preserve versioned record-format URLs independently of package versions.

The switch needs one copy safeguard: R07/M04 found that the released form itself says `in use with pilot teams`. Do not silently republish that unsupported sentence. The follow-up must remove or qualify the presentation note without changing the released scoring data or logic, then check browser/CLI parity for the selected release. Until that work is complete, keep the existing development label visible. The hand-written homepage version should later come from the same explicit release metadata. This recommendation does not change `site/build.py`, the renderer or the deployment workflow in this slice.

## 2. Planned claims and publication gates

These rows cover item 4, the positioning it must follow, and adjacent roadmap features that could otherwise be advertised prematurely. Built components can be described now; their new web pages and illustrations are still work for the named slices. Companion recommendations are attributed to the repository's positioning, read on 2026-11-13 UTC. This session did not rerun external tools or verify their current websites.

| ID | Planned assertion | Placement | Status | Evidence | Publication decision |
| --- | --- | --- | --- | --- | --- |
| P01 | Lead with agent and release jobs, their authority and the evidence behind findings. | 4.2 hero | Backed today | [docs/landscape.md:453][S004]; B11; [docs/settings-audit.md:3][S026] | Use: Check the authority of agent and release jobs. Inspect workflow evidence, read available repository settings, and report what cannot be established. Label audit as development-only until released. |
| P02 | Every claimed control is verified in files, repository settings and at runtime. | 4.2 hero | Cut | [docs/checker-configuration.md:177][S011]; [CHANGELOG.md:141][S100]; [docs/egress-control.md:128][S059] | The complete positioning sentence is an aim. Do not present it as current universal coverage. |
| P03 | OBAAF is the only tool that checks what an agent can reach. | Any comparison or hero | Cut | [docs/landscape.md:502][S133] | No exclusivity claim. Name ci-agent-audit as overlapping; untested vendor statements are not comparative results. |
| P04 | The homepage offers a real terminal session with a finding and its fix. | 4.2 terminal example | Backed today | R02-R05 and B08-B11; [docs/flagship.md:278][S134] | Use the recorded released-package tag/pin example with --fail-on low and exits 1/0. Keep the narrow agent/release lead; an agent fixture can show authority risks. The new homepage itself is not built. |
| P05 | The first result takes a particular number of human minutes. | 4.2 quickstart headline | Cut | [docs/flagship.md:262][S135]; [docs/adoption-guide.md:3][S123] | Cut human timing claims. Slice 3.1 measures machine time and countable steps, and explicitly forbids estimating human reading or decision time. It cannot supply this claim. |
| P06 | check reads workflows and reports findings without editing them. | 4.2 check/audit/enforcement explanation | Backed today | [src/obaaf/checker/__init__.py:411][S014]; B08-B12. | Explain local file analysis, recognized patterns, unsupported cases and severity thresholds. It does not configure a merge gate. |
| P07 | audit compares readable repository settings with workflow assumptions. | 4.2 check/audit/enforcement explanation | Backed today, development only | [docs/settings-audit.md:3][S026]; B13 settings tests; B20 snapshot replay. | Explain permissions and cannot-tell results. This session made no live authenticated audit; B20 skipped workflow comparison because the target differed. |
| P08 | Runtime controls are distinct from checker and settings-audit reports. | 4.2 check/audit/enforcement explanation | Backed today | [docs/egress-control.md:11][S099]; [CHANGELOG.md:141][S100]; [tests/test_fr06_verifier.py:262][S048] | Show operator-configured controls and caller-enforced verifier exits. Optional egress wrapper is development-only and has documented escape limits. |
| P09 | The checker recognizes the egress wrapper as a verified clearing control. | 4.2 runtime explanation | Not built yet: 2c.3 | [CHANGELOG.md:141][S100]; [docs/flagship.md:271][S102] | Do not claim GHA-020 clears because the wrapper is present. |
| P10 | The next egress work investigates DNS leakage and tests model-key forwarding. | 4.2 lane illustration | Not built yet: 2c.4 | [docs/egress-control.md:128][S059]; [docs/flagship.md:246][S136] | Testing may conclude the mechanism is unsupported. The slice does not promise a shipped proxy or independently verified model receipts. |
| P11 | OBAAF will ship an inference proxy that records trusted model identity. | 4.2 lane illustration | Cut as a committed delivery claim | [docs/inference-proxy.md:3][S055]; B17. | A contract exists but no implementing slice is committed in item 4 or 2c.4. Say not implemented; do not announce delivery or treat model identity fields as independently verified. |
| P12 | Findings can be accepted with an owner, reason and expiry. | 4.2 capability detail | Backed today, development only | [docs/checker-configuration.md:163][S137]; [tests/test_finding_lifecycle.py:72][S138]; full baseline. | Acceptance is a recorded decision, not proof that a risk was removed. |
| P13 | Control reports distinguish verified, not met and cannot tell. | 4.2 capability detail | Backed today, development only | [docs/checker-configuration.md:177][S011]; [tests/test_controls.py:76][S139]; full baseline. | GHA-005 and GHA-020 report controls, but neither can be cleared today. Settings and verified egress integration remain incomplete; do not advertise the fixed lifecycle state as a current clearing capability. |
| P14 | The homepage will use original inline SVG for the three ideas. | 4.2 illustrations | Not built yet: 4.2 | [docs/flagship.md:278][S134] | The plan does not name the three ideas explicitly. Proposed interpretation: reach, control evidence, and findings/limits. Keep check/audit/enforcement as a separate relationship; reviewer confirms before drawing. |
| P15 | Animation explains a relationship and respects reduced-motion settings. | 4.2 illustrations | Not built yet: 4.2 | [docs/flagship.md:278][S134] | Do not claim the redesign has passed accessibility checks before 4.4. |
| P16 | A quickstart page covers released installation, a useful finding and a gate configuration. | 4.3 quickstart | Not built yet: 4.3 | [docs/flagship.md:279][S140]; R02-R05; [docs/adoption-guide.md:17][S090] | CLI example is available; dedicated page and documented end-to-end adoption measurement are not. Gate instructions must distinguish prepared YAML from a hosted CI run. |
| P17 | A rule catalogue exposes rule scope, severity, evidence and limitations. | 4.3 rule catalogue | Not built yet: 4.3 | [docs/flagship.md:279][S140]; [src/obaaf/catalog.py:32][S019] | Source catalogue exists. A web page must not imply complete platform coverage or render missing limitations as guarantees. |
| P18 | A dated comparison links sources and distinguishes tested from documented behavior. | 4.3 comparison | Not built yet: 4.3 | [docs/flagship.md:279][S140]; [docs/landscape.md:465][S141] | Use reviewed landscape evidence at publication time. This base predates H2; do not copy its obsolete not-run cells into a new page. |
| P19 | A case-study page presents a measured adoption or live repository audit. | 4.3 case study | Not built yet: 4.3 and 3.7 | [docs/flagship.md:279][S140]; [docs/flagship.md:268][S142]; [docs/checker-demonstration.md:53][S073] | Historical demonstrations may be labelled and linked. Do not rename them a validated independent production case study. |
| P20 | A papers page links the two manuscripts with their limitations. | 4.3 papers | Not built yet: 4.3 | [docs/flagship.md:279][S140]; [papers/OBAAF-Paper1-Agent-Assurance-LaTeX/README.md:1][S008]; [papers/OBAAF-Paper2-Build-Assurance-Games-LaTeX/README.md:1][S065] | The manuscripts exist; dedicated site page remains planned. Do not imply peer review or accepted standards status. |
| P21 | The new site has been checked at desktop and phone widths. | 4.4 quality claim | Not built yet: 4.4 | [docs/flagship.md:280][S143] | Run the browser checks and attach screenshots before claiming this. |
| P22 | The new site has been checked in light and dark modes. | 4.4 quality claim | Not built yet: 4.4 | [docs/flagship.md:280][S143] | A successful static build is insufficient. |
| P23 | The new site remains useful with JavaScript disabled. | 4.4 quality claim | Not built yet: 4.4 | [docs/flagship.md:280][S143]; [index][S089] | Current engineer panel starts hidden. Specify a usable fallback and test it; scoring needs JavaScript or the CLI. |
| P24 | The new site has no third-party fonts, scripts or trackers. | 4.4 quality claim | Not built yet: 4.4 | [docs/flagship.md:280][S143]; [site/build.py:143][S144] | Audit built assets and browser network requests. Local link validation does not establish this for a future redesign. |
| P25 | Screenshots prove the planned browser checks were performed. | 4.4 PR evidence | Not built yet: 4.4 | [docs/flagship.md:280][S143] | No screenshot is supplied by this documentation-only slice. |
| P26 | Public assessment and quickstart use the same pinned stable tool release. | Form version label, quickstart | Not built yet: later site/build slice | [docs/flagship.md:271][S102]; [site/build.py:145][S109]; R03 | Adopt the version decision below. This task records it and changes no build code. |
| P27 | obaaf init installs recommended companion checks. | Future quickstart | Not built yet: 3.3 | [docs/flagship.md:264][S145]; B02 shows no init command. | Do not invent an init command in instructions. |
| P28 | The positioning document recommends zizmor; CodeQL where available; actionlint; poutine. | 4.3 comparison: General workflow weaknesses | Backed today as a documented recommendation | [docs/landscape.md:465][S141] | Link the dated source and each named project from it. These tools were not run in this 4.1 session; verify current availability and claims before publishing a fresh external comparison. |
| P29 | The positioning document recommends GitHub native egress firewall; Agent Workflow Firewall; Harden-Runner or Cimon where already used. | 4.3 comparison: Network restrictions | Backed today as a documented recommendation | [docs/landscape.md:466][S146] | Link the dated source and each named project from it. These tools were not run in this 4.1 session; verify current availability and claims before publishing a fresh external comparison. |
| P30 | The positioning document recommends GitHub workflow execution protections. | 4.3 comparison: Workflow entry policy | Backed today as a documented recommendation | [docs/landscape.md:467][S147] | Link the dated source and each named project from it. These tools were not run in this 4.1 session; verify current availability and claims before publishing a fresh external comparison. |
| P31 | The positioning document recommends GitHub workflow lockfiles and commit-pinning policy; Chainguard Actions as a documented commercial option. | 4.3 comparison: Action selection and pinning | Backed today as a documented recommendation | [docs/landscape.md:468][S148] | Link the dated source and each named project from it. These tools were not run in this 4.1 session; verify current availability and claims before publishing a fresh external comparison. |
| P32 | The positioning document recommends GitHub Agentic Workflows. | 4.3 comparison: New agent workflows | Backed today as a documented recommendation | [docs/landscape.md:469][S149] | Link the dated source and each named project from it. These tools were not run in this 4.1 session; verify current availability and claims before publishing a fresh external comparison. |
| P33 | The positioning document recommends GitHub artifact attestations and gh attestation verify. | 4.3 comparison: Signing and verification | Backed today as a documented recommendation | [docs/landscape.md:470][S150] | Link the dated source and each named project from it. These tools were not run in this 4.1 session; verify current availability and claims before publishing a fresh external comparison. |
| P34 | The positioning document recommends Snyk agent-scan; Agent Threat Rules; agent-audit; promptwarden. | 4.3 comparison: Agent skills, MCP servers and instruction scanning | Backed today as a documented recommendation | [docs/landscape.md:471][S151] | Link the dated source and each named project from it. These tools were not run in this 4.1 session; verify current availability and claims before publishing a fresh external comparison. |
| P35 | The positioning document recommends Legitify; OpenSSF Scorecard. | 4.3 comparison: Organization-wide settings | Backed today as a documented recommendation | [docs/landscape.md:472][S152] | Link the dated source and each named project from it. These tools were not run in this 4.1 session; verify current availability and claims before publishing a fresh external comparison. |
| P36 | The positioning document recommends poutine. | 4.3 comparison: Other CI platforms | Backed today as a documented recommendation | [docs/landscape.md:473][S153] | Link the dated source and each named project from it. These tools were not run in this 4.1 session; verify current availability and claims before publishing a fresh external comparison. |

## 3. Numbers that may be used

This is an allowlist with scope, not a list of headline metrics. A new number needs new evidence. Section labels, rule IDs, GitHub run IDs, commit hashes and DOI identifiers are identifiers; copy them from the cited source without presenting them as counts or quality scores.

| ID | Number | Observed value | Command or source query | Limit |
| --- | --- | --- | --- | --- |
| N01 | Released package / audited development source | 0.3.0 / 0.4.0.dev0 | R03: obaaf --version; B01: obaaf --version | Both observed on 2026-11-13 UTC. Do not call the development version a release. |
| N02 | Assessment questions | 34 | B03 count script below; obaaf catalog | Catalog size, not a detection success rate. |
| N03 | Scored tiers | 4, with 8 / 12 / 9 / 5 items | B03 count script below | Tier 0 means no tier earned. Eligible N/A answers can satisfy items; tier labels are not certifications. |
| N04 | Agent controls | 8: R1-R8 | B03 count script below; obaaf catalog | Requirements, not eight fully enforced runtime controls. |
| N05 | Profile requirements and families | 28 requirements; 9 families | B03 count script below; obaaf catalog | Do not confuse these with assessment items or checker rules. |
| N06 | Development catalogue rules by prefix | GHA 24; JEN 15; REPO 2; INS 1; CFG 1 | B03 count script below | Count by namespace; do not add settings rules to this without a separate source. Rule count is not comparative coverage. |
| N07 | Settings rules | 15 | M01: len(obaaf.audit.rules.RULES); B20 audit snapshot replay | Output: 14 cannot-tell results from 14 of 15 rules, not 14 active checks passed. Development only; B20 did not compare workflow-dependent rules with the target files. |
| N08 | Featured versus total development CLI commands | 4 featured; 14 top-level commands | B02: obaaf --help; B03 count script below | Say four featured commands, not only four commands. |
| N09 | Python compatibility declaration | >=3.10 | python -c "from importlib.metadata import metadata; print(metadata('obaaf')['Requires-Python'])" (M01) | Metadata declaration, not evidence that every supported interpreter was tested; this session used Python 3.12.14. |
| N10 | Direct runtime dependencies | 2 required; 1 optional keys dependency | R06 metadata.requires and B03 dependencies | PyYAML and jsonschema; cryptography for keys. Transitive packages are additional. |
| N11 | Agent case entries and status | 10: 7 Demonstrated, 3 Exploited | B03 count script below | Use ten documented agent cases, not ten exploited incidents or ten prevented attacks. |
| N12 | Other case groups | 9 game cases; 6 transfer cases | B03 count script below | Separate groups; no implied number of unique incidents across all groups. |
| N13 | Agent case disclosure range | 2025-03 through 2026-02 | B03 count script below | Catalog disclosure dates, not dates of this audit or of production validation. |
| N14 | Companion manuscripts | 2 | M01: count the two tracked papers/*/README.md paths; source quotes below | No implied peer-review or acceptance count. |
| N15 | Schema / statement / build-type versions | 3 OBAAF predicate schemas at v0.1; generic build type v0.1; in-toto Statement v1; SLSA provenance v1 | M01 source constants; B17 statement summary; site/build.py | Record-format versions differ from tool 0.3.0, assessment data 0.1.0 and the SLSA v1.2 crosswalk. |
| N16 | Historical build demo version and findings | 0.1; one medium unpinned-action finding; one documented exception | rg -n "0.1\|medium\|exception\|2027" docs/checker-demonstration.md (M02) | Historical document only. Exception expires 2027-01-09. Runs 38005157685 / 38005287677 are identifiers, not counts; live runs not fetched. |
| N17 | Historical synthetic agent demo findings | 0.1.0; before 4 high + 1 low; after 0 high + 0 medium + 1 low | rg -n "0.1.0\|high\|low\|402404" docs/agent-checker-demonstration.md (M02) | Runs 40240418961 / 40240448552 are identifiers. Agent not run; no protected merge gate. Counts belong only to those historical files. |
| N18 | Fresh read-only tag/pin example | 1 low before; 0 findings after; exits 1 / 0 | R04/R05 and B08/B09: obaaf check <file> --fail-on low | Local workflow only. Same result on released and development packages; no CI action executed. |
| N19 | Fresh agent fixture findings | 6 high, 1 medium, 1 low | B11: obaaf check tests/fixtures/workflows/risky/promptpwnd-issue-agent.yml --fail-on medium | Static fixture output, not the historical synthetic demo and not malicious-prompt detection. |
| N20 | Local validation test counts | 1190 full-suite tests before; 135 focused existing tests | python -m unittest discover -s tests; B13 command below | Evidence of this checkout only. Not a website quality score, production success rate or equivalent number of attacks. |
| N21 | Assessment parity samples | 60 generated answer cases | rg -n -F "range(60)" tests/test_fr02_assessment.py (M06); B13 | Scoring parity tests, not 60 people, repositories or browser sessions. |
| N22 | Reassessment interval | 90 days | rg -n "90 days" docs/adoption-guide.md (M02) | Guidance only. Do not imply measured benefit or a deadline imposed by the tool. |
| N23 | Pins and digests | 40-character Git commit used in example; SHA-256 subjects | M01 counts the example pin; B17 uses SHA-256 subjects | A version label and a digest are not assurance levels. Keep identifiers intact; do not claim security from their length. |
| N24 | License versions | Apache-2.0; CC BY 4.0 | rg -n "Apache-2.0\|CC BY 4.0" LICENSING.md (M02) | Legal identifiers copied from the repository, not an interpretation of licensing obligations. |
| N25 | SLSA/SSDF crosswalk versions | Use exact catalogue labels only | rg -n "version:\|name:" src/obaaf/data/frameworks.yaml (M02) | A crosswalk is not certified compliance. Avoid unsupported standards-level claims. |
| N26 | Unapproved numbers | Cut adoption counts, percentages prevented, speed promises and comparative coverage percentages | No session measurement supports those claims. [docs/traceability.md:3][S006] | Do not extract them from enthusiasm, paper examples or source test totals. Historical egress-test counts also need their own dated qualification and are not approved as a safety headline. |

## Commands and observed output

The full baseline passed before drafting: constrained editable install, 1190 unit tests, `obaaf catalog`, `obaaf docs build --check`, `obaaf check . --fail-on medium`, and `python site/build.py`, all exit 0. The before output was `Ran 1190 tests in 45.230s` and `OK`; the first after-draft output was `Ran 1190 tests in 45.914s` and `OK`. All baseline commands passed again after drafting. Node was `v24.22.1`, Python `3.12.14`. This document adds no tests and changes no implementation.

Commands below ran in the pinned checkout unless stated otherwise. The R commands used a separate fresh virtual environment outside the source checkout, with no source `PYTHONPATH`. The handover retains exact argv, working directory, UTC timestamp, exit status and complete stdout/stderr for each measurement. Displayed paths use `$WORK` for the session's temporary samples and `$CASE` for a throwaway fixture directory. The release fixture was created by `tests/scenario.py:build_release` with temporary local keys and deleted afterward. No production key, model call, hosted workflow or upload was used. Its reproduction harness is in the handover; its output does not establish live Sigstore behavior.

| Run | Command (paths abbreviated) | Exit | Observed result or summary |
| --- | --- | --- | --- |
| B01 | `obaaf --version` | 0 | obaaf 0.4.0.dev0 |
| B02 | `obaaf --help` | 0 | {assess,check,baseline,audit,snapshot,manifest,proposal,attest,record,dsse,verify,templates,docs,catalog} |
| B04 | `obaaf assess init --output "$WORK/answers.yaml"` | 0 | initialized an answer file |
| B05 | `obaaf assess score "$WORK/answers.yaml"` | 0 | Tier reached: 0 (Not yet Accounted) |
| B06 | `obaaf assess score examples/self-assessment/tier-one-demo.yaml` | 0 | Tier reached: 1 (Accounted) |
| B07 | `obaaf assess form --output "$WORK/assessment.html"` | 0 | wrote the standalone form |
| B08 | `obaaf check "$WORK/unpinned.yml" --fail-on low` | 1 | LOW    OBAAF-GHA-008 |
| B09 | `obaaf check "$WORK/pinned.yml" --fail-on low` | 0 | Hygiene findings: 0 high, 0 medium, 0 low. |
| B10 | `obaaf check "$WORK/unpinned.yml" --fail-on low --format json` | 1 | JSON report; same low finding |
| B10 | `obaaf check "$WORK/unpinned.yml" --fail-on low --format sarif` | 1 | SARIF report; same low finding |
| B11 | `obaaf check tests/fixtures/workflows/risky/promptpwnd-issue-agent.yml --fail-on medium` | 1 | Other findings: 8 new (6 high, 1 medium, 1 low) |
| B12 | `obaaf check tests/fixtures/jenkins/risky/pr-title-injection.groovy --platform jenkins --fail-on high` | 1 | HIGH   OBAAF-JEN-009 |
| B13 | `PYTHONPATH=src:tests python -m unittest -v test_fr02_assessment test_fr08_effect_lane test_fr10_agent_record test_fr11_keys test_fr06_verifier test_jenkins_cli test_settings_adopter` | 0 | Ran 135 tests in 6.081s; OK |
| B14 | `obaaf verify release [fixture paths; exact flags below] --approvals "$CASE/approvals.json"` | 0 | Release verification: PASSED, upload may proceed |
| B15 | `obaaf verify release [same fixture paths, no --approvals]` | 1 | Release verification: BLOCKED, do not upload |
| B16 | `obaaf verify release [same flags as B14, SLSA envelope removed]` | 1 | BLOCK: Game-win64.zip: no verified SLSA provenance |
| B17 | `obaaf attest agent-run [snapshot, workflow and proposal paths; exact flags below]` | 0 | Statement has no signatures; model id/version are null |
| B18 | `obaaf proposal check "$WORK/proposal"` | 0 | Proposal check passed: 1 file(s), 0 path(s) touched |
| B19 | `obaaf proposal check "$WORK/proposal" (after inserting a URL into comment.md)` | 1 | Proposal check FAILED: 1 file(s), 0 path(s) touched |
| B20 | `obaaf audit --from-snapshot tests/fixtures/settings/live-expectrail-2026-11-13/snapshot.json --fail-on never` | 0 | CANNOT TELL: 14, from 14 of 15 rules |
| R02 | `python -m pip install obaaf` | 0 | installed the released package in a fresh environment |
| R03 | `obaaf --version` | 0 | obaaf 0.3.0 |
| R04 | `obaaf check "$WORK/unpinned.yml" --fail-on low` | 1 | LOW    OBAAF-GHA-008 |
| R05 | `obaaf check "$WORK/pinned.yml" --fail-on low` | 0 | Hygiene findings: 0 high, 0 medium, 0 low. |
| R07 | `obaaf assess form --output "$WORK/released-assessment.html"` | 0 | released form generation succeeded |
| M07 | `obaaf attest slsa --artifact [synthetic file] --builder-id https://example.invalid/test-builder --repository-uri https://example.invalid/test-source --source-revision [40 a characters] --source-ref refs/heads/main --out [predicate.json] --statement-out [statement.json]` | 0 | wrote a SLSA v1 statement with 1 subject |
| M03 | `PYTHONPATH=src:tests python -m unittest -v test_fr05_build_record test_d007_predicate_namespace` | 0 | Ran 14 tests in 0.414s; OK |

The fresh workflow used `on: push`, top-level `permissions: {contents: read}`, and `persist-credentials: false`. Its only action was `actions/checkout@v6.0.0`; the fix replaced that reference with `actions/checkout@1af3b93b6815bc44a9784bd300feb67ff0d1eeb3`. No action was executed. The low threshold matters: a medium threshold would not fail on this low finding.

B14-B16's fixture command flags and B17's generation command are reproduced here from the command records. Temporary paths are illustrative; recreate the fixtures with the supplied harness. A successful verifier exit permits a caller to proceed; it does not itself upload or enforce another workflow's behavior.

```bash
obaaf verify release --policy /tmp/task41-release-_fjpbdwy/policy.yaml --artifacts /tmp/task41-release-_fjpbdwy/build/dist --dsse /tmp/task41-release-_fjpbdwy/attestations.json --actor releaser --repo-dir /tmp/task41-release-_fjpbdwy/repo --range v0.9.0..8193bdb8e1c44507c53f9c644e5173c8b8bdd1b3 --source-revision 8193bdb8e1c44507c53f9c644e5173c8b8bdd1b3 --approvals /tmp/task41-release-_fjpbdwy/approvals.json
```

```bash
obaaf verify release --policy /tmp/task41-release-_fjpbdwy/policy.yaml --artifacts /tmp/task41-release-_fjpbdwy/build/dist --dsse /tmp/task41-release-_fjpbdwy/attestations.json --actor releaser --repo-dir /tmp/task41-release-_fjpbdwy/repo --range v0.9.0..8193bdb8e1c44507c53f9c644e5173c8b8bdd1b3 --source-revision 8193bdb8e1c44507c53f9c644e5173c8b8bdd1b3
```

```bash
obaaf verify release --policy /tmp/task41-release-_fjpbdwy/policy.yaml --artifacts /tmp/task41-release-_fjpbdwy/build/dist --dsse /tmp/task41-release-_fjpbdwy/attestations.json --actor releaser --repo-dir /tmp/task41-release-_fjpbdwy/repo --range v0.9.0..8193bdb8e1c44507c53f9c644e5173c8b8bdd1b3 --source-revision 8193bdb8e1c44507c53f9c644e5173c8b8bdd1b3 --approvals /tmp/task41-release-_fjpbdwy/approvals.json
```

```bash
obaaf attest agent-run --snapshot /workspace/scratch/567d2d60a102/task41-samples/snapshot --snapshot-digest 49950f8612bed5bff4227c2caad52478a6140799a4b3db3d4ea71343f0729bdd --proposal /workspace/scratch/567d2d60a102/task41-samples/proposal --workflow-file /workspace/scratch/567d2d60a102/OBAAF-4.1/templates/github-actions/workflows/obaaf-agent-propose.yml --job agent --out /workspace/scratch/567d2d60a102/task41-samples/predicate.json --statement-out /workspace/scratch/567d2d60a102/task41-samples/statement.json
```

Selected verbatim output, with unrelated lines omitted:

**B05**

```text
OBAAF self-assessment
Tier reached: 0 (Not yet Accounted)
```

**B06**

```text
OBAAF self-assessment for Fictional Tier 1 demonstration
Tier reached: 1 (Accounted)
```

**B08**

```text
Accepted risk: none. No finding is accepted by a baseline entry or an ignore entry.
Other findings: 1 new (1 low), 0 cannot tell, 0 fixed by controls the checker verified.

unpinned.yml
     9  LOW    OBAAF-GHA-008  Action or container not pinned to a full digest  [job build]
        Action 'actions/checkout@v6.0.0' is pinned to 'v6.0.0', not a full commit SHA.
        Requirement: G2.1, R6
        Fix: Pin the reference to a full 40-character commit SHA, or an image to its sha256 digest, and keep the version in a comment (for example `uses: actions/checkout@<sha> # v7.0.1`). Let Dependabot propose updates to the pin.

1 workflow file(s) checked.
Authority findings: 0 high, 0 medium, 0 low.
Hygiene findings: 0 high, 0 medium, 1 low.
```

**B09**

```text
Accepted risk: none. No finding is accepted by a baseline entry or an ignore entry.
Other findings: 0 new, 0 cannot tell, 0 fixed by controls the checker verified.

1 workflow file(s) checked.
Authority findings: 0 high, 0 medium, 0 low.
Hygiene findings: 0 high, 0 medium, 0 low.
```

**B11**

```text
Accepted risk: none. No finding is accepted by a baseline entry or an ignore entry.
Other findings: 8 new (6 high, 1 medium, 1 low), 0 cannot tell, 0 fixed by controls the checker verified.
```

**B12**

```text
Accepted risk: none. No finding is accepted by a baseline entry or an ignore entry.
Other findings: 1 new (1 high), 0 cannot tell, 0 fixed by controls the checker verified.

pr-title-injection.groovy
     9  HIGH   OBAAF-JEN-009  Untrusted text interpolated into a command  [stage Announce]
        The sh step in stage 'Announce' builds its script with Groovy interpolation of CHANGE_TITLE. The value becomes part of the command before the shell runs, so it can run commands of its own.
        Requirement: G3.1, G8.1, R1
        Fix: Use single-quoted Groovy strings and let the shell expand the value: `sh 'echo "$CHANGE_TITLE"'`, with the value in the environment (it already is for CHANGE_* and parameters, or set it with withEnv).

Jenkins coverage (advisory). Exit status 0 is not a conformance decision: controller settings (authorization, build authorization, agents, library trust, Replay, network policy) are not in a Jenkinsfile, and what the checker cannot see is listed as unknown.
  pr-title-injection.groovy (declarative, sha256:3bb7dbf6c232...): 1 fail, 1 unknown, 2 pass, 11 not applicable
    unknown OBAAF-JEN-002: line 4: agents labelled 'linux' run work that change requests or an AI agent can steer; whether those agents are ephemeral, and whether other jobs run privileged work on them, is controller configuration
```

**B14**

```text
Release verification: PASSED, upload may proceed
```

**B15**

```text
Release verification: BLOCKED, do not upload
  artifact Game-win64.zip sha256:ce0d81409be45ff2… provenance: verified, build record: verified, tier: A
  agent commit 8855155dbcd8: verified
BLOCK: no release approvals were supplied; the policy requires 1 in environment(s) 'release' (pass --approvals)
```

**B16**

```text
Release verification: BLOCKED, do not upload
  artifact Game-win64.zip sha256:ce0d81409be45ff2… provenance: missing, build record: verified, tier: A
  release approved by: approver
  agent commit 8855155dbcd8: verified
BLOCK: Game-win64.zip: no verified SLSA provenance
```

**B19**

```text
Proposal check FAILED: 1 file(s), 0 path(s) touched
  comment contains '//' (a web address): '//'
  comment contains a URL scheme: 'https:'
```

**B20**

```text
Settings audit of Expectrail/Expectrail
From the snapshot tests/fixtures/settings/live-expectrail-2026-11-13/snapshot.json, taken 2026-11-13 09:10 UTC without a token. Nothing was asked of GitHub now.
The workflow files were not read: the clone in the current directory is of Obaaf/OBAAF, not of Expectrail/Expectrail; to compare the settings with a repository's workflow files, name the directory that holds them (obaaf audit DIR --repo OWNER/REPO). The twelve rules that compare a setting with what the workflows use answer "cannot tell"; OBAAF-SET-004, OBAAF-SET-005 and OBAAF-SET-013 read settings only and do not need the files.

FINDINGS: 0 (0 high, 0 medium, 0 low). CANNOT TELL: 14, from 14 of 15 rules. "Cannot tell" is never a pass: nothing is established there.
```

**M01**

```text
Requires-Python: >=3.10
paper README files: 2
settings rules: 15
predicate types: {"agent-approval": "https://www.obaaf.com/attestation/agent-approval/v0.1", "agent-run": "https://www.obaaf.com/attestation/agent-run/v0.1", "build-record": "https://www.obaaf.com/attestation/build-record/v0.1"}
generic build type: https://www.obaaf.com/buildtypes/generic/v0.1
example pin length: 40
```

**M04**

```text
released-assessment.html:145:  <p class="draft-note">OBAAF 0.3.0, in use with pilot teams. It may change in OBAAF 0.4 based on pilot feedback.</p>
assessment.html:145:  <p class="draft-note">OBAAF 0.4.0.dev0, a development version and not a release. It may change before OBAAF 0.4.0 is released.</p>
```

**M06**

```text
197:        for _ in range(60):
```

**M07**

```text
wrote /workspace/scratch/567d2d60a102/task41-samples/generic-predicate.json (https://slsa.dev/provenance/v1, 1 subject(s))
```

**M08**

```text
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [
    {
      "name": "generic-artifact.txt",
      "digest": {
        "sha256": "b91b66771b6ab7ce8f906c171c351e0f729ec21205db88ed835be3d56e47b048"
      }
    }
  ],
  "predicateType": "https://slsa.dev/provenance/v1",
  "predicate": {
    "buildDefinition": {
      "buildType": "https://www.obaaf.com/buildtypes/generic/v0.1",
      "externalParameters": {
        "source": {
          "uri": "https://example.invalid/test-source",
          "ref": "refs/heads/main"
        }
      },
      "internalParameters": {},
      "resolvedDependencies": [
        {
          "uri": "git+https://example.invalid/test-source@refs/heads/main",
          "digest": {
            "gitCommit": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
          }
        }
      ]
    },
    "runDetails": {
      "builder": {
        "id": "https://example.invalid/test-builder"
      },
      "metadata": {
        "startedOn": "2026-11-13T16:47:10Z"
      }
    }
  }
}
```

**B17 statement inspection**

```json
{
  "type": "https://in-toto.io/Statement/v1",
  "predicateType": "https://www.obaaf.com/attestation/agent-run/v0.1",
  "top_level_keys": [
    "_type",
    "subject",
    "predicateType",
    "predicate"
  ],
  "has_signatures": false,
  "model": {
    "reportedBy": "none",
    "id": null,
    "version": null
  }
}
```

B20 was a **snapshot replay**, not a fresh GitHub audit. It deliberately demonstrated an honest unknown result: the local clone is OBAAF and the snapshot names Expectrail, so workflow comparison was not performed. Its exit 0 used `--fail-on never`; it means neither clean settings nor a passed control. B13's settings-adopter tests replay recorded API responses. Historical site demo runs were read as documentation only, not fetched or rerun.

### Reproduce the catalogue counts

After the constrained editable install, B03 ran the following count logic through the outside-repository measurement helper. These are data counts, not independently verified security outcomes.

```python
import argparse
from collections import Counter
from importlib import metadata
import json
from obaaf.catalog import load
from obaaf import __version__, cli, render
from obaaf.checker import jenkins
from obaaf.audit import rules
c=load()
parser=cli.build_parser()
sub=next(a for a in parser._actions if isinstance(a,argparse._SubParsersAction))
print(json.dumps({'version':__version__,'requirements':len(c.requirements),'families':len(c.families),'assessment_items':len(c.items),'tiers':{k:v['name'] for k,v in c.tiers.items()},'tier_items':dict(Counter(i['tier'] for i in c.items.values())),'agent_controls':list(c.agent_requirements),'rules_by_prefix':dict(Counter(k.rsplit('-',1)[0] for k in c.rules)),'jenkins_rules':len(jenkins.RULES),'cli_commands':list(sub.choices),'case_groups':{k:len(v) for k,v in c.compromises.items() if k.endswith('_cases')},'agent_case_status':dict(Counter(i['status'] for i in c.compromises['agent_cases'])),'agent_case_dates':sorted(set(i['disclosed'] for i in c.compromises['agent_cases'])),'dependencies':metadata.requires('obaaf'),'form_version':render.form_data().get('version')},indent=2))
```

Observed B03 output:

```json
{
  "version": "0.4.0.dev0",
  "requirements": 28,
  "families": 9,
  "assessment_items": 34,
  "tiers": {
    "1": "Accounted",
    "2": "Controlled",
    "3": "Verified",
    "4": "Assured"
  },
  "tier_items": {
    "1": 8,
    "2": 12,
    "3": 9,
    "4": 5
  },
  "agent_controls": [
    "R1",
    "R2",
    "R3",
    "R4",
    "R5",
    "R6",
    "R7",
    "R8"
  ],
  "rules_by_prefix": {
    "OBAAF-GHA": 24,
    "OBAAF-CFG": 1,
    "OBAAF-JEN": 15,
    "OBAAF-REPO": 2,
    "OBAAF-INS": 1
  },
  "jenkins_rules": 15,
  "cli_commands": [
    "assess",
    "check",
    "baseline",
    "audit",
    "snapshot",
    "manifest",
    "proposal",
    "attest",
    "record",
    "dsse",
    "verify",
    "templates",
    "docs",
    "catalog"
  ],
  "case_groups": {
    "game_cases": 9,
    "transfer_cases": 6,
    "agent_cases": 10
  },
  "agent_case_status": {
    "Demonstrated": 7,
    "Exploited": 3
  },
  "agent_case_dates": [
    "2025-03",
    "2025-05",
    "2025-07",
    "2025-08",
    "2025-10",
    "2025-12",
    "2026-02"
  ],
  "dependencies": [
    "PyYAML>=6.0",
    "jsonschema>=4.26.0",
    "cryptography>=46.0.5; extra == \"keys\""
  ],
  "form_version": "0.1.0"
}
```

`form_version: 0.1.0` above is the assessment data format, not the tool version printed in the form header. M01 read `Requires-Python`, counted `papers/*/README.md`, counted `obaaf.audit.rules.RULES`, and printed the predicate/build-type constants. M02 ran the source-number `rg -n` queries named in part 3; they returned the historical counts, dates and version labels quoted there. Raw commands and complete output are included in the handover. The first B03 attempt called a nonexistent parser helper; it failed, was corrected to `cli.build_parser`, and reran successfully. No product file changed to make it pass.

## Source extracts

Each quoted line was located with `rg -n -F` before citation. Long lines are quoted only in part. Function and test declarations locate implementation evidence; they are not substitutes for the run results above. Historical report text proves what the report says, not that this session reran its external services.

| Pinned source | Literal line or line excerpt |
| --- | --- |
| [.github/workflows/pages.yml:7][S132] | <code>branches: [main]</code> |
| [CHANGELOG.md:236][S040] | <code>### Jenkins (advisory)</code> |
| [CHANGELOG.md:141][S100] | <code>- **The checker does not credit it yet.** OBAAF-GHA-020 still cannot be cleared by this action until slice 2c.3 teaches the checker to recognise it.</code> |
| [CONTRIBUTING.md:3][S103] | <code>OBAAF accepts contributions under the rules below. Version 0.x formats may still change before 1.0, so open an issue before a large change.</code> |
| [DECISIONS.md:86][S114] | <code>**Decision.** OBAAF's in-toto predicate types and its generic SLSA build type live under `https://www.obaaf.com/`, the project's own domain, for example `https://www.obaaf.com/attestation/agent-run/v0.1`. They are defined once in `src/obaaf/predicates.py` and used in the templates. Each type URI resolves to a page that describes its format, and</code> |
| [LICENSING.md:3][S002] | <code>OBAAF is free and open (NFR1). Two licenses apply, by material:</code> |
| [LICENSING.md:25][S106] | <code>Sean led the research. Ofonna handled implementation, testing, and GitHub integration, with Sean contributing across the project. These contribution roles do not change the copyright notice.</code> |
| [SECURITY.md:7][S104] | <code>Please do not open a public issue containing vulnerability details. Use GitHub's private vulnerability reporting for this repository.</code> |
| [actions/setup-obaaf/action.yml:51][S092] | <code>--require-hashes --requirement "$GITHUB_ACTION_PATH/requirements.txt"</code> |
| [actions/setup-obaaf/action.yml:16][S093] | <code>and python that runs and is 3.10 or later. On macOS and Windows runners, run</code> |
| [docs/adoption-guide.md:3][S123] | <code>This guide is for a studio of fewer than 50 people, where one engineer owns the build system part-time and nobody owns security. It goes tier by tier; each tier is useful on its own. Effort figures are the self-assessment's initial estimates and will be checked in the pilot.</code> |
| [docs/adoption-guide.md:17][S090] | <code>Answer each question from the evidence named beside it, not from memory. Two people answering separately and comparing is better still: where you disagree, look at the evidence together. Save the answers; you will repeat the assessment in 90 days.</code> |
| [docs/agent-checker-demonstration.md:20][S076] | <code>## Limits</code> |
| [docs/agent-checker-demonstration.md:7][S075] | <code>\| Revision \| Public audit \| Result \|</code> |
| [docs/architecture.md:20][S036] | <code>## Lanes</code> |
| [docs/architecture.md:69][S039] | <code>## What OBAAF does not protect against</code> |
| [docs/architecture.md:3][S095] | <code>OBAAF has five components. The profile, the agent controls and the self-assessment are specifications, kept as data in `src/obaaf/data/`. The templates and the tools put them into practice. A studio can adopt each component on its own.</code> |
| [docs/attestations.md:73][S056] | <code>## The approval record (R4)</code> |
| [docs/attestations.md:55][S049] | <code>Before acting on a proposal, the effect lane runs `obaaf verify agent-run`. It passes only if all of these hold:</code> |
| [docs/attestations.md:3][S034] | <code>OBAAF writes four kinds of record. Each signed record is an [in-toto statement](https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md) whose subjects are files identified by SHA-256 digest. The predicate formats are drafts (version 0.1); their JSON Schemas are in [`src/obaaf/data/schemas/`](../src/obaaf/data/schemas/).</code> |
| [docs/attestations.md:53][S088] | <code>Approvals happen after this record is signed, so they are recorded in the approval record over the same subjects (D-009). Version 0.1 differs from Table 3 in three ways. The trace is one digest of the trace file, not a digest per tool call. The model fields stay empty until an inference proxy reports them (D-020). The approval time is when the</code> |
| [docs/attestations.md:107][S035] | <code>`obaaf verify release` finds agent-authored commits by the trailer, by an added record file, or by the effect lane's commit identity (`agents.effect_identities`). It blocks the commit unless all of these hold:</code> |
| [docs/checker-configuration.md:163][S137] | <code>## What happens to a finding</code> |
| [docs/checker-configuration.md:177][S011] | <code>### Controls that clear a finding</code> |
| [docs/checker-demonstration.md:40][S070] | <code>## Corrected revision</code> |
| [docs/checker-demonstration.md:53][S073] | <code>## Exception and limits</code> |
| [docs/checker-demonstration.md:27][S069] | <code>## Risky revision</code> |
| [docs/checker-demonstration.md:6][S067] | <code>## Version note</code> |
| [docs/egress-control.md:128][S059] | <code>## Not done</code> |
| [docs/egress-control.md:11][S099] | <code>It does not make an agent safe to hold a secret. Anything it can send to a listed host it can send there; **a name it asks the proxy for leaves the runner in a DNS query even when the proxy refuses it**, which is a channel for data (shown in the tests, below); and it confines one command, not the job. Read [What it blocks, and what it does</code> |
| [docs/flagship.md:271][S102] | <code>### 4. The website</code> |
| [docs/flagship.md:246][S136] | <code>- ☐ **2c.4 The proxy's DNS channel, and model keys through AWF's API proxy.** Found by 2c.2 (decision F-76); issue #120. *Done when* either the escape test that asks the proxy for a labelled name asserts that the label does not leave the runner, or the documentation says exactly why it cannot be closed on hosted runners and what the channel</code> |
| [docs/flagship.md:262][S135] | <code>- ☐ **3.1 Measure what exists.** Time the current path in a clean directory and a fresh repository layout: install to first useful result, and to a gate in CI. *Done when* the times and every stumble are recorded here. *Reserved for a ChatGPT session (decision F-62):* run 13 passed over this slice because its session cannot reach PyPI, and the</code> |
| [docs/flagship.md:264][S145] | <code>- ☐ **3.3 `obaaf init`.** *Done when* it inspects a repository, proposes `.github/obaaf.yml` (including detected agent jobs and secrets) and adds a workflow, with no file written by hand. *Positioning (1.4):* it proposes agent jobs from the named tools and also from any job that holds a model provider's key (most of Expectrail's agent jobs have no</code> |
| [docs/flagship.md:268][S142] | <code>- ☐ **3.7 Expectrail case study.** From public facts only, with numbers recomputed here, stating plainly that Expectrail is the author's own project and that outside results are still to come.</code> |
| [docs/flagship.md:278][S134] | <code>- ☐ **4.2 Home page.** Leads with what OBAAF does and the fastest way to try it: a real terminal session and a real finding with its fix. Original inline SVG for the three ideas and for how check, audit and enforcement fit together; animation only where it explains, honouring `prefers-reduced-motion`.</code> |
| [docs/flagship.md:279][S140] | <code>- ☐ **4.3 Pages.** Quickstart, rule catalogue, landscape comparison with its date and sources, case study, papers.</code> |
| [docs/flagship.md:280][S143] | <code>- ☐ **4.4 Checked in a browser.** *Done when* it has been checked at desktop and phone widths, in light and dark, with JavaScript off, with no third-party fonts, scripts or trackers, and the screenshots are in the pull request.</code> |
| [docs/inference-proxy.md:3][S055] | <code>The agent lane gives the agent no secrets (R2, FR7), so it cannot hold the credential for the model API. Paper 1's design puts that credential in an **inference proxy** outside the agent's reach (R3), and limits the agent's network egress to the proxy (R7). This page specifies the proxy's contract. OBAAF does not include a proxy. A reference</code> |
| [docs/landscape.md:453][S004] | <code>&gt; For the jobs in a repository that run an AI agent or publish a release, OBAAF says what each job can reach, checks that the controls claimed for it are real (in the workflow file, in the repository's settings, and while the job runs), and shows its evidence. For everything else it points to the tool that already does it well.</code> |
| [docs/landscape.md:472][S152] | <code>\| Checking a whole organisation's settings against a standard \| Legitify, OpenSSF Scorecard, or one of the enterprise products \| Built since slice 2b.2, not in a release: `obaaf audit` reads only the settings the repository's own workflows depend on and applies fifteen rules, twelve of which compare a setting with the workflow files ([the settings</code> |
| [docs/landscape.md:467][S147] | <code>\| Controlling who and what can start a workflow \| GitHub's workflow execution protections \| Built since slice 2b.2, not in a release, and never run against a real policy: where the policy can be read, `obaaf audit` compares it with the triggers the workflows use (`OBAAF-SET-009`), and says whether the `pull_request_target` change of 2026-12-02</code> |
| [docs/landscape.md:465][S141] | <code>\| General weaknesses in workflow files: script injection, checkout of a pull request's code, unpinned actions, token permissions, caches, runners \| zizmor first: it has the most rules and fixes some findings itself. CodeQL where code scanning is on. actionlint for plain mistakes. poutine for scripts piped into a shell \| Adds no new general rule.</code> |
| [docs/landscape.md:502][S133] | <code>Not alone, and not to be claimed as such: asking what an agent job in CI can reach. ci-agent-audit does. Wiz and Aikido say their products detect misconfigured agents in CI; neither was tested here.</code> |
| [docs/landscape.md:451][S017] | <code>OBAAF is a small open-source project with one adopter, and that adopter is its author's own. A third of its 24 GitHub Actions rules report what larger tools report too, and on its own subject it is no longer alone. So the position is narrow on purpose:</code> |
| [docs/landscape.md:473][S153] | <code>\| Other CI systems \| poutine reads GitLab, Azure DevOps and Tekton \| GitHub Actions only. Jenkins support stays advisory, as it is \|</code> |
| [docs/landscape.md:468][S148] | <code>\| Pinning and vetting the actions a workflow uses \| GitHub's workflow lockfiles and its policy for pinning to a commit. Chainguard Actions is a commercial option in open beta (not run here) \| Keeps its report of unpinned actions (GHA-008). Does not know about lockfiles; no slice plans it yet \|</code> |
| [docs/landscape.md:466][S146] | <code>\| Restricting what a job can reach on the network \| GitHub's native egress firewall where a repository has it. Otherwise the Agent Workflow Firewall. Harden-Runner or Cimon where a team already runs one. None was run here \| Planned (slice 2c), not built: a small action that pins and wraps AWF, escape tests that try to get out of it on every</code> |
| [docs/landscape.md:471][S151] | <code>\| Scanning what steers an agent: skills, MCP servers, instruction files \| Snyk's agent-scan, Agent Threat Rules, agent-audit, promptwarden (none run here) \| Keeps its two small rules about instruction files. Adds none \|</code> |
| [docs/landscape.md:470][S150] | <code>\| Signing and verifying what was built \| GitHub artifact attestations and `gh attestation verify` \| Keeps its own records (an agent's run, an approval, a build) as in-toto statements signed the same way, and its two rules about releases without provenance \|</code> |
| [docs/landscape.md:469][S149] | <code>\| Writing a new agent workflow \| GitHub Agentic Workflows (not run here) \| OBAAF's agent lane templates stay as a worked example of its controls. They are not the recommended place to start \|</code> |
| [docs/landscape.md:465][S141] | <code>\| General weaknesses in workflow files: script injection, checkout of a pull request's code, unpinned actions, token permissions, caches, runners \| zizmor first: it has the most rules and fixes some findings itself. CodeQL where code scanning is on. actionlint for plain mistakes. poutine for scripts piped into a shell \| Adds no new general rule.</code> |
| [docs/self-assessment-walkthrough.md:3][S064] | <code>The self-assessment is a predefined checklist of 34 questions. It scores answers</code> |
| [docs/settings-audit.md:3][S026] | <code>*Status: not in a release yet. The command reads a repository's GitHub settings, records what it read and what it could not, and applies fifteen rules, `OBAAF-SET-001` to `OBAAF-SET-015`: twelve compare a setting with what the repository's workflow files use, and three read settings only. A rule reports a finding, or "cannot tell" when a setting</code> |
| [docs/traceability.md:3][S006] | <code>The specification's roadmap figure plans specifications, templates, the checker, the verifier and tests for FR1</code> |
| [docs/traceability.md:34][S024] | <code>\| NFR5 \| Private by default, no telemetry \| No telemetry: no command reports anything to OBAAF. In Sigstore mode, `obaaf verify release` and `obaaf verify agent-run` call the GitHub CLI, which sends artifact digests to GitHub to fetch and check attestations. The form's content security policy forbids network requests (tested in FR2) \|</code> |
| [papers/OBAAF-Paper1-Agent-Assurance-LaTeX/README.md:1][S008] | <code># Untrusted Text, Trusted Tokens: Bounding the Authority of AI Agents in Software Build Pipelines</code> |
| [papers/OBAAF-Paper2-Build-Assurance-Games-LaTeX/README.md:1][S065] | <code># Securing the Game Build: A Sector Profile of SSDF and SLSA and a Self-Assessment Model for Independent Studios</code> |
| [pyproject.toml:25][S018] | <code>"Development Status :: 3 - Alpha",</code> |
| [pyproject.toml:30][S043] | <code>dependencies = [</code> |
| [pyproject.toml:10][S021] | <code>requires-python = "&gt;=3.10"</code> |
| [site/build.py:117][S113] | <code>&lt;p class="caption"&gt;Version 0.1 may change before OBAAF 1.0. A changed format gets a new version and a new URI; this page and its schema stay as published.&lt;/p&gt;"""</code> |
| [site/build.py:129][S118] | <code>&lt;p&gt;&lt;strong&gt;Internal parameters.&lt;/strong&gt; None.&lt;/p&gt;</code> |
| [site/build.py:126][S115] | <code>&lt;p class="large"&gt;The &lt;code&gt;buildType&lt;/code&gt; of SLSA v1 provenance written by &lt;code&gt;obaaf attest slsa&lt;/code&gt;, for CI systems that do not generate provenance themselves. On GitHub Actions, OBAAF uses the provenance GitHub generates instead.&lt;/p&gt;</code> |
| [site/build.py:114][S112] | <code>&lt;p&gt;&lt;strong&gt;Written by.&lt;/strong&gt; &lt;code&gt;{command}&lt;/code&gt;. &lt;strong&gt;Signed by.&lt;/strong&gt; {signer}, through GitHub's Sigstore with the signing workflow's identity.&lt;/p&gt;</code> |
| [site/build.py:145][S109] | <code>assessment = render.form_html(link_base='https://github.com/Obaaf/OBAAF/blob/main/')</code> |
| [site/build.py:92][S110] | <code>def write_formats(output):</code> |
| [site/build.py:113][S111] | <code>&lt;p&gt;&lt;strong&gt;Subjects.&lt;/strong&gt; {subjects}, each identified by its SHA-256 digest.&lt;/p&gt;</code> |
| [site/build.py:126][S115] | <code>&lt;p class="large"&gt;The &lt;code&gt;buildType&lt;/code&gt; of SLSA v1 provenance written by &lt;code&gt;obaaf attest slsa&lt;/code&gt;, for CI systems that do not generate provenance themselves. On GitHub Actions, OBAAF uses the provenance GitHub generates instead.&lt;/p&gt;</code> |
| [site/build.py:143][S144] | <code>for name in ('index.html', 'styles.css', 'main.js'):</code> |
| [src/obaaf/attest/records.py:205][S130] | <code>"reportedBy": "protected workflow definition",</code> |
| [src/obaaf/attest/records.py:276][S119] | <code>"internalParameters": {},</code> |
| [src/obaaf/catalog.py:32][S019] | <code>class Catalog:</code> |
| [src/obaaf/checker/__init__.py:143][S038] | <code>def _agent_via_script(job, root: Path, commands: list) -&gt; str \| None:</code> |
| [src/obaaf/checker/__init__.py:411][S014] | <code>def check(target: Path, files: list[Path] \| None = None, config: Config \| None = None,</code> |
| [src/obaaf/checker/rules.py:1132][S032] | <code>add("OBAAF-INS-001", rel, hidden[0].line, "{count} hidden character(s): {characters}{more}.",</code> |
| [src/obaaf/checker/rules.py:1101][S031] | <code>add("OBAAF-REPO-001", ".github/CODEOWNERS", 1, "The repository has no CODEOWNERS file.", kind="no-codeowners")</code> |
| [src/obaaf/cli.py:736][S046] | <code>x.add_argument("--format", choices=("text", "json", "sarif"), default="text")</code> |
| [src/obaaf/cli.py:403][S012] | <code>def _emit(args, subjects, predicate_type, predicate) -&gt; int:</code> |
| [src/obaaf/cli.py:420][S005] | <code>def cmd_attest_agent_run(args) -&gt; int:</code> |
| [src/obaaf/cli.py:476][S116] | <code>def cmd_attest_slsa(args) -&gt; int:</code> |
| [src/obaaf/cli.py:620][S094] | <code>def cmd_templates_install(args) -&gt; int:</code> |
| [src/obaaf/data/agent_controls.yaml:72][S081] | <code>- id: R1</code> |
| [src/obaaf/data/agent_controls.yaml:98][S082] | <code>- id: R2</code> |
| [src/obaaf/data/agent_controls.yaml:121][S083] | <code>- id: R3</code> |
| [src/obaaf/data/agent_controls.yaml:146][S084] | <code>- id: R4</code> |
| [src/obaaf/data/agent_controls.yaml:169][S033] | <code>- id: R5</code> |
| [src/obaaf/data/agent_controls.yaml:192][S085] | <code>- id: R6</code> |
| [src/obaaf/data/agent_controls.yaml:212][S086] | <code>- id: R7</code> |
| [src/obaaf/data/agent_controls.yaml:237][S087] | <code>- id: R8</code> |
| [src/obaaf/data/assessment.yaml:33][S129] | <code>summary: "Adds two-person control and independent verification."</code> |
| [src/obaaf/data/assessment.yaml:24][S126] | <code>summary: "Establishes who and what can publish or sign."</code> |
| [src/obaaf/data/assessment.yaml:30][S128] | <code>summary: "Produces and checks provenance and isolates builds."</code> |
| [src/obaaf/data/assessment.yaml:27][S127] | <code>summary: "Separates release builds from untrusted work and removes standing credentials."</code> |
| [src/obaaf/data/assessment.yaml:23][S063] | <code>name: Accounted</code> |
| [src/obaaf/data/compromises.yaml:4][S009] | <code># agent_cases: Paper 1, Tables 1 and 4.</code> |
| [src/obaaf/data/frameworks.yaml:10][S097] | <code>ssdf:</code> |
| [src/obaaf/data/schemas/agent-approval.schema.json:5][S051] | <code>"description": "Predicate of the in-toto statement, signed by the effect lane, that records who approved applying an agent's proposal (Paper 1, Table 3, Approvals; R4, R8). Its subjects are the same proposal-bundle files as the agent-run attestation.",</code> |
| [src/obaaf/data/schemas/agent-run.schema.json:5][S050] | <code>"description": "Predicate of the in-toto statement that records one agent run (Paper 1, Table 3; R8, FR10). The statement's subjects are the files of the proposal bundle. Every field except `trace` is produced by a job the agent cannot influence.",</code> |
| [src/obaaf/data/schemas/build-record.schema.json:5][S052] | <code>"description": "Predicate of the in-toto statement that records how a release artifact was built (G7.1, FR4, FR5). It accompanies SLSA provenance and adds what games need: the asset revision, the binary-manifest digest, the SDK versions and the isolation tier. Each field says who reported it.",</code> |
| [src/obaaf/data/schemas/build-record.schema.json:13][S131] | <code>"required": ["revision", "reportedBy"],</code> |
| [src/obaaf/form_template.html:239][S122] | <code>el("div", { class: "tags", text: `Profile ${item.profile.join(", ")} · effort ${DATA.effort[item.effort].label.toLowerCase()}` }));</code> |
| [src/obaaf/form_template.html:274][S121] | <code>if (item.limits.length) why.push(`Detects or limits ${item.limits.join(", ")}.`);</code> |
| [src/obaaf/form_template.html:169][S124] | <code>&lt;button id="print"&gt;Print or save as PDF&lt;/button&gt;</code> |
| [src/obaaf/form_template.html:143][S107] | <code>&lt;p class="lead"&gt;Thirty-four yes-or-no questions in four tiers for a software team without security staff. Answer each from the evidence named beside it. You reach a tier when every item at that tier and below is answered yes. A tier describes controls in place, not a guarantee of security.&lt;/p&gt;</code> |
| [src/obaaf/form_template.html:273][S120] | <code>if (item.prevents.length) why.push(`Would have prevented ${item.prevents.join(", ")}.`);</code> |
| [src/obaaf/form_template.html:143][S107] | <code>&lt;p class="lead"&gt;Thirty-four yes-or-no questions in four tiers for a software team without security staff. Answer each from the evidence named beside it. You reach a tier when every item at that tier and below is answered yes. A tier describes controls in place, not a guarantee of security.&lt;/p&gt;</code> |
| [src/obaaf/form_template.html:287][S061] | <code>function exportAnswers() {</code> |
| [src/obaaf/form_template.html:342][S125] | <code>$("print").addEventListener("click", () =&gt; window.print());</code> |
| [src/obaaf/render.py:65][S041] | <code>def form_note(version: str = __version__) -&gt; str:</code> |
| [templates/github-actions/agent/agent.sh:21][S037] | <code># This example calls no model: it writes a fixed acknowledgement, so the lanes can be tested</code> |
| [templates/github-actions/workflows/obaaf-agent-apply.yml:250][S015] | <code>gh pr create --repo "$GITHUB_REPOSITORY" --base "$DEFAULT_BRANCH" --head "$branch" \</code> |
| [templates/github-actions/workflows/obaaf-agent-propose.yml:117][S010] | <code># R2, R3: read-only access, no id-token, no secrets, no environment.</code> |
| [templates/github-actions/workflows/obaaf-agent-propose.yml:229][S013] | <code>uses: actions/attest@1e69f48acb82d1966a394da916b4c1698aa569d6 # v4.2.2</code> |
| [templates/github-actions/workflows/obaaf-release.yml:89][S117] | <code>uses: actions/attest-build-provenance@4d101475d8b20a2381f78447822ac1eab6504dd8 # v4.2.2</code> |
| [tests/test_controls.py:76][S139] | <code>def test_no_workflow_can_clear_it_yet(self):</code> |
| [tests/test_finding_lifecycle.py:72][S138] | <code>def test_owner_reason_and_a_date_within_a_year_is_valid(self):</code> |
| [tests/test_fr02_assessment.py:188][S108] | <code>class FormParityTest(unittest.TestCase):</code> |
| [tests/test_fr02_assessment.py:72][S062] | <code>def test_not_applicable_counts_as_yes_only_where_allowed(self):</code> |
| [tests/test_fr02_assessment.py:155][S045] | <code>def test_offline_form_cannot_make_network_requests(self):</code> |
| [tests/test_fr02_assessment.py:62][S030] | <code>def test_ranking_within_a_tier_puts_lower_effort_first_then_more_documented_cases(self):</code> |
| [tests/test_fr02_assessment.py:142][S044] | <code>def test_scoring_uses_no_network(self):</code> |
| [tests/test_fr02_assessment.py:56][S029] | <code>def test_tiers_are_cumulative(self):</code> |
| [tests/test_fr06_verifier.py:262][S048] | <code>def test_cli_exit_codes(self):</code> |
| [tests/test_fr06_verifier.py:42][S027] | <code>def test_missing_provenance_blocks(self):</code> |
| [tests/test_fr11_keys.py:33][S047] | <code>def test_only_signing_jobs_can_request_an_identity_and_they_run_no_build_or_agent_code(self):</code> |
| [tests/test_jenkins_cli.py:77][S023] | <code>def test_text_report_states_the_advisory_status(self):</code> |

## Publication limits and follow-up

No claim here establishes an independent production adopter, a successful hosted agent run, a verified model identity, complete network confinement, a SLSA certification, or successful browser QA of the redesign. No external comparison tools were run in this task. No live authenticated settings, repository protections, release upload, GitHub Sigstore signing, or remote demo run was changed or exercised.

Apply homepage corrections in 4.2, dedicated pages in 4.3 and browser validation in 4.4. The stable-form recommendation and changes to shared assessment presentation need an explicitly allowed follow-up. Recheck the latest reviewed landscape before copying its comparison: this pinned base still contains stale broad statements that no settings audit or runtime control exists. The newer settings audit and optional egress wrapper do exist in development, with the limits recorded above. Do not promote them to released capabilities until the selected release includes them.

The site README's hosting and asset descriptions, the adoption guide's Jenkins status, plural pilot wording, and shared assessment prevention labels need maintainer review outside this file. They were not edited here. Any new website wording not covered by a row needs its own source and, for behavior, an observed run before publication.

[S001]: https://github.com/Obaaf/OBAAF/blob/e87d376981ba1ec39767c7b079f24d5ec65924ee/site/index.html#L6
[S002]: https://github.com/Obaaf/OBAAF/blob/e87d376981ba1ec39767c7b079f24d5ec65924ee/LICENSING.md#L3
[S003]: https://github.com/Obaaf/OBAAF/blob/e87d376981ba1ec39767c7b079f24d5ec65924ee/site/index.html#L8
[S004]: https://github.com/Obaaf/OBAAF/blob/e87d376981ba1ec39767c7b079f24d5ec65924ee/docs/landscape.md#L453
[S005]: https://github.com/Obaaf/OBAAF/blob/e87d376981ba1ec39767c7b079f24d5ec65924ee/src/obaaf/cli.py#L420
[S006]: https://github.com/Obaaf/OBAAF/blob/e87d376981ba1ec39767c7b079f24d5ec65924ee/docs/traceability.md#L3
[S007]: https://github.com/Obaaf/OBAAF/blob/e87d376981ba1ec39767c7b079f24d5ec65924ee/site/index.html#L30
[S008]: https://github.com/Obaaf/OBAAF/blob/e87d376981ba1ec39767c7b079f24d5ec65924ee/papers/OBAAF-Paper1-Agent-Assurance-LaTeX/README.md#L1
[S009]: https://github.com/Obaaf/OBAAF/blob/e87d376981ba1ec39767c7b079f24d5ec65924ee/src/obaaf/data/compromises.yaml#L4
[S010]: https://github.com/Obaaf/OBAAF/blob/e87d376981ba1ec39767c7b079f24d5ec65924ee/templates/github-actions/workflows/obaaf-agent-propose.yml#L117
[S011]: https://github.com/Obaaf/OBAAF/blob/e87d376981ba1ec39767c7b079f24d5ec65924ee/docs/checker-configuration.md#L177
[S012]: https://github.com/Obaaf/OBAAF/blob/e87d376981ba1ec39767c7b079f24d5ec65924ee/src/obaaf/cli.py#L403
[S013]: https://github.com/Obaaf/OBAAF/blob/e87d376981ba1ec39767c7b079f24d5ec65924ee/templates/github-actions/workflows/obaaf-agent-propose.yml#L229
[S014]: https://github.com/Obaaf/OBAAF/blob/e87d376981ba1ec39767c7b079f24d5ec65924ee/src/obaaf/checker/__init__.py#L411
[S015]: https://github.com/Obaaf/OBAAF/blob/e87d376981ba1ec39767c7b079f24d5ec65924ee/templates/github-actions/workflows/obaaf-agent-apply.yml#L250
[S016]: https://github.com/Obaaf/OBAAF/blob/e87d376981ba1ec39767c7b079f24d5ec65924ee/site/index.html#L23
[S017]: https://github.com/Obaaf/OBAAF/blob/e87d376981ba1ec39767c7b079f24d5ec65924ee/docs/landscape.md#L451
[S018]: https://github.com/Obaaf/OBAAF/blob/e87d376981ba1ec39767c7b079f24d5ec65924ee/pyproject.toml#L25
[S019]: https://github.com/Obaaf/OBAAF/blob/e87d376981ba1ec39767c7b079f24d5ec65924ee/src/obaaf/catalog.py#L32
[S020]: https://github.com/Obaaf/OBAAF/blob/e87d376981ba1ec39767c7b079f24d5ec65924ee/site/index.html#L31
[S021]: https://github.com/Obaaf/OBAAF/blob/e87d376981ba1ec39767c7b079f24d5ec65924ee/pyproject.toml#L10
[S022]: https://github.com/Obaaf/OBAAF/blob/e87d376981ba1ec39767c7b079f24d5ec65924ee/site/index.html#L32
[S023]: https://github.com/Obaaf/OBAAF/blob/e87d376981ba1ec39767c7b079f24d5ec65924ee/tests/test_jenkins_cli.py#L77
[S024]: https://github.com/Obaaf/OBAAF/blob/e87d376981ba1ec39767c7b079f24d5ec65924ee/docs/traceability.md#L34
[S025]: https://github.com/Obaaf/OBAAF/blob/e87d376981ba1ec39767c7b079f24d5ec65924ee/site/index.html#L34
[S026]: https://github.com/Obaaf/OBAAF/blob/e87d376981ba1ec39767c7b079f24d5ec65924ee/docs/settings-audit.md#L3
[S027]: https://github.com/Obaaf/OBAAF/blob/e87d376981ba1ec39767c7b079f24d5ec65924ee/tests/test_fr06_verifier.py#L42
[S028]: https://github.com/Obaaf/OBAAF/blob/e87d376981ba1ec39767c7b079f24d5ec65924ee/site/index.html#L36
[S029]: https://github.com/Obaaf/OBAAF/blob/e87d376981ba1ec39767c7b079f24d5ec65924ee/tests/test_fr02_assessment.py#L56
[S030]: https://github.com/Obaaf/OBAAF/blob/e87d376981ba1ec39767c7b079f24d5ec65924ee/tests/test_fr02_assessment.py#L62
[S031]: https://github.com/Obaaf/OBAAF/blob/e87d376981ba1ec39767c7b079f24d5ec65924ee/src/obaaf/checker/rules.py#L1101
[S032]: https://github.com/Obaaf/OBAAF/blob/e87d376981ba1ec39767c7b079f24d5ec65924ee/src/obaaf/checker/rules.py#L1132
[S033]: https://github.com/Obaaf/OBAAF/blob/e87d376981ba1ec39767c7b079f24d5ec65924ee/src/obaaf/data/agent_controls.yaml#L169
[S034]: https://github.com/Obaaf/OBAAF/blob/e87d376981ba1ec39767c7b079f24d5ec65924ee/docs/attestations.md#L3
[S035]: https://github.com/Obaaf/OBAAF/blob/e87d376981ba1ec39767c7b079f24d5ec65924ee/docs/attestations.md#L107
[S036]: https://github.com/Obaaf/OBAAF/blob/e87d376981ba1ec39767c7b079f24d5ec65924ee/docs/architecture.md#L20
[S037]: https://github.com/Obaaf/OBAAF/blob/e87d376981ba1ec39767c7b079f24d5ec65924ee/templates/github-actions/agent/agent.sh#L21
[S038]: https://github.com/Obaaf/OBAAF/blob/e87d376981ba1ec39767c7b079f24d5ec65924ee/src/obaaf/checker/__init__.py#L143
[S039]: https://github.com/Obaaf/OBAAF/blob/e87d376981ba1ec39767c7b079f24d5ec65924ee/docs/architecture.md#L69
[S040]: https://github.com/Obaaf/OBAAF/blob/e87d376981ba1ec39767c7b079f24d5ec65924ee/CHANGELOG.md#L236
[S041]: https://github.com/Obaaf/OBAAF/blob/e87d376981ba1ec39767c7b079f24d5ec65924ee/src/obaaf/render.py#L65
[S042]: https://github.com/Obaaf/OBAAF/blob/e87d376981ba1ec39767c7b079f24d5ec65924ee/site/index.html#L37
[S043]: https://github.com/Obaaf/OBAAF/blob/e87d376981ba1ec39767c7b079f24d5ec65924ee/pyproject.toml#L30
[S044]: https://github.com/Obaaf/OBAAF/blob/e87d376981ba1ec39767c7b079f24d5ec65924ee/tests/test_fr02_assessment.py#L142
[S045]: https://github.com/Obaaf/OBAAF/blob/e87d376981ba1ec39767c7b079f24d5ec65924ee/tests/test_fr02_assessment.py#L155
[S046]: https://github.com/Obaaf/OBAAF/blob/e87d376981ba1ec39767c7b079f24d5ec65924ee/src/obaaf/cli.py#L736
[S047]: https://github.com/Obaaf/OBAAF/blob/e87d376981ba1ec39767c7b079f24d5ec65924ee/tests/test_fr11_keys.py#L33
[S048]: https://github.com/Obaaf/OBAAF/blob/e87d376981ba1ec39767c7b079f24d5ec65924ee/tests/test_fr06_verifier.py#L262
[S049]: https://github.com/Obaaf/OBAAF/blob/e87d376981ba1ec39767c7b079f24d5ec65924ee/docs/attestations.md#L55
[S050]: https://github.com/Obaaf/OBAAF/blob/e87d376981ba1ec39767c7b079f24d5ec65924ee/src/obaaf/data/schemas/agent-run.schema.json#L5
[S051]: https://github.com/Obaaf/OBAAF/blob/e87d376981ba1ec39767c7b079f24d5ec65924ee/src/obaaf/data/schemas/agent-approval.schema.json#L5
[S052]: https://github.com/Obaaf/OBAAF/blob/e87d376981ba1ec39767c7b079f24d5ec65924ee/src/obaaf/data/schemas/build-record.schema.json#L5
[S053]: https://github.com/Obaaf/OBAAF/blob/e87d376981ba1ec39767c7b079f24d5ec65924ee/site/index.html#L38
[S054]: https://github.com/Obaaf/OBAAF/blob/e87d376981ba1ec39767c7b079f24d5ec65924ee/site/index.html#L63
[S055]: https://github.com/Obaaf/OBAAF/blob/e87d376981ba1ec39767c7b079f24d5ec65924ee/docs/inference-proxy.md#L3
[S056]: https://github.com/Obaaf/OBAAF/blob/e87d376981ba1ec39767c7b079f24d5ec65924ee/docs/attestations.md#L73
[S057]: https://github.com/Obaaf/OBAAF/blob/e87d376981ba1ec39767c7b079f24d5ec65924ee/site/index.html#L61
[S058]: https://github.com/Obaaf/OBAAF/blob/e87d376981ba1ec39767c7b079f24d5ec65924ee/site/index.html#L49
[S059]: https://github.com/Obaaf/OBAAF/blob/e87d376981ba1ec39767c7b079f24d5ec65924ee/docs/egress-control.md#L128
[S060]: https://github.com/Obaaf/OBAAF/blob/e87d376981ba1ec39767c7b079f24d5ec65924ee/site/index.html#L64
[S061]: https://github.com/Obaaf/OBAAF/blob/e87d376981ba1ec39767c7b079f24d5ec65924ee/src/obaaf/form_template.html#L287
[S062]: https://github.com/Obaaf/OBAAF/blob/e87d376981ba1ec39767c7b079f24d5ec65924ee/tests/test_fr02_assessment.py#L72
[S063]: https://github.com/Obaaf/OBAAF/blob/e87d376981ba1ec39767c7b079f24d5ec65924ee/src/obaaf/data/assessment.yaml#L23
[S064]: https://github.com/Obaaf/OBAAF/blob/e87d376981ba1ec39767c7b079f24d5ec65924ee/docs/self-assessment-walkthrough.md#L3
[S065]: https://github.com/Obaaf/OBAAF/blob/e87d376981ba1ec39767c7b079f24d5ec65924ee/papers/OBAAF-Paper2-Build-Assurance-Games-LaTeX/README.md#L1
[S066]: https://github.com/Obaaf/OBAAF/blob/e87d376981ba1ec39767c7b079f24d5ec65924ee/site/index.html#L65
[S067]: https://github.com/Obaaf/OBAAF/blob/e87d376981ba1ec39767c7b079f24d5ec65924ee/docs/checker-demonstration.md#L6
[S068]: https://github.com/Obaaf/OBAAF/blob/e87d376981ba1ec39767c7b079f24d5ec65924ee/site/main.js#L13
[S069]: https://github.com/Obaaf/OBAAF/blob/e87d376981ba1ec39767c7b079f24d5ec65924ee/docs/checker-demonstration.md#L27
[S070]: https://github.com/Obaaf/OBAAF/blob/e87d376981ba1ec39767c7b079f24d5ec65924ee/docs/checker-demonstration.md#L40
[S071]: https://github.com/Obaaf/OBAAF/blob/e87d376981ba1ec39767c7b079f24d5ec65924ee/site/main.js#L24
[S072]: https://github.com/Obaaf/OBAAF/blob/e87d376981ba1ec39767c7b079f24d5ec65924ee/site/main.js#L8
[S073]: https://github.com/Obaaf/OBAAF/blob/e87d376981ba1ec39767c7b079f24d5ec65924ee/docs/checker-demonstration.md#L53
[S074]: https://github.com/Obaaf/OBAAF/blob/e87d376981ba1ec39767c7b079f24d5ec65924ee/site/main.js#L37
[S075]: https://github.com/Obaaf/OBAAF/blob/e87d376981ba1ec39767c7b079f24d5ec65924ee/docs/agent-checker-demonstration.md#L7
[S076]: https://github.com/Obaaf/OBAAF/blob/e87d376981ba1ec39767c7b079f24d5ec65924ee/docs/agent-checker-demonstration.md#L20
[S077]: https://github.com/Obaaf/OBAAF/blob/e87d376981ba1ec39767c7b079f24d5ec65924ee/site/main.js#L51
[S078]: https://github.com/Obaaf/OBAAF/blob/e87d376981ba1ec39767c7b079f24d5ec65924ee/site/main.js#L41
[S079]: https://github.com/Obaaf/OBAAF/blob/e87d376981ba1ec39767c7b079f24d5ec65924ee/site/main.js#L43
[S080]: https://github.com/Obaaf/OBAAF/blob/e87d376981ba1ec39767c7b079f24d5ec65924ee/site/index.html#L66
[S081]: https://github.com/Obaaf/OBAAF/blob/e87d376981ba1ec39767c7b079f24d5ec65924ee/src/obaaf/data/agent_controls.yaml#L72
[S082]: https://github.com/Obaaf/OBAAF/blob/e87d376981ba1ec39767c7b079f24d5ec65924ee/src/obaaf/data/agent_controls.yaml#L98
[S083]: https://github.com/Obaaf/OBAAF/blob/e87d376981ba1ec39767c7b079f24d5ec65924ee/src/obaaf/data/agent_controls.yaml#L121
[S084]: https://github.com/Obaaf/OBAAF/blob/e87d376981ba1ec39767c7b079f24d5ec65924ee/src/obaaf/data/agent_controls.yaml#L146
[S085]: https://github.com/Obaaf/OBAAF/blob/e87d376981ba1ec39767c7b079f24d5ec65924ee/src/obaaf/data/agent_controls.yaml#L192
[S086]: https://github.com/Obaaf/OBAAF/blob/e87d376981ba1ec39767c7b079f24d5ec65924ee/src/obaaf/data/agent_controls.yaml#L212
[S087]: https://github.com/Obaaf/OBAAF/blob/e87d376981ba1ec39767c7b079f24d5ec65924ee/src/obaaf/data/agent_controls.yaml#L237
[S088]: https://github.com/Obaaf/OBAAF/blob/e87d376981ba1ec39767c7b079f24d5ec65924ee/docs/attestations.md#L53
[S089]: https://github.com/Obaaf/OBAAF/blob/e87d376981ba1ec39767c7b079f24d5ec65924ee/site/index.html#L67
[S090]: https://github.com/Obaaf/OBAAF/blob/e87d376981ba1ec39767c7b079f24d5ec65924ee/docs/adoption-guide.md#L17
[S091]: https://github.com/Obaaf/OBAAF/blob/e87d376981ba1ec39767c7b079f24d5ec65924ee/site/index.html#L68
[S092]: https://github.com/Obaaf/OBAAF/blob/e87d376981ba1ec39767c7b079f24d5ec65924ee/actions/setup-obaaf/action.yml#L51
[S093]: https://github.com/Obaaf/OBAAF/blob/e87d376981ba1ec39767c7b079f24d5ec65924ee/actions/setup-obaaf/action.yml#L16
[S094]: https://github.com/Obaaf/OBAAF/blob/e87d376981ba1ec39767c7b079f24d5ec65924ee/src/obaaf/cli.py#L620
[S095]: https://github.com/Obaaf/OBAAF/blob/e87d376981ba1ec39767c7b079f24d5ec65924ee/docs/architecture.md#L3
[S096]: https://github.com/Obaaf/OBAAF/blob/e87d376981ba1ec39767c7b079f24d5ec65924ee/site/index.html#L69
[S097]: https://github.com/Obaaf/OBAAF/blob/e87d376981ba1ec39767c7b079f24d5ec65924ee/src/obaaf/data/frameworks.yaml#L10
[S098]: https://github.com/Obaaf/OBAAF/blob/e87d376981ba1ec39767c7b079f24d5ec65924ee/site/index.html#L70
[S099]: https://github.com/Obaaf/OBAAF/blob/e87d376981ba1ec39767c7b079f24d5ec65924ee/docs/egress-control.md#L11
[S100]: https://github.com/Obaaf/OBAAF/blob/e87d376981ba1ec39767c7b079f24d5ec65924ee/CHANGELOG.md#L141
[S101]: https://github.com/Obaaf/OBAAF/blob/e87d376981ba1ec39767c7b079f24d5ec65924ee/site/index.html#L71
[S102]: https://github.com/Obaaf/OBAAF/blob/e87d376981ba1ec39767c7b079f24d5ec65924ee/docs/flagship.md#L271
[S103]: https://github.com/Obaaf/OBAAF/blob/e87d376981ba1ec39767c7b079f24d5ec65924ee/CONTRIBUTING.md#L3
[S104]: https://github.com/Obaaf/OBAAF/blob/e87d376981ba1ec39767c7b079f24d5ec65924ee/SECURITY.md#L7
[S105]: https://github.com/Obaaf/OBAAF/blob/e87d376981ba1ec39767c7b079f24d5ec65924ee/site/index.html#L73
[S106]: https://github.com/Obaaf/OBAAF/blob/e87d376981ba1ec39767c7b079f24d5ec65924ee/LICENSING.md#L25
[S107]: https://github.com/Obaaf/OBAAF/blob/e87d376981ba1ec39767c7b079f24d5ec65924ee/src/obaaf/form_template.html#L143
[S108]: https://github.com/Obaaf/OBAAF/blob/e87d376981ba1ec39767c7b079f24d5ec65924ee/tests/test_fr02_assessment.py#L188
[S109]: https://github.com/Obaaf/OBAAF/blob/e87d376981ba1ec39767c7b079f24d5ec65924ee/site/build.py#L145
[S110]: https://github.com/Obaaf/OBAAF/blob/e87d376981ba1ec39767c7b079f24d5ec65924ee/site/build.py#L92
[S111]: https://github.com/Obaaf/OBAAF/blob/e87d376981ba1ec39767c7b079f24d5ec65924ee/site/build.py#L113
[S112]: https://github.com/Obaaf/OBAAF/blob/e87d376981ba1ec39767c7b079f24d5ec65924ee/site/build.py#L114
[S113]: https://github.com/Obaaf/OBAAF/blob/e87d376981ba1ec39767c7b079f24d5ec65924ee/site/build.py#L117
[S114]: https://github.com/Obaaf/OBAAF/blob/e87d376981ba1ec39767c7b079f24d5ec65924ee/DECISIONS.md#L86
[S115]: https://github.com/Obaaf/OBAAF/blob/e87d376981ba1ec39767c7b079f24d5ec65924ee/site/build.py#L126
[S116]: https://github.com/Obaaf/OBAAF/blob/e87d376981ba1ec39767c7b079f24d5ec65924ee/src/obaaf/cli.py#L476
[S117]: https://github.com/Obaaf/OBAAF/blob/e87d376981ba1ec39767c7b079f24d5ec65924ee/templates/github-actions/workflows/obaaf-release.yml#L89
[S118]: https://github.com/Obaaf/OBAAF/blob/e87d376981ba1ec39767c7b079f24d5ec65924ee/site/build.py#L129
[S119]: https://github.com/Obaaf/OBAAF/blob/e87d376981ba1ec39767c7b079f24d5ec65924ee/src/obaaf/attest/records.py#L276
[S120]: https://github.com/Obaaf/OBAAF/blob/e87d376981ba1ec39767c7b079f24d5ec65924ee/src/obaaf/form_template.html#L273
[S121]: https://github.com/Obaaf/OBAAF/blob/e87d376981ba1ec39767c7b079f24d5ec65924ee/src/obaaf/form_template.html#L274
[S122]: https://github.com/Obaaf/OBAAF/blob/e87d376981ba1ec39767c7b079f24d5ec65924ee/src/obaaf/form_template.html#L239
[S123]: https://github.com/Obaaf/OBAAF/blob/e87d376981ba1ec39767c7b079f24d5ec65924ee/docs/adoption-guide.md#L3
[S124]: https://github.com/Obaaf/OBAAF/blob/e87d376981ba1ec39767c7b079f24d5ec65924ee/src/obaaf/form_template.html#L169
[S125]: https://github.com/Obaaf/OBAAF/blob/e87d376981ba1ec39767c7b079f24d5ec65924ee/src/obaaf/form_template.html#L342
[S126]: https://github.com/Obaaf/OBAAF/blob/e87d376981ba1ec39767c7b079f24d5ec65924ee/src/obaaf/data/assessment.yaml#L24
[S127]: https://github.com/Obaaf/OBAAF/blob/e87d376981ba1ec39767c7b079f24d5ec65924ee/src/obaaf/data/assessment.yaml#L27
[S128]: https://github.com/Obaaf/OBAAF/blob/e87d376981ba1ec39767c7b079f24d5ec65924ee/src/obaaf/data/assessment.yaml#L30
[S129]: https://github.com/Obaaf/OBAAF/blob/e87d376981ba1ec39767c7b079f24d5ec65924ee/src/obaaf/data/assessment.yaml#L33
[S130]: https://github.com/Obaaf/OBAAF/blob/e87d376981ba1ec39767c7b079f24d5ec65924ee/src/obaaf/attest/records.py#L205
[S131]: https://github.com/Obaaf/OBAAF/blob/e87d376981ba1ec39767c7b079f24d5ec65924ee/src/obaaf/data/schemas/build-record.schema.json#L13
[S132]: https://github.com/Obaaf/OBAAF/blob/e87d376981ba1ec39767c7b079f24d5ec65924ee/.github/workflows/pages.yml#L7
[S133]: https://github.com/Obaaf/OBAAF/blob/e87d376981ba1ec39767c7b079f24d5ec65924ee/docs/landscape.md#L502
[S134]: https://github.com/Obaaf/OBAAF/blob/e87d376981ba1ec39767c7b079f24d5ec65924ee/docs/flagship.md#L278
[S135]: https://github.com/Obaaf/OBAAF/blob/e87d376981ba1ec39767c7b079f24d5ec65924ee/docs/flagship.md#L262
[S136]: https://github.com/Obaaf/OBAAF/blob/e87d376981ba1ec39767c7b079f24d5ec65924ee/docs/flagship.md#L246
[S137]: https://github.com/Obaaf/OBAAF/blob/e87d376981ba1ec39767c7b079f24d5ec65924ee/docs/checker-configuration.md#L163
[S138]: https://github.com/Obaaf/OBAAF/blob/e87d376981ba1ec39767c7b079f24d5ec65924ee/tests/test_finding_lifecycle.py#L72
[S139]: https://github.com/Obaaf/OBAAF/blob/e87d376981ba1ec39767c7b079f24d5ec65924ee/tests/test_controls.py#L76
[S140]: https://github.com/Obaaf/OBAAF/blob/e87d376981ba1ec39767c7b079f24d5ec65924ee/docs/flagship.md#L279
[S141]: https://github.com/Obaaf/OBAAF/blob/e87d376981ba1ec39767c7b079f24d5ec65924ee/docs/landscape.md#L465
[S142]: https://github.com/Obaaf/OBAAF/blob/e87d376981ba1ec39767c7b079f24d5ec65924ee/docs/flagship.md#L268
[S143]: https://github.com/Obaaf/OBAAF/blob/e87d376981ba1ec39767c7b079f24d5ec65924ee/docs/flagship.md#L280
[S144]: https://github.com/Obaaf/OBAAF/blob/e87d376981ba1ec39767c7b079f24d5ec65924ee/site/build.py#L143
[S145]: https://github.com/Obaaf/OBAAF/blob/e87d376981ba1ec39767c7b079f24d5ec65924ee/docs/flagship.md#L264
[S146]: https://github.com/Obaaf/OBAAF/blob/e87d376981ba1ec39767c7b079f24d5ec65924ee/docs/landscape.md#L466
[S147]: https://github.com/Obaaf/OBAAF/blob/e87d376981ba1ec39767c7b079f24d5ec65924ee/docs/landscape.md#L467
[S148]: https://github.com/Obaaf/OBAAF/blob/e87d376981ba1ec39767c7b079f24d5ec65924ee/docs/landscape.md#L468
[S149]: https://github.com/Obaaf/OBAAF/blob/e87d376981ba1ec39767c7b079f24d5ec65924ee/docs/landscape.md#L469
[S150]: https://github.com/Obaaf/OBAAF/blob/e87d376981ba1ec39767c7b079f24d5ec65924ee/docs/landscape.md#L470
[S151]: https://github.com/Obaaf/OBAAF/blob/e87d376981ba1ec39767c7b079f24d5ec65924ee/docs/landscape.md#L471
[S152]: https://github.com/Obaaf/OBAAF/blob/e87d376981ba1ec39767c7b079f24d5ec65924ee/docs/landscape.md#L472
[S153]: https://github.com/Obaaf/OBAAF/blob/e87d376981ba1ec39767c7b079f24d5ec65924ee/docs/landscape.md#L473
