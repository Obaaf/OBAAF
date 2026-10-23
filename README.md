# Open Build and Agent Assurance Framework (OBAAF)

OBAAF is a free, open framework for keeping malicious code out of the software updates people install. It secures the build pipelines that produce those updates, and the AI agents now connected to them. It works for any team that ships software updates. The first version is shaped by the needs of small teams without dedicated security staff, independent game studios among them, whose updates reach phones, PCs and consoles.

> **Status: version 0.1, in active adoption.** OBAAF 0.1.0 is on PyPI (`pip install obaaf`) and in use with pilot teams. The first external pilot ran the checker on a production repository; its feedback is tracked in [issue #19](https://github.com/Obaaf/OBAAF/issues/19) and shapes the [0.2 roadmap](docs/roadmap-0.2.md). The checker was also exercised in a [limited GitHub Actions demonstration](docs/checker-demonstration.md). Broader platform validation continues, and formats may still change before 1.0. The code is licensed under Apache-2.0 and the specifications and documentation under CC BY 4.0. This is not a research-paper submission. The specifications and tools are built only from public standards and public documentation. See [LICENSING.md](LICENSING.md).
>
> Design decisions, including those still proposed, are tracked in [DECISIONS.md](DECISIONS.md).

## What is here

| Component | What it does | Where |
| --- | --- | --- |
| Build-integrity profile | 28 requirements in nine control families that tailor NIST's SSDF and SLSA to software build pipelines, with game studios as the worked example, each with a test and its mappings | [spec/profile.md](spec/profile.md) |
| Agent controls | Taint-bounded authority, eight requirements (R1–R8), a three-lane architecture and a signed record of each agent run | [spec/agent-controls.md](spec/agent-controls.md) |
| Self-assessment | 34 yes-or-no questions in four tiers that give a tier and a ranked list of fixes, on paper, in an offline form, or from the command line | [spec/self-assessment.md](spec/self-assessment.md), [offline form](assessment/obaaf-self-assessment.html) |
| Team resource site | A public resource introducing the framework, questionnaire, workflow demonstration, and adoption steps | [Build and preview instructions](site/README.md) |
| Reference pipeline templates | GitHub Actions workflows for four lanes: untrusted contributions, agents, approved changes and releases | [templates/github-actions](templates/github-actions/README.md) |
| Verification tools | A pipeline checker that flags risky workflow settings; a release verifier that blocks uploads without valid provenance, approvals and agent records; and checks on an agent's signed record and proposal before anything is applied | [spec/checker-rules.md](spec/checker-rules.md), `obaaf verify release`, `obaaf verify agent-run`, `obaaf proposal check` |

The profile, the agent controls and the self-assessment come from the author's two companion papers, both unpublished drafts:

- **Paper 1**, [*Untrusted Text, Trusted Tokens*](papers/OBAAF-Paper1-Agent-Assurance-LaTeX/README.md): agent assurance, the source of the agent controls.
- **Paper 2**, [*Securing the Game Build*](papers/OBAAF-Paper2-Build-Assurance-Games-LaTeX/README.md): build assurance for games, the source of the profile and the self-assessment, whose controls apply to any software team.

Their machine-readable form in [`src/obaaf/data/`](src/obaaf/data/) is the single source of truth: the documents in `spec/` and the offline form are generated from it.

## How it fits together

```mermaid
flowchart LR
  subgraph untrusted["Untrusted lane"]
    PR["Pull requests,<br/>including partners' forks"] --> CI["Build and test<br/>no secrets, read-only"]
  end
  subgraph agent["Agent lane (level of its inputs)"]
    EV["Issue or comment"] --> SN["Snapshot<br/>digests and labels"] --> AG["Agent<br/>read-only, no secrets"] --> PB["Proposal bundle"]
    PB --> AT["Attestation step<br/>signs agent-run record"]
  end
  subgraph effect["Effect lane (Maintainer)"]
    AP["Approval by someone<br/>other than the requester"] --> EF["Checks, then applies<br/>as a pull request"]
  end
  subgraph release["Release lane (Release)"]
    BU["Isolated build from a tag<br/>Tier A or B, no shared cache"] --> PV["Signed provenance<br/>and build record"] --> VE["Verify from the default branch,<br/>then a person approves"] --> UP["Upload; a person<br/>sets it live"]
  end
  AT --> AP
  EF --> PRV["Reviewed merge"] --> BU
```

## Quick start

OBAAF needs Python 3.10 or later.

```bash
pip install "obaaf[keys]"   # omit [keys] if you only need assess and check
obaaf --help
```

**Teams.** Start with the self-assessment. Open [the offline form](assessment/obaaf-self-assessment.html) in a browser, or:

```bash
obaaf assess init --output answers.yaml   # fill in yes, no or na
obaaf assess score answers.yaml           # your tier and what to fix first
```

Your answers never leave your machine. Then follow [the adoption guide](docs/adoption-guide.md).

**Build engineers.** Check your workflows, then install the templates:

```bash
obaaf check path/to/your/repository
obaaf templates install --dest path/to/your/repository --obaaf-repo OWNER/obaaf --obaaf-sha <commit>
```

**Reviewers.** Read [the architecture](docs/architecture.md), [the decisions log](DECISIONS.md), and [how each requirement is tested](docs/traceability.md).

## Tests

```bash
python -m unittest discover -s tests -v
obaaf docs build --check   # the generated documents match the data
obaaf catalog              # the data files agree with each other
```

Each functional requirement of the specification (FR1–FR12) has an offline test module. Some acceptance criteria can only be shown on a real GitHub repository, such as a fork's pull request being denied secrets: for those, the offline tests check the templates and tools, and the [live acceptance tests](docs/live-acceptance-tests.md), which have not been run yet, check the platform. [Traceability](docs/traceability.md) gives the status of each requirement, including the ones version 0.1 meets only in part.

## Project documents

- [DECISIONS.md](DECISIONS.md): every design decision, its reason and its status
- [CHANGELOG.md](CHANGELOG.md): changes by version
- [CONTRIBUTING.md](CONTRIBUTING.md): contribution rules and review responsibilities
- [SECURITY.md](SECURITY.md): how to report a vulnerability
- [GOVERNANCE.md](GOVERNANCE.md): project roles, decision-making, and how to become a maintainer
- [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md): expected conduct in the community
- [LICENSING.md](LICENSING.md): current licensing status and intended licenses

Software project attribution: [Ofonna Nweze](https://github.com/Ofonna-N) and [Osita Sean Keluo-Udeke](https://github.com/seanudeke).

Both contributors maintain the project. The Python package metadata credits both names.

Sean led the research. Ofonna handled implementation, testing, and GitHub
integration, with Sean contributing across the project.

The companion research papers are the independent work of Osita Sean Keluo-Udeke. The project does not imply endorsement by any government agency or by the research author's employer.
