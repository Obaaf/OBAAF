# Records and attestation formats

OBAAF writes four kinds of record. Each signed record is an [in-toto statement](https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md) whose subjects are files identified by SHA-256 digest. The predicate formats are drafts (version 0.1); their JSON Schemas are in [`src/obaaf/data/schemas/`](../src/obaaf/data/schemas/).

| Record | Predicate type | Subjects | Written by | Signed by |
| --- | --- | --- | --- | --- |
| SLSA provenance | `https://slsa.dev/provenance/v1` | release artifacts | GitHub's attest-build-provenance action (or `obaaf attest slsa` elsewhere) | release lane attest job |
| Build record | [`https://www.obaaf.com/attestation/build-record/v0.1`](https://www.obaaf.com/attestation/build-record/v0.1) | release artifacts | `obaaf attest build-record` | release lane attest job |
| Agent-run record | [`https://www.obaaf.com/attestation/agent-run/v0.1`](https://www.obaaf.com/attestation/agent-run/v0.1) | proposal bundle files | `obaaf attest agent-run` | agent lane attest job |
| Approval record | [`https://www.obaaf.com/attestation/agent-approval/v0.1`](https://www.obaaf.com/attestation/agent-approval/v0.1) | proposal bundle files | `obaaf attest approval` | effect lane, `approve` job |

Each OBAAF type URI resolves to a page describing its format, and each schema's `$id` resolves to the schema (DECISIONS.md, D-007). OBAAF 0.1 used provisional `obaaf.example` URIs; records signed with them do not verify under 0.2 or later. In the GitHub Actions templates, every attestation is signed through GitHub's Sigstore with the signing workflow's identity, in a job that runs no build or agent code, using a certificate issued for that job; no long-lived signing key exists for attestations (FR11). Studios on other CI systems sign the same predicates as DSSE envelopes with a key held in a key service (`obaaf dsse prepare`, the key service, then `obaaf dsse assemble`) and verify them with `signing: keys`; the [Jenkins release lane](jenkins.md#the-release-lane-on-jenkins) is the worked example. In a Jenkins build, the records' `run` field names the build from its own environment and is marked self-reported.

## The snapshot (R1)

Not signed itself; its digest is bound into the agent-run record. Written by `obaaf snapshot` before the agent starts:

```json
{
  "format": "obaaf-snapshot/v0.1",
  "takenAt": "2026-10-06T12:00:00Z",
  "trigger": {
    "event": "issue_comment", "action": "created", "number": 42, "id": "123456",
    "repository": "OWNER/REPO", "repositoryVisibility": "public",
    "principal": {"login": "maintainer", "level": "Maintainer", "labelSource": "repository role 'admin'"}
  },
  "inputs": [
    {"name": "comment.body", "channel": "issue_comment.comment.body", "path": "inputs/01-comment.body.txt",
     "digest": {"sha256": "…"}, "author": "maintainer", "label": "Maintainer", "labelSource": "repository role 'admin'"},
    {"name": "issue.body", "channel": "issue_comment.issue.body", "path": "inputs/03-issue.body.txt",
     "digest": {"sha256": "…"}, "author": "outsider", "label": "Public", "labelSource": "repository role 'read'"}
  ],
  "floor": {"label": "Public", "reason": "public repository: the agent's token can read content that anyone can write"},
  "integrityLevel": "Public"
}
```

The integrity level is the lowest label among the inputs, the floor and the triggering principal: the meet in Paper 1, section 5.1. The floor is Public unless the workflow raises it with `--floor` (D-008). The snapshot job publishes the digest of `snapshot.json` as a job output, and the attest job checks the snapshot against it, so a snapshot replaced during the agent run is caught there. The effect lane checks the snapshot again, against the digest in the signed agent-run record (`obaaf verify agent-run`), before it trusts the issue number or the list of requesters in it.

## The agent-run record (R8, FR10)

Fields follow Paper 1, Table 3:

| Field | Content | From |
| --- | --- | --- |
| `trigger` | event, number, repository, triggering principal and level | snapshot |
| `inputs` | every snapshot item with digest, channel and label; the floor; the integrity level; the snapshot digest | snapshot |
| `authority` | token permissions, secret names, environment, OIDC permission, cache mode, declared network policy, runner | the protected workflow definition |
| `agent` | the actions the agent job runs, with commit digests; harness; model identifier and version | workflow definition and the inference proxy |
| `trace` | digest of the agent's own trace, marked `"trusted": false` | the agent harness |
| `run` | the CI run that produced it | the platform |

Approvals happen after this record is signed, so they are recorded in the approval record over the same subjects (D-009). Version 0.1 differs from Table 3 in three ways. The trace is one digest of the trace file, not a digest per tool call. The model fields stay empty until an inference proxy reports them (D-020). The approval time is when the effect lane read the approval.

Before acting on a proposal, the effect lane runs `obaaf verify agent-run`. It passes only if all of these hold:

- the record is signed by the agent workflow on the protected branch;
- it covers exactly the files in the proposal bundle, by name and digest;
- it names the downloaded snapshot and the agent run;
- it shows an agent job without write access, OIDC, secrets, an environment, caches or a self-hosted runner.

## Proposal checks (R4)

`obaaf proposal check` reads the patch twice: with Git itself (`git apply --numstat`, forwards and in reverse, and `--summary`) and with a strict parser of its own. Every path Git reports must also be one the parser found, the number of file changes must match the number of `diff --git` headers, and every path either of them names must pass. It refuses:

- protected paths: `.github/`, `.obaaf/`, `.git/`, `CODEOWNERS`, `.gitmodules`, `.gitattributes`, `.lfsconfig`, the OBAAF manifest files, every agent instruction file, and any `--protect` pattern, compared without regard to letter case and ignoring trailing dots and spaces;
- any other path under a name starting with `.`, unless allowed with `--allow-dot-path`;
- renames and copies, binary changes, symbolic links, submodules, and any file mode other than 100644 and 100755;
- paths with control characters, backslashes, colons or hidden characters, and paths outside the repository.

With `--repo`, it also applies the patch to a temporary index of the repository at HEAD and checks the resulting changes and their modes, which is the only way to see a patch that changes an existing symbolic link without saying so. Comments may contain no `](`, `]:`, `<`, `//`, `www.`, URL schemes or email addresses, and no hidden characters; labels must come from the allow-list.

## The approval record (R4)

Who approved applying the proposal, in which environment, and who requested the work. The requesters are the people who started or re-ran the agent run or the effect run, the principal who triggered the agent, and every author of the agent's inputs. `obaaf attest approval` refuses to write a record when no approval comes from someone outside that list. The approvals API does not return review times, so `recordedAt` is when the effect job read the approval.

## The build record (G7.1, FR4, FR5)

Adds to SLSA provenance what game builds need. The source, assets, manifest, SDK entries and isolation fields carry reporter labels. The table also identifies where the builder and trigger metadata come from.

| Field | Content | Reported by |
| --- | --- | --- |
| `source` | repository, revision and ref | the platform |
| `assets` | asset revision and system (Git, Perforce, …) | the platform for Git, the build job otherwise |
| `manifest` | digest of the binary manifest, entry and component counts | the attest job |
| `sdks` | engine, SDK, plugin and middleware versions from the manifest | the manifest |
| `isolation` | Tier A or B, whether it can meet SLSA Build L3, runner environment and labels | the protected workflow definition (D-015) |
| `builder` | builder identity and workflow | the platform |
| `trigger` | who started the release | the platform |

## The agent record file (G8.3)

`.obaaf/records/<bundle digest>.json`, added by the effect lane in the same commit as each agent-authored change and named in the commit's `OBAAF-Agent-Record:` trailer:

```json
{
  "format": "obaaf-agent-record/v0.1",
  "bundleDigest": {"sha256": "…"},
  "proposal": {"files": {"patch.diff": "<base64>"}},
  "attestations": {"agentRun": {"…": "Sigstore bundle or DSSE envelope"}, "approval": {"…": "…"}},
  "agentRunUrl": "https://github.com/OWNER/REPO/actions/runs/…"
}
```

The bundle digest is the SHA-256 of the sorted list of `[file name, file SHA-256]` pairs, serialized as compact JSON.

`obaaf verify release` finds agent-authored commits by the trailer, by an added record file, or by the effect lane's commit identity (`agents.effect_identities`). It blocks the commit unless all of these hold:

- the commit adds exactly one record, named after its bundle digest, that no other commit in the range uses, and changes nothing else in the records directory;
- both attestations verify and cover the record's files;
- the agent run held no write access, OIDC, secrets, environment, caches or self-hosted runner;
- someone other than the requesters approved;
- with `require_exact_diff` (the default), applying the approved patch to the commit's parent gives exactly the commit's change.

A record without a patch cannot accompany a commit that changes files. A merge made under the effect lane's identity is blocked, because the effect lane never merges.

## The release policy

`obaaf verify release` and `obaaf verify agent-run` read `.github/obaaf-policy.yaml` ([example](../templates/github-actions/obaaf-policy.example.yaml)) from the default branch. It sets:

- with `signing: sigstore`, which workflow may sign provenance, and from which refs (required);
- the allowed isolation tiers;
- the protected branch the released commit must be on;
- the release environments, and how many distinct approvers they need;
- the commit after which agent commits are checked (`agents.since`);
- where agent records live, and which workflows must sign them.

The policy decides what may ship, so both commands read it strictly. Each field must have its YAML type: text, `true` or `false`, a whole number of 0 or more written in plain decimal digits (`min_approvals`), or a list of non-empty texts, even with one entry (`source_refs: ["refs/tags/v*"]`, not `source_refs: refs/tags/v*`). Booleans follow YAML 1.2, so `no`, `off` and `"false"` are text, not false; a whole number such as `010` or `0x10`, which PyYAML reads as YAML 1.1 does (8 and 16), is refused. These are each an `error:` naming the file, and the command ends with status 2 before it checks anything:

- a value of another type, or an empty list (leaving the key out means no restriction for `approvers` and `runner_environments` and the default for `allowed_tiers`, `environments` and `effect_identities`; `source_refs` with Sigstore and each role under `keys` need an entry);
- a field written with no value (a section with nothing under it, `keys` included, is read as absent);
- a key the policy does not define (a misspelling such as `min_aprovals`), and a field only Sigstore checks written with `signing: keys`: that kind of signing checks each record's key and not the workflow, ref, runner or issuer, so `provenance` may hold none of its four fields and `agents` neither `propose_workflow`, `apply_workflow` nor `source_ref`; with `signing: sigstore`, a `keys` section with anything in it;
- both `release.environment` and `release.environments`;
- YAML that cannot be read, and a file that is not UTF-8.

The error names the field and its line where it can; an error from the YAML loader names the line where the loader gives one. Remove a key to use its default. `branch: ""` still turns the protected-branch check off, `since: ""` still means not set, and an empty text still gives the other text fields that have a default (`signer_workflow`, `issuer`, `environment`, `records_dir`, the two agent workflows, `source_ref`, where the `signing` allows them) that default.

With `signing: keys`, the policy's `repository` is not checked against the records: the verifier checks that each record is signed with a policy key, not which repository the record says it was built from ([#406](https://github.com/Obaaf/OBAAF/issues/406)). Whoever holds a key can sign a record for any build.

Missing certificate fields fail verification. An attestation that fails the policy is ignored, with a warning, when a valid one exists for the same file.

## The release decision

`obaaf verify release` writes its decision as text by default, or as JSON with `--format json`, and in a GitHub run also to the step summary, as text. The exit status is 0 when nothing it checked blocks and 1 when something does. Where a full verification counts GitHub approvals (`release.min_approvals` above 0, and no Jenkins build's JSON given), an `--approvals` file that is not in the shape GitHub's API gives blocks, and no approval in it is counted: it must be a list of objects, and in each, `environments`, where given, a list of objects whose `name` is text, and `user`, where given, an object whose `login` is text (a missing or null `name`, `user` or `login` counts for nothing). A pre-approval run, and a run whose policy needs no approval, do not read that file.

A run that stops on an error before it has decided writes no decision. It ends with 2, and an `error:` line, for wrong arguments; for a policy it cannot read or whose fields are not valid (see the release policy, above); for an `--approvals` or `--release-run` file it cannot read or that is not JSON; and for a `--revision-file` that does not hold one commit ID. It ends with 1 for an error while it verifies: an `error:` line (a key file it cannot read), or a Python traceback for an input of a shape it does not read, such as a Jenkins build's JSON with `"causes": 5` or a DSSE envelope whose `payload` is a number (#414; not every input has been tried). Once it has decided, it writes the decision to the console or the `--output` file, then the text to the console after a JSON `--output`, then the step summary. If one of these cannot be written, the run ends in a traceback with status 1, and what was written before stays, so a decision that says the checks passed can stand beside status 1 (#414). A run that stops early leaves an `--output` file from an earlier run as it was. Read a decision only from a run whose status you have checked.

`--pre-approval` skips the approvals, so that the approver can read the rest before approving. On Jenkins it also skips the checks that tie the publishing build to the tag build: that both builds' JSON is given, that the publishing build was started by exactly one build and not by hand, that this build is the one given as `--release-run`, and that it is a tag build of `release.jenkins_project`, which the policy must set. So a Jenkins pre-approval run can pass under a policy without `release.jenkins_project`, which a full verification given a Jenkins build's JSON blocks. Such a run never decides that the upload may proceed: its text report begins `Pre-approval checks: PASSED, release approval is still required` (or `full verification is still required` where `release.min_approvals` is 0) when nothing it checked blocks, and the run that decides the upload is a full verification without `--pre-approval`, after the approval.

The JSON decision, `obaaf-release-decision/v0.2`:

```json
{
  "format": "obaaf-release-decision/v0.2",
  "allowed": false,
  "checksPassed": true,
  "preApproval": true,
  "approvalsRequired": 1,
  "blocks": [],
  "warnings": ["approvals were not checked (pre-approval run); the upload job checks them"],
  "artifacts": [{"name": "game.zip", "sha256": "…", "provenance": "verified", "buildRecord": "verified", "tier": "A"}],
  "agentCommits": [],
  "approvals": []
}
```

- `allowed`: the upload may proceed. True only for a full verification in which nothing blocks; false for every pre-approval run. A program that decides whether to upload reads this field.
- `checksPassed`: nothing this run checked blocks, so `blocks` is empty and the exit status is 0. A program that shows a pre-approval result to the approver reads this field.
- `preApproval`: the run was made with `--pre-approval`.
- `approvalsRequired`: the policy's `release.min_approvals`, the number of distinct approvers the full verification needs.
- `blocks` and `warnings`: what blocks, and what does not. `approvals`: the approvers who were counted, empty in a pre-approval run.

In `obaaf-release-decision/v0.1`, written before slice 2d.24 (#394), `allowed` meant what `checksPassed` means now, so a pre-approval run that passed had `"allowed": true`, the same as a full verification that may be uploaded; v0.1 has none of the three new fields.
