# Records and attestation formats

OBAAF writes four kinds of record. Each signed record is an [in-toto statement](https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md) whose subjects are files identified by SHA-256 digest. The predicate formats are drafts (version 0.1); their JSON Schemas are in [`src/obaaf/data/schemas/`](../src/obaaf/data/schemas/).

| Record | Predicate type | Subjects | Written by | Signed by |
| --- | --- | --- | --- | --- |
| SLSA provenance | `https://slsa.dev/provenance/v1` | release artifacts | GitHub's attest-build-provenance action (or `obaaf attest slsa` elsewhere) | release lane attest job |
| Build record | `https://obaaf.example/attestation/build-record/v0.1` | release artifacts | `obaaf attest build-record` | release lane attest job |
| Agent-run record | `https://obaaf.example/attestation/agent-run/v0.1` | proposal bundle files | `obaaf attest agent-run` | agent lane attest job |
| Approval record | `https://obaaf.example/attestation/agent-approval/v0.1` | proposal bundle files | `obaaf attest approval` | effect lane, `approve` job |

The `obaaf.example` URIs are provisional and will change before public release (DECISIONS.md, D-007). In the GitHub Actions templates, every attestation is signed through GitHub's Sigstore with the signing workflow's identity, in a job that runs no build or agent code, using a certificate issued for that job; no long-lived signing key exists for attestations (FR11). Studios on other CI systems can sign the same predicates as DSSE envelopes with a key held in a key service and verify them with `signing: keys`.

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

Adds to SLSA provenance what game builds need. Each field says who reported it:

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

- which workflow may sign provenance, and from which refs (required);
- the allowed isolation tiers;
- the protected branch the released commit must be on;
- the release environments, and how many distinct approvers they need;
- the commit after which agent commits are checked (`agents.since`);
- where agent records live, and which workflows must sign them.

Missing certificate fields fail verification. An attestation that fails the policy is ignored, with a warning, when a valid one exists for the same file.
