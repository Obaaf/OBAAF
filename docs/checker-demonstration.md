# GitHub Actions checker demonstration

This is a limited demonstration on `Ofonna-N/netflix-clone-2`, not an independent
studio pilot or a validation of the complete OBAAF framework.

## Version note

The audit ran OBAAF 0.1 (the commit named below), which rated the unpinned action
OBAAF-GHA-008 at medium, so the medium gate blocked it. From 0.2, an unpinned action in an
ordinary job with explicitly read-only permissions, no secrets and no privileged outside
trigger is rated low and does not fail a medium gate; release, agent and effect jobs stay
high. This workflow's job is read-only with no secrets, so 0.2 would report the same
finding at low severity. Use `--fail-on low` to keep blocking it.

## What was tested

The application workflow installs dependencies, checks TypeScript, and builds
the app. A separate auditor installs OBAAF at commit
`a039d0c848efaa0576c560e94be1c6fa6691658b` from the private repository, reads the
proposed commit's files as data, and reports an `OBAAF audit` status.

The auditor's code and policy come from protected `main`. It does not execute
the proposed commit's scripts or consume artifacts or caches from its CI run.
A dedicated read-only deploy key accesses OBAAF. Its private half is stored in
the `obaaf-audit` environment, restricted to `main`.

## Risky revision

At commit `318fd850a24aa43aebf7ac138a328643d38727ec`, the checkout action's full
commit SHA was replaced with the official `v6.0.0` tag. A tag can move to different
code; a full commit SHA selects an exact revision. Pinning does not establish
that the selected code itself is safe.

- [Application CI passed](https://github.com/Ofonna-N/netflix-clone-2/actions/runs/38005076608).
- [OBAAF failed](https://github.com/Ofonna-N/netflix-clone-2/actions/runs/38005157685)
  with `OBAAF-GHA-008`, a medium finding for an action not pinned to a full digest.
- After making `OBAAF audit` a required status, GitHub reported the non-draft PR
  as blocked from merging. The risky revision was not merged into `main`.

## Corrected revision

At commit `9743e9847dcb1a4e243a2a1aae6b281a215b631a`, checkout was restored to
`1af3b93b6815bc44a9784bd300feb67ff0d1eeb3`, the reviewed revision for v6.0.0.

- [Application CI passed](https://github.com/Ofonna-N/netflix-clone-2/actions/runs/38005238458).
- [OBAAF passed](https://github.com/Ofonna-N/netflix-clone-2/actions/runs/38005287677)
  with no active findings at the medium-or-higher threshold.
- GitHub reported the PR as mergeable with both required checks satisfied.

The [demonstration PR](https://github.com/Ofonna-N/netflix-clone-2/pull/5) retains
both revisions and reproduction instructions.

## Exception and limits

Both audit reports include one exception for `OBAAF-GHA-001` in the auditor's
own `workflow_run` job. OBAAF flags that job's access to a secret even though it
executes trusted code and treats the proposed files only as data. The exception
documents that boundary and expires January 9, 2027. A passing report with this
exception is not a claim of zero unsuppressed risks outside the checked rules.

The example establishes that an application can build successfully while its
workflow has a configuration risk, and that the audit can block that change.
It does not validate application vulnerability scanning, all eight agent
controls, release verification, enforced network isolation, or every platform
acceptance criterion. The checker detects configured patterns; it does not
prove that the repository is secure.

The [live acceptance plan](live-acceptance-tests.md) remains the checklist for
broader platform validation. Reviewers should distinguish this demonstration's
recorded results from criteria that have not yet been exercised.
