# F4 Derived data and caches

Control family F4 treats cache entries as build inputs with an author. If release builds read a cache that others can write, anyone who can write to it can influence what ships. It covers profile requirements [G4.1](../../spec/profile.md#g41-scope-caches-by-lane), [G4.2](../../spec/profile.md#g42-regenerate-or-verify-derived-data-for-releases) and [G4.3](../../spec/profile.md#g43-check-code-artifacts-by-independent-rebuild).

This is draft guidance for OBAAF version 0.1. The studio pilot will test and revise it. Terms are explained in the [glossary](../glossary.md).

<a id="item-2-7"></a>
## Item 2.7: Release caches protected from untrusted writers

**Why.** A poisoned CI cache reached the release build in the [Ultralytics case](https://blog.pypi.org/posts/2024-12-11-ultralytics-attack-analysis/), and an AI triage agent steered by an issue title poisoned a cache used by release jobs in the [Clinejection case](https://adnanthekhan.com/posts/clinejection/). Engines add their own shared caches: Unreal's shared derived-data cache makes data built by one person available to every user and build machine ([Epic Games](https://dev.epicgames.com/documentation/en-us/unreal-engine/using-derived-data-cache-in-unreal-engine)).

**Do this.**

- List every cache release builds read: CI caches, package caches, engine derived-data caches and cache servers, and container layer caches.
- On GitHub Actions, set `cache-mode: none` on release jobs, as the [release](../../templates/github-actions/workflows/obaaf-release.yml) and [publish](../../templates/github-actions/workflows/obaaf-publish.yml) templates do, so no release job can restore a cache another workflow wrote.
- Never let a workflow that outsiders can start write to a cache. These are workflows started by issues, comments, `pull_request_target`, or `workflow_run` after another workflow. On github.com, GitHub gives some of them read-only cache access by default (`pull_request_target`, `issue_comment`, and `workflow_run` runs that follow a pull request from a fork, per [GitHub's changelog](https://github.blog/changelog/2026-06-26-read-only-actions-cache-for-untrusted-triggers)), but not every such case, so set `cache-mode: none` or `read` on them yourself.
- Give the release lane its own engine cache (a separate shared derived-data cache or cache server), writable only by release machines. Do not point release builds at the cache that workstations and pull-request builds write.
- Run `obaaf check`: rules `OBAAF-GHA-006` and `OBAAF-GHA-007` report caches shared between lanes.

**Keep as evidence.** The access permissions of each cache release builds read.

<a id="item-4-2"></a>
## Item 4.2: Independent rebuild

**Why.** Build-time tampering leaves the source clean: SUNSPOT swapped a source file during compilation and restored it afterward ([CrowdStrike](https://www.crowdstrike.com/en-us/blog/sunspot-malware-technical-analysis/)). Rebuilding on a separate machine and comparing exposes such tampering, as long as the separate machine was not compromised too.

**Do this.**

- Rebuild the release's executables (not cooked content, which can be nondeterministic) on a separate machine from the same source revision and manifest.
- Compare the results byte for byte, and list every difference.
- Remove avoidable differences, such as embedded timestamps and absolute paths, using your compiler's reproducibility options.
- Keep a short list of expected differences, such as signatures and known engine nondeterminism, and investigate anything else before release.

**Keep as evidence.** The comparison report for the latest release.

<a id="item-4-4"></a>
## Item 4.4: Release-lane derived data

**Why.** Cooking can be intermittently nondeterministic, so cooked content cannot always be checked by rebuilding it. The release lane should trust only derived data it produced itself (G4.2).

**Do this.**

- Either regenerate derived data from scratch in every release build, or have release builds read only content-addressed cache entries written by the release lane.
- If regenerating takes too long, keep a release-only cache that only release machines can write, and record its location in the build configuration.

**Keep as evidence.** The cache configuration for release builds.
