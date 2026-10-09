# F3 Build execution

Control family F3 keeps release builds away from untrusted work, isolates them, limits where they can send data, and removes standing credentials. It covers profile requirements [G3.1](../../spec/profile.md#g31-separate-the-release-lane), [G3.2](../../spec/profile.md#g32-use-tiered-isolation), [G3.3](../../spec/profile.md#g33-restrict-egress-from-release-hosts) and [G3.4](../../spec/profile.md#g34-keep-no-standing-secrets-on-build-hosts).

This is draft guidance for OBAAF version 0.1. The studio pilot will test and revise it. Terms are explained in the [glossary](../glossary.md).

<a id="item-1-4"></a>
## Item 1.4: List of build and signing machines

**Why.** You can only isolate, reimage and watch the machines you know about. Attackers have compromised build environments and build orchestration servers at game developers (the 2019 compromises and PipeMon).

**Do this.**

- List every machine, virtual machine and CI runner pool that builds or signs release builds, with its owner, its purpose and the platforms it builds.
- Include cloud CI runners by pool or label, and machines under a desk.
- Review the list at least every 90 days.

**Keep as evidence.** The list, updated within the last 90 days.

<a id="item-2-1"></a>
## Item 2.1: Release-only build machines

**Why.** A machine that builds unreviewed changes can be made to run attacker code, which can then tamper with later builds on that machine. Persistent runners that ran pull-request workflows exposed release credentials in the [PyTorch case](https://johnstawinski.com/2024/01/11/playing-with-fire-how-we-executed-a-critical-supply-chain-attack-on-pytorch/).

**Do this.**

- Build pull requests, partner work and agent tasks in an untrusted lane, on separate machines. The [untrusted CI template](../../templates/github-actions/workflows/obaaf-untrusted-ci.yml) uses GitHub-hosted runners, which start every job on a new machine.
- Run release builds only on machines that never take those jobs: GitHub-hosted runners in the [release template](../../templates/github-actions/workflows/obaaf-release.yml), or self-hosted machines whose runner registration or agent pool only the release workflow uses.
- In Jenkins, and any CI system where the build definition inside a change chooses its agent, a separate label is not enough: a pull request's Jenkinsfile can name the release label. Restrict release agents to the release job (for example with a job-restriction plugin), or build pull requests on a separate controller, and make sure pull requests from outside run a build definition they cannot edit.
- Turn off interactive logins on release machines.

**Keep as evidence.** The build-agent pool configuration showing which jobs each pool accepts.

<a id="item-2-4"></a>
## Item 2.4: Job-scoped credentials

**Why.** A credential stored on a build machine is stolen by whoever compromises it. In the [tj-actions compromise](https://www.stepsecurity.io/blog/harden-runner-detection-tj-actions-changed-files-action-is-compromised), secrets were printed to build logs that others could read; a credential that expires with its job is of little use once the job has ended.

**Do this.**

- Give signing and upload credentials only to the job that needs them, for that job only. On GitHub, store them as secrets of a protected environment that only the publish job uses; the [publish template](../../templates/github-actions/workflows/obaaf-publish.yml) does this.
- Where a service supports it, use short-lived credentials issued per job, such as OpenID Connect federation to a cloud account, instead of stored keys.
- On persistent machines, check that tools do not leave logins behind after a job (some upload tools cache a login on the machine), and clear them at the end of each job.
- Run `obaaf check`: rule `OBAAF-GHA-001` reports secrets in workflows that outsiders can start.

**Keep as evidence.** The credential configuration, and an inspection of build hosts showing no stored credentials.

<a id="item-3-3"></a>
## Item 3.3: Fresh environments where possible

**Why.** A fresh environment for each build limits how long an implant survives. This is Tier A isolation, which can meet SLSA Build Level 3.

**Do this.**

- For each release target, decide whether its toolchain can build in a fresh container or virtual machine. Targets whose toolchains run on Linux or Windows usually can ([GameCI images](https://game.ci/docs/docker/docker-images/), [GitHub-hosted runners](https://docs.github.com/en/actions/concepts/runners/github-hosted-runners)); Apple builds can on hosted macOS virtual machines; console builds often cannot.
- Build every target that can in a fresh environment. GitHub-hosted runners start each job on a new virtual machine, except single-CPU runners, which start each job in a new container; both are fresh environments.
- For self-hosted runners, registering a runner as ephemeral (`--ephemeral`) only makes it leave after one job. Your automation must also destroy that machine or container and start a new one from a clean image for the next job; otherwise the host is persistent, and its builds are Tier B.
- Declare the tier in the workflow (`OBAAF_TIER`), so the build record states it (FR4).
- Answer N/A only if none of your release targets can build in a fresh container or virtual machine.

**Keep as evidence.** The build-agent configuration for each target.

<a id="item-3-4"></a>
## Item 3.4: Reimaged persistent hosts

**Why.** Where a target needs a persistent machine, reimaging from a known image removes anything an attacker left behind. This is Tier B isolation; its builds are reported as below SLSA Build Level 3.

**Do this.**

- Build a versioned machine image for each persistent release host, and keep the image definition in version control.
- Reimage on a fixed schedule (for example weekly) and immediately after any suspected exposure.
- Keep the hosts dedicated to the release lane, with no interactive sessions and no stored credentials (items 2.1 and 2.4).
- Log each reimage: host, image version, date.
- Answer N/A only if you have no persistent build hosts for release builds.

**Keep as evidence.** The reimage log.

<a id="item-3-5"></a>
## Item 3.5: Egress allow-list for release hosts

**Why.** Limiting outbound traffic makes it harder for an implant to fetch tools or send data out, except through the destinations you allow, and makes unusual connections visible. It does not help when the destination is an allowed service, such as the code-hosting platform itself.

**Do this.**

- List the destinations release builds need: package mirrors, platform upload endpoints, and the provenance service (for GitHub Actions attestations, GitHub's and Sigstore's endpoints).
- Allow only those, through a firewall or an outbound proxy, on self-hosted release machines. On GitHub-hosted runners, which have no native allow-list, an egress monitor can enforce or report one.
- Test it: from a release host, try a connection to a destination that is not on the list, and confirm it fails.

**Keep as evidence.** The firewall or proxy rules, and the result of the test connection.
