# Egress control for agent jobs: design

*Design note for flagship slice 2c.1, written 2026-11-12. Nothing described here is built yet. **Nothing here was run**: the session that wrote it had no Docker daemon, so every statement about another tool comes from that tool's own pages, read on 2026-11-12 and listed under [Sources](#sources). Where those pages disagree with each other the note says so and does not pick one. Running it is the first task of slice 2c.2.*

## What is wanted

An action in this repository that runs one command with its network access limited to a declared list of hosts, blocks and logs everything else, and cannot be switched off by the command it confines. It has to work on GitHub-hosted Linux runners, where every step can use `sudo` without a password. OBAAF's own CI has to try to get out of it and fail.

The reason is rule OBAAF-GHA-020, "Agent job without an egress restriction". Today an adopter has no fix for it that OBAAF can check, and the one adopter has accepted it 19 times in a baseline.

## The decision

The action pins and wraps GitHub's Agent Workflow Firewall (AWF, `github/gh-aw-firewall`, MIT). OBAAF does not write a firewall. This is decision F-20 in the [flagship plan](flagship.md), confirmed by the maintainer on 2026-11-11.

Whether OBAAF needs a mechanism of its own instead depends on two things the plan names: whether AWF can be pinned and verified, and whether it holds against OBAAF's escape tests.

- **Pinned and verified: yes, by its documentation.** The setup action is used at a full commit; it takes a `version` input, and its `image-tag` output can carry a digest for each container image, to be passed to `awf --image-tag`. The images are signed with cosign (keyless, GitHub's OIDC issuer). The setup action says it checks the release's signed identity, its artifact attestations and its checksums before installing. Two weak points: the documented cosign identity is a pattern for the whole repository and not one workflow, and the only check of a release asset documented for doing by hand is a checksum file, which is not a signature.
- **Holds against escape tests: not known.** OBAAF has not run it. AWF's repository has no published security advisory ("There aren't any published security advisories", its security page). Its own automated reports say that a daily review on 2026-07-27 found no critical or high weakness and three medium ones, and that an escape test on 2026-08-04 blocked all 13 techniques it tried, 122 in all runs so far. Those reports are written by agents in GitHub's repositories and name no AWF version. They are a reason to start from AWF, not evidence that OBAAF's action works.

So nothing has failed, and nothing has been tried. Slice 2c.2 tries it. OBAAF designs its own mechanism, or recommends a control that covers the whole job instead, in three cases: a test in the "must block" list below fails on the pinned version and cannot be closed by how the wrapper calls AWF; the verification above cannot be made to work in CI; or the open question under [What the command leaves behind](#what-the-command-leaves-behind) has no answer.

## How AWF confines a command

**AWF's pages disagree about how it works by default, and which is true of the version OBAAF pins is not known.**

- The documentation site (security architecture, command reference) describes `sudo awf` with firewall rules, as set out below.
- The notes for release v0.28.71 call that mode `--legacy-security` and give the default as "strict security (network-isolation + api-proxy)", a mode that "Requires no sudo/NET_ADMIN". The pages read do not say how that mode keeps the command in.

The two keep a command in by different means, so slice 2c.2 settles this before anything else. What follows is the mode the documentation site describes.

- `sudo awf --allow-domains a.example,b.example -- <command>` runs the command in a container on a Docker network of its own. A second container runs a Squid proxy. Rules in the agent container send ports 80 and 443 to Squid, which allows a request by the host name in the TLS handshake or the `Host` header, and answers 403 otherwise. Every other protocol is dropped, not filtered. Rules in the host's `DOCKER-USER` chain drop whatever else leaves that network.
- DNS goes only to the configured resolvers. The command reference says these are found from the host's own resolvers, with 8.8.8.8 and 8.8.4.4 used if that fails; the security architecture page gives the two Google addresses as the default.
- The command runs as the calling user, not root, inside a `chroot` of the host's filesystem.
- A name on the list allows all its subdomains. With no list, nothing is allowed.

**How the command is kept from undoing it, in that mode.** The rules are in two places the command should not be able to change. The container's own rules need `CAP_NET_ADMIN`, which the security architecture page says is dropped before the command starts; AWF's review of 2026-07-27 says the agent container never has it, and that `NET_RAW` and `SYS_ADMIN` are dropped too. The host's rules need root on the host, and the page says the Docker socket is hidden from the command. About `sudo` no page says anything. The escape report says `no-new-privs=1` is set inside; if so, `sudo` should gain nothing. That is an inference, and it was not run. It is the first escape test.

In that mode AWF itself needs `sudo` on the runner to set the rules. That is not a weakness in the confinement: the step that starts AWF is written by the workflow's author.

## What AWF does not do

The quoted sentences are AWF's. They go into OBAAF's documentation as they are, and none may be described as blocked.

- **Data can go wherever the list allows.** "If it can reach an allowed destination, it can send that data there." Allowing `github.com` allows every account and repository on it.
- **DNS can carry data out.** Tunnelling through the allowed resolvers "is still theoretically possible, as the trusted DNS server will recursively resolve any domain". A model key is short enough to leave in a few DNS queries. So this control does not make it safe to give an agent a secret, and it does not clear OBAAF-GHA-005 by itself; that rule is slice 2a.2.
- **It is not a boundary against the runner.** The container, chroot and firewall rules are "not a security boundary against runner-host compromise". In the documented mode, a root process on the host that removes the `DOCKER-USER` rules opens it.
- **What the command can read and write is not clear.** The security architecture page says "Filesystem access is unrestricted", that the command can read `.ssh` and `.aws` under the home directory, and that the home directory and `/tmp` are writable. The command reference describes selective mounts, with only some directories under the home directory writable (it names `.cache`, `.config` and `.local`). The review of 2026-07-27 says credentials are hidden. Not run.
- **IPv6** is turned off in the container by a setting whose failure is only a warning (AWF's review, rated medium).
- **Some flags remove the protection.** `--enable-dind` lets the command "bypass all firewall restrictions". `--env-all` "May expose sensitive credentials". `--ssl-bump` changes the security model. The v0.28.71 notes add `--legacy-security`, `--enable-host-access` and `--upstream-proxy`, which is taken from the host's proxy variables when it is not set.

One more limit is our inference, not AWF's statement: without TLS inspection the proxy reads only the server name, so a request to an allowed name on a shared address may carry a different `Host` inside. Bullfrog was bypassed this way ([landscape](landscape.md), part 2).

## What OBAAF's action adds

The wrapper exists so that the confinement is the same every time and can be checked from the workflow file.

1. **Everything pinned.** The action carries one AWF version, the setup action's commit and the image digests, all tested together by OBAAF's CI. The adopter pins OBAAF's action by commit and gets those. Nothing is fetched as `latest`. AWF moves fast (release pages found by a search on 2026-11-12 go up to 0.28.71, and its README says releases 0.25.21 to 0.25.39 were retired), so a scheduled job proposes each new version and the escape tests decide.
2. **A fixed command line.** The action builds the whole `awf` command from a fixed list of options. It has no input that passes options through, so no input can reach a flag that removes the protection. Proxy variables from the host are cleared first.
3. **A literal allow-list.** Plain host names only. An entry with `*` is refused (AWF's review says `*.com` is accepted), and so is a single-label name. Because a name allows all its subdomains, a name under which anyone can register a host (`workers.dev`, `github.io`) allows everyone; the action's documentation says so, and the checker reports it (below).
4. **Named environment only.** The adopter lists the variables the command gets. What AWF passes by default was not established.
5. **A check from inside, before the command.** The action runs, inside the same sandbox and immediately before the adopter's command, a probe that must fail to reach a host that is not on the list, must find no IPv6 route out, and must find `sudo` useless. If the probe gets out, the step fails and the command never starts. This turns AWF's warning-only cases into errors. The probe also tells a firewall that did not start from a command that failed, which AWF's exit code does not.
6. **Output that cannot give orders.** The runner reads workflow commands from a step's output. The action prints the command's output with workflow commands stopped, and restores the runner's `GITHUB_ENV`, `GITHUB_PATH`, `GITHUB_OUTPUT` and `GITHUB_STATE` files to what they were, failing if the command changed them.
7. **A record.** The action collects AWF's logs, lists the blocked hosts in the job summary and uploads the logs.

### What the command leaves behind

This is the open question of the design, and it can sink it.

The confinement ends when the command ends. Whatever the command could write is still there for the rest of the job, and anything a later step executes or loads from such a place runs with the full network. The workspace is one such place; it is the agent's output. By AWF's pages, so are `/tmp` and at least some directories under the home directory. On a hosted runner, as far as we know without having run it, `~/.local/bin` is on the `PATH` ahead of the system directories and `git` reads `~/.config/git/config`, and actions used earlier in the job (`actions/checkout`, for one) run a post step after the last step. A program planted as `~/.local/bin/git` would then run, unconfined, in a post step that the workflow's author never sees.

So the rule for the job is: **after the confined step, nothing runs or loads anything from a place the command could write**, post steps included. Those places are the workspace, `/tmp`, the writable home directories and any directory on the `PATH`. The agent's output leaves as an artifact, and another job treats it as data. That is the effect lane OBAAF already describes.

Whether a job can be written to meet that rule is not known. It depends on which places the pinned AWF really lets the command write, and on whether the action can keep those writes away from the rest of the job (a scratch home directory for the command, or restoring the writable directories afterwards). Slice 2c.2 establishes both. If it cannot be done, a command wrapper is not enough on a hosted runner and OBAAF says so.

### What it covers and what it does not

It confines a command. An agent that is itself an action (`uses: anthropics/claude-code-action`) is a separate step and cannot be wrapped by this; for those the answer is a control that covers the whole job, below.

The adopter's 19 agent jobs all start their agent from a `run` step, 17 of them from the project's own code ([flagship plan](flagship.md), slice 1.3), so in principle they could be wrapped. That was not tried. A rough count by the reviewer of this note: 11 of the 19 have `run` steps after the step that holds the model key, which the rule above does not allow as they stand, and 10 already run their agent under bubblewrap.

## The escape tests (for slice 2c.2)

A job in OBAAF's CI runs each attempt inside the action.

- **The judge is outside the sandbox.** A packet capture on the runner decides whether anything left for a host that is not allowed. The confined command's own exit code is not evidence.
- **Every attempt has a control.** Each is first made outside the sandbox and must get out. If it does not (a hosted runner may have no IPv6 route at all), the attempt is reported as not testable here, never as blocked.

Must block, or the action does not ship as enforcement:

- a host that is not on the list, over HTTPS and over HTTP
- a direct connection to an IP address, on 443 and on another port
- another DNS resolver over UDP and over TCP, and DNS over HTTPS to a resolver that is not on the list
- IPv6
- `sudo`; the firewall rules; the Docker socket and a new container (Harden-Runner's `disable-sudo` was evaded through Docker, and Bullfrog's removal of `sudo` was undone through the `docker` group)
- a child process, a background process that outlives the command, and proxy variables such as `NO_PROXY=*`
- traffic sent with `sendto` and `sendmsg` (it escaped Harden-Runner's log), and a second DNS query in one TCP segment (it escaped Bullfrog)
- a TLS handshake with no server name
- anything left behind that takes effect later: a line in `GITHUB_ENV`, `GITHUB_PATH` or `GITHUB_OUTPUT`, a workflow command on the output, a program planted in `~/.local/bin`, a git configuration file

Must still work: a host on the list, and the command's exit code and output.

Recorded, not asserted: data in DNS queries to the allowed resolvers, which AWF says it does not stop; and a `Host` header that differs from the allowed server name, which we expect it does not stop. The test records what happened, and the documentation says it.

If full enforcement turns out not to be achievable on hosted runners, the documentation says exactly what is and is not blocked, and nothing is shipped that looks like enforcement and is not.

## Where another tool is the better choice

- **GitHub's native egress firewall** (`runs-on: ubuntu-24.04-firewall`, technical preview). It sits outside the runner's virtual machine, so nothing in the job can touch it, and it covers every step, which also answers the question of what a command leaves behind. Where a repository can use it, use it and not this action.
- **GitHub Agentic Workflows** for a new agent workflow (decision F-21, still the maintainer's to confirm). It runs the agent behind AWF, whose key proxy is meant to keep the model key from the agent. That proxy has not been tested here.
- **Harden-Runner** when the whole job is to be limited, including agents that are actions. It needs version 2.16.0 or later with `sudo` and containers removed, and its free tier does not cover private repositories ([landscape](landscape.md), part 2).
- **Cimon** (Cycode) also covers the whole job, with an eBPF sensor. Its action is Apache-2.0 and downloads a binary whose source the pages read do not show; it says it usually ignores traffic between containers and the 10.0.0.0/8 and 172.16.0.0/12 networks; whether a root process can turn it off is not stated.
- **Self-hosted runners behind a network policy.** The boundary is outside the machine. AWF's own page recommends this for self-hosted runners.

## For the checker (slice 2c.3)

OBAAF-GHA-020 clears for this action only when all of these can be read from the workflow:

- the action is pinned to a commit OBAAF lists as released;
- the agent command is inside the action's `run` input, and no agent runs in another step of the job;
- the allow-list is written out in the workflow (no expression), and has no single-label name and no name under which anyone can register a host; the report shows the list;
- nothing after the confined step, post steps included, runs or loads anything from a place the command could write. Until slice 2c.2 shows which places those are, this cannot be read, and the result is "cannot tell".

Where any of it cannot be read, the result is "cannot tell", not a pass.

## Not done

- Nothing was run. The default mode, the behaviour of `sudo` inside the sandbox, what the command can write, IPv6 and DNS are all from AWF's pages, which disagree in places.
- The source of Harden-Runner's agent and of Cimon's sensor was not read; only their pages and Cimon's `action.yml`.
- Whether this repository can use the native firewall's runner label was not tried.
- AWF's README says its key proxy is always on, the v0.28.71 notes put it in the default mode, and the command reference lists it as a flag that is off by default. Which is true decides part of slice 2a.2 and was not established.
- What a hosted runner puts on the `PATH`, and what its post steps run, is from memory and not from a run.

## Sources

All read on 2026-11-12. The pages were read through a tool that returns extracts, so each quotation above was checked a second time by an independent reviewer, through the same kind of tool.

- AWF security architecture: <https://github.github.io/gh-aw-firewall/reference/security-architecture/>
- AWF command reference: <https://github.github.io/gh-aw-firewall/reference/cli-reference/>
- AWF README and documentation home: <https://github.com/github/gh-aw-firewall>, <https://github.github.io/gh-aw-firewall>
- AWF in GitHub Actions, image verification, compatibility: <https://github.com/github/gh-aw-firewall/blob/main/docs/github_actions.md>, <https://github.com/github/gh-aw-firewall/blob/main/docs/image-verification.md>, <https://github.com/github/gh-aw-firewall/blob/main/docs/compatibility.md>
- AWF security page (policy and advisories): <https://github.com/github/gh-aw-firewall/security>
- Notes for AWF release v0.28.71, on a third-party page that copies GitHub's release notes: <https://newreleases.io/project/github/github/gh-aw-firewall/release/v0.28.71>
- AWF daily security review, 2026-07-27: <https://github.com/github/gh-aw-firewall/discussions/6624>
- Firewall escape test report, 2026-08-04: <https://github.com/github/gh-aw/discussions/50187>
- Dependency findings in AWF's container images, not weaknesses in the firewall: <https://github.com/github/gh-aw/issues/49920>, <https://github.com/github/gh-aw/pull/49766>
- Cimon: <https://cycode.com/blog/introducing-cimon-build-hardening/>, <https://github.com/marketplace/actions/cimon-by-cycode>, <https://github.com/CycodeLabs/cimon-action>
- Harden-Runner and Bullfrog advisories, and GitHub's native firewall: [landscape](landscape.md), part 2.
