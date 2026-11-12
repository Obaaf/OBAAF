# Egress control for agent jobs: design

*Design note for flagship slice 2c.1, written 2026-11-12. Nothing described here is built yet. **Nothing here was run**: the session that wrote it had no Docker daemon, so every statement about another tool comes from that tool's own pages, read on 2026-11-12 and listed under [Sources](#sources). Running it is the first task of slice 2c.2.*

## What is wanted

An action in this repository that runs one command with its network access limited to a declared list of hosts, blocks and logs everything else, and cannot be switched off by the command it confines. It has to work on GitHub-hosted Linux runners, where every step can use `sudo` without a password. OBAAF's own CI has to try to get out of it and fail.

The reason is rule OBAAF-GHA-020, "Agent job without an egress restriction". Today an adopter has no fix for it that OBAAF can check, and the one adopter has accepted it 19 times in a baseline.

## The decision

The action pins and wraps GitHub's Agent Workflow Firewall (AWF, `github/gh-aw-firewall`, MIT). OBAAF does not write a firewall. This is decision F-20 in the [flagship plan](flagship.md), confirmed by the maintainer on 2026-11-11.

Whether OBAAF needs a mechanism of its own instead depends on two things the plan names: whether AWF can be pinned and verified, and whether it holds against OBAAF's escape tests.

- **Pinned and verified: yes, by its documentation.** The setup action is used at a full commit; it takes a `version` input, and with `pull-images: true` it returns an `image-tag` output that carries a digest for each container image, to be passed to `awf --image-tag`. The images are signed with cosign (keyless, GitHub's OIDC issuer). The setup action says it checks the release's signed identity, its artifact attestations and its checksums before installing. Two weak points: the documented cosign identity is a pattern for the whole repository and not one workflow, and no command is documented for checking a release asset by hand.
- **Holds against escape tests: not known.** OBAAF has not run it. AWF's repository has no published security advisory ("There aren't any published security advisories", its security page). Its own automated reports say that a daily review on 2026-07-27 found no critical or high weakness and three medium ones, and that an escape test on 2026-08-04 blocked all 13 techniques it tried, 122 in all runs so far. Those reports are written by agents in GitHub's repositories and name no AWF version. They are a reason to start from AWF, not evidence that OBAAF's action works.

So nothing has failed, and nothing has been tried. Slice 2c.2 tries it. OBAAF designs its own mechanism only if a test in the "must block" list below fails on the pinned version and cannot be closed by how the wrapper calls AWF, or if the verification above cannot be made to work in CI.

## How AWF confines a command

From its security architecture page and command reference:

- `sudo awf --allow-domains a.example,b.example -- <command>` runs the command in a container on a Docker network of its own. A second container runs a Squid proxy. Rules in the agent container send ports 80 and 443 to Squid, which allows a request by the host name in the TLS handshake or the `Host` header, and answers 403 otherwise. Every other protocol is dropped, not filtered. Rules in the host's `DOCKER-USER` chain drop whatever else leaves that network.
- DNS goes only to the configured resolvers, by default 8.8.8.8 and 8.8.4.4.
- The command runs as the calling user, not root, inside a `chroot` of the host's filesystem: system paths read-only, the home directory and `/tmp` writable.
- A name on the list allows its subdomains. With no list, nothing is allowed.

**How the command is kept from undoing it.** The rules that matter are in two places the command cannot write. The container's own rules need `CAP_NET_ADMIN`, which AWF's page says is dropped before the command starts; its review says the agent container never has it, that `NET_RAW` and `SYS_ADMIN` are dropped too, and its escape report found `no-new-privs=1` inside, which stops `sudo` from gaining anything. The host's rules need root on the host, and the command is not on the host: the Docker socket is hidden from it. AWF's page does not say in so many words that `sudo` fails inside the sandbox, so that is the first escape test.

AWF itself needs `sudo` on the runner to set this up. That is not a weakness in the confinement: the step that starts AWF is written by the workflow's author, and the command inside cannot reach it.

## What AWF does not do, in its own words

These go into OBAAF's documentation as they are. None may be described as blocked.

- **Data can go wherever the list allows.** "If it can reach an allowed destination, it can send that data there." Allowing `github.com` allows every account and repository on it. Without TLS inspection the proxy sees only the host name, so a request to an allowed name on a shared address can carry a different `Host` inside.
- **DNS can carry data out.** Tunnelling through the allowed resolvers "is still theoretically possible, as the trusted DNS server will recursively resolve any domain". A model key is under a hundred bytes. So this control does not make it safe to give an agent a secret, and it does not clear OBAAF-GHA-005 by itself; that rule is slice 2a.2.
- **The filesystem is not confined.** "Filesystem access is unrestricted." The command can read `.ssh` and `.aws` under the home directory and whatever environment it is given.
- **It is not a boundary against the runner.** "Not a security boundary against runner-host compromise." A root process on the host that removes the `DOCKER-USER` rules opens it.
- **IPv6** is turned off in the container by a setting whose failure is only a warning (AWF's own review, medium).
- **`--enable-dind`** lets the command "bypass all firewall restrictions". `--env-all` "May expose sensitive credentials". `--ssl-bump` changes the security model.

## What OBAAF's action adds

The wrapper exists so that the confinement is the same every time and can be checked from the workflow file.

1. **Everything pinned.** The action carries one AWF version, the setup action's commit and the image digests, all tested together by OBAAF's CI. The adopter pins OBAAF's action by commit and gets those. Nothing is fetched as `latest`. AWF moves fast (release pages found by a search on 2026-11-12 go up to 0.28.71, and its README says releases 0.25.21 to 0.25.39 were withdrawn), so a scheduled job proposes each new version and the escape tests decide.
2. **No weakening flags.** The action has no input that reaches `--enable-dind`, `--ssl-bump`, `--env-all` or `--dns-servers`. The allow-list takes plain host names; an entry with `*` is refused (AWF accepts `*.com`).
3. **Named environment only.** The adopter lists the variables the command gets. Nothing else is passed.
4. **A check from inside, before the command.** The action runs, inside the same sandbox and immediately before the adopter's command, a probe that must fail to reach a host that is not on the list, must find IPv6 off, and must find `sudo` useless. If the probe gets out, the step fails and the command never starts. This turns AWF's warning-only cases into errors. The probe also tells a firewall that did not start from a command that failed, which AWF's exit code does not.
5. **What the command leaves behind.** The confinement ends when the command ends. The command can write the workspace, the home directory and `/tmp`, and on a hosted runner the files the runner reads after a step (`GITHUB_ENV`, `GITHUB_PATH`, `GITHUB_OUTPUT`) are under the home directory, so by AWF's description the command can write them; an escape test checks. Anything a later step executes or trusts from there runs with the full network. The action restores those runner files to what they were, and fails if the command changed them. It cannot do the same for the workspace, because the workspace is the agent's output. So the rule for the job is: after the confined step, nothing in the same job executes what the agent wrote. The output leaves as an artifact and another job treats it as data. That is the effect lane OBAAF already describes.
6. **A record.** The action collects AWF's proxy and firewall logs, lists the blocked hosts in the job summary and uploads the logs.

**What it covers and what it does not.** It confines a command. An agent started as a command (`claude -p …`, `python -m agents.review`) can be wrapped; the adopter's 19 agent jobs all start their agent from a `run` step, 17 of them from the project's own code ([flagship plan](flagship.md), slice 1.3). An agent that is itself an action (`uses: anthropics/claude-code-action`) is a separate step and cannot be wrapped by this; for those the answer is a control that covers the whole job, below.

## The escape tests (for slice 2c.2)

A job in OBAAF's CI runs each attempt inside the action. **The judge is outside the sandbox**: a packet capture on the runner decides whether anything left for a host that is not allowed. The confined command's own exit code is not evidence.

Must block, or the action does not ship as enforcement:

- a host that is not on the list, over HTTPS and over HTTP
- a direct connection to an IP address, on 443 and on another port
- another DNS resolver over UDP and over TCP, and DNS over HTTPS to a resolver that is not on the list
- IPv6
- `sudo`, and through it the firewall rules, the Docker socket and a new container (the route by which Harden-Runner's `disable-sudo` and Bullfrog were undone)
- a child process, a background process that outlives the command, and proxy variables such as `NO_PROXY=*`
- UDP sent with `sendto` and `sendmsg` (it escaped Harden-Runner's log), and a second DNS query in one TCP segment (it escaped Bullfrog)
- a TLS handshake with no server name
- a write to `GITHUB_ENV` or `GITHUB_PATH` taking effect in the next step

Must still work: a host on the list, and the command's exit code and output.

Recorded, not asserted, because AWF says it does not stop them: a `Host` header that differs from the allowed server name; data in DNS queries to the allowed resolvers. The test records what happened, and the documentation says it.

If full enforcement turns out not to be achievable on hosted runners, the documentation says exactly what is and is not blocked, and nothing is shipped that looks like enforcement and is not.

## Where another tool is the better choice

- **GitHub's native egress firewall** (`runs-on: ubuntu-24.04-firewall`, technical preview). It sits outside the runner's virtual machine, so nothing in the job can touch it, and it covers every step. Where a repository can use it, use it and not this action.
- **GitHub Agentic Workflows** for a new agent workflow (decision F-21, still the maintainer's to confirm). It uses AWF itself and adds a proxy that keeps the model key from the agent.
- **Harden-Runner** when the whole job is to be limited, including agents that are actions. It needs version 2.16.0 or later with `sudo` and containers removed, and its free tier does not cover private repositories ([landscape](landscape.md), part 2).
- **Cimon** (Cycode) also covers the whole job, with an eBPF sensor. Its action is Apache-2.0 and downloads a binary whose source the pages read do not show; it says it usually ignores traffic between containers and the 10.0.0.0/8 and 172.16.0.0/12 networks; whether a root process can turn it off is not stated.
- **Self-hosted runners behind a network policy.** The boundary is outside the machine. AWF's own page recommends this for self-hosted runners.

## For the checker (slice 2c.3)

OBAAF-GHA-020 clears for this action only when all of these can be read from the workflow: the action is pinned to a commit OBAAF lists as released; the agent command is inside the action's `run` input, and no agent runs in another step of the job; and every later step in the job is on a short list that executes nothing from the workspace. Where any of it cannot be read, the result is "cannot tell", not a pass.

## Not done

- Nothing was run. The default mode, the behaviour of `sudo` inside the sandbox, IPv6 and DNS are all from AWF's pages.
- The source of Harden-Runner's agent and of Cimon's sensor was not read; only their pages and Cimon's `action.yml`.
- Whether this repository can use the native firewall's runner label was not tried.
- AWF's README says its key proxy is always on, and its command reference lists it as a flag that is off by default. Which is true decides part of slice 2a.2 and was not established.

## Sources

All read on 2026-11-12.

- AWF security architecture: <https://github.github.io/gh-aw-firewall/reference/security-architecture/>
- AWF command reference: <https://github.github.io/gh-aw-firewall/reference/cli-reference/>
- AWF README and documentation home: <https://github.com/github/gh-aw-firewall>, <https://github.github.io/gh-aw-firewall>
- AWF in GitHub Actions, image verification, compatibility: <https://github.com/github/gh-aw-firewall/blob/main/docs/github_actions.md>, <https://github.com/github/gh-aw-firewall/blob/main/docs/image-verification.md>, <https://github.com/github/gh-aw-firewall/blob/main/docs/compatibility.md>
- AWF security page (policy and advisories): <https://github.com/github/gh-aw-firewall/security>
- AWF daily security review, 2026-07-27: <https://github.com/github/gh-aw-firewall/discussions/6624>
- Firewall escape test report, 2026-08-04: <https://github.com/github/gh-aw/discussions/50187>
- Dependency findings in AWF's container images, not weaknesses in the firewall: <https://github.com/github/gh-aw/issues/49920>, <https://github.com/github/gh-aw/pull/49766>
- Cimon: <https://cycode.com/blog/introducing-cimon-build-hardening/>, <https://github.com/marketplace/actions/cimon-by-cycode>, <https://github.com/CycodeLabs/cimon-action>
- Harden-Runner and Bullfrog advisories, and GitHub's native firewall: [landscape](landscape.md), part 2.
