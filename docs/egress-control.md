# Egress control for agent jobs

*Built in flagship slice 2c.2 (2026-11-13) as the action [`actions/egress`](../actions/egress/action.yml). What this page says holds is what the escape tests in [`.github/workflows/egress-escape-tests.yml`](../.github/workflows/egress-escape-tests.yml) showed on GitHub-hosted `ubuntu-24.04` runners, in the runs it links. Statements about the Agent Workflow Firewall's internals come from its source at v0.29.13 (commit `62b7e8f`) or its pages, and say which. Slice 2c.1 wrote the design on 2026-11-12 without running anything; where running it settled a question, the answer is under [What running it settled](#what-running-it-settled).*

## In short

`actions/egress` runs one command with its network limited to a list of host names. Everything else the command tries is refused, and the refused names are listed in the job summary. It runs the command under GitHub's Agent Workflow Firewall (AWF, `github/gh-aw-firewall`, MIT), pinned by OBAAF, in AWF's default mode: the command's container sits on a Docker network with no route out, and a Squid proxy that allows only the listed names is its one way out. The command runs with no privileges (`sudo` refuses), sees none of the runner's environment except variables the workflow names, and can write only to a scratch copy of the workspace, its own home and its own `TMPDIR`, which the action deletes or hands back as output. The runner's own workspace, home directory, `/tmp` and file-command files are out of its reach.

On a hosted runner, OBAAF's CI tried 22 ways out from inside it. Each was first tried outside the sandbox, where all but the two IPv6 ones got out; inside, a packet capture on the runner's external interface saw none of them leave, and a request to the listed host worked. The two IPv6 attempts could not be tested, because the runner itself had no IPv6 route.

It does not make an agent safe to hold a secret. Anything it can send to a listed host it can send there; **a name it asks the proxy for leaves the runner in a DNS query even when the proxy refuses it**, which is a channel for data (shown in the tests, below); and it confines one command, not the job. Read [What it blocks, and what it does not](#what-it-blocks-and-what-it-does-not) before relying on it.

## Using it

```yaml
jobs:
  review:
    runs-on: ubuntu-24.04
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@<commit> # pin it
        with:
          persist-credentials: false   # the action refuses a workspace whose .git/config holds a token
      - id: agent
        uses: Obaaf/OBAAF/actions/egress@<commit> # pin it to a commit
        env:
          REVIEW_TARGET: ${{ github.event.pull_request.number }}
        with:
          allow: api.github.com          # the host names your command needs
          env: REVIEW_TARGET
          run: ./scripts/run-agent.sh
      - uses: actions/upload-artifact@<commit>
        with:
          name: agent-output
          path: ${{ steps.agent.outputs.workspace }}
```

- **`allow`** (required): host names, separated by commas, spaces or new lines. A name covers its subdomains, so `github.com` allows every account and repository on GitHub. Plain names only: an entry with `*`, an address, a port, a scheme, a path, a trailing dot or a single label is refused before anything runs.
- **`run`** (required): the command, run with `bash -e` in a copy of the workspace.
- **`env`**: names of variables from the step's `env` to pass in. Nothing else of the runner's environment reaches the command, `GITHUB_TOKEN` and `ACTIONS_RUNTIME_TOKEN` included. Refused: variables that change how a shell, a loader or the network behaves (`PATH`, `HOME`, `LD_PRELOAD`, `BASH_ENV`, the proxy variables, `GIT_SSH_COMMAND` and others); the runner's file-command variables; names AWF reads as its own configuration (starting `AWF_`, `OTEL_` or `FOUNDRY_`, ending `_API_TARGET`, `_API_BASE_PATH`, `_BASE_URL` or `_ENDPOINT_OVERRIDE`; an OpenTelemetry endpoint, for one, would be added to the proxy's allow-list); names starting `ACTIONS_`, `SQUID_` or `OBAAF_EGRESS_`; and **model keys and GitHub tokens** (below). The list follows AWF v0.29.13's names by pattern. AWF reads a few more names from the same file that choose how its API proxy talks to a provider rather than what the proxy allows (`COPILOT_PROVIDER_TYPE`, `COPILOT_MODEL`, `GOOGLE_GENAI_USE_VERTEXAI` and others); those are passed.
- **Model keys do not work yet.** AWF withholds variables such as `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `GEMINI_API_KEY` and `GITHUB_TOKEN` from the command and gives model keys to its own API proxy instead, which the agent is meant to call (AWF v0.29.13, `src/services/agent-environment/excluded-vars.ts`). The action does not set that up, because OBAAF has not tested it, so it refuses these names rather than let them vanish. An agent that reads one of them cannot run under this action today; plan slice 2c.4 is to test AWF's API proxy and support it, or say why not. A key under a name AWF does not know is passed to the command like any other variable, and the command can then send it to any listed host and out through DNS (below).
- **Outputs:** `workspace` (the copy the command ran in and could change), `scratch`, `log-dir` (the proxy's log, outside the scratch directory), `denied` (names the proxy refused), `exit-code`, and `confined`, which is `true` only when the step's status is the command's own. The step fails with the command's exit status. It fails with status 3, and the command does not run, if the probe described below gets out, if the sandbox does not start, or if the runner's file-command files changed.
- **Treat what the command wrote as data.** Upload it, diff it, read it; do not run or load anything from `steps.<id>.outputs.workspace` or `scratch` in a later step of the same job, because later steps have the full network. That includes running `git` in the copy: the command can write its `.git/config` and `.git/hooks`. The checker reads this (below).

Linux x64 runners with Docker only. It downloads AWF's binary from GitHub's release page and its images from `ghcr.io`, so those must be reachable from the runner. A run takes about 40 seconds longer than the command, most of it pulling the images.

**Not tried:** an agent that is itself an action (it cannot be wrapped; see below), a model key or model call (refused, above), self-hosted or larger runners, `ubuntu-22.04`, a repository larger than OBAAF's.

## What it blocks, and what it does not

Each "blocked" line is an attempt in the escape tests that got out when made outside the sandbox and was not seen leaving the runner when made inside it, judged from a packet capture on the runner's external interface (the interface of its IPv4 default route, through which Docker's traffic also leaves; the job logs the runner's routes, and IPv6 had no route at all). The confined command's own exit statuses are recorded and decide nothing. The runs: [43432030855](https://github.com/Obaaf/OBAAF/actions/runs/43432030855) (commit `4a25d1b`) and [43431555704](https://github.com/Obaaf/OBAAF/actions/runs/43431555704) (`06ea5bb`), both with every check described here, including the cleanup and the `confined` output; [43425789742](https://github.com/Obaaf/OBAAF/actions/runs/43425789742) (`2b02f3d`) and [43425073087](https://github.com/Obaaf/OBAAF/actions/runs/43425073087) (`9bb65cb`) gave the same verdicts on the attempts before those were added. The pull request that adds this page names the run on its last commit.

**Blocked (tested):**

| Attempt | How |
| --- | --- |
| An unlisted host over HTTPS and over HTTP | `curl https://example.org`, `curl http://example.net`, through the proxy the sandbox sets |
| The same, ignoring the proxy | `NO_PROXY='*'`, `curl --noproxy '*'` |
| A proxy of one's own | `HTTPS_PROXY=http://208.67.220.123:443` |
| A direct address, through the proxy and not | `https://1.1.1.1`, `https://1.0.0.1`, a TCP connection to 208.67.220.220:8443 |
| Another DNS resolver, over UDP and over TCP | `dig @9.9.9.9`, `dig +tcp @149.112.112.112` |
| DNS over HTTPS, by name and by address | `https://cloudflare-dns.com/dns-query`, `https://1.1.1.3/dns-query` |
| Two DNS queries in one TCP segment | to 149.112.112.10:53 |
| Raw socket calls | UDP `sendto` and `sendmsg` to 1.1.1.2 and 1.0.0.2 |
| A TLS handshake with no server name | `openssl s_client -noservername -connect 149.112.112.11:443` |
| A child process | Python started from bash, connecting to 9.9.9.11 |
| A process that outlives the command | started with `setsid nohup`, firing 20 seconds later; the capture ran 35 seconds after the step. Nothing left: AWF removes the container when the command ends, which ends the process with it, so this shows the process does not survive, not that the proxy refused it |
| `sudo`, then a connection; `sudo` to flush the firewall rules, then a connection | `sudo` refuses: the "no new privileges" flag is set |
| The Docker socket | AWF binds `/dev/null` over `/var/run/docker.sock` and `/run/docker.sock`; `docker run --network host` fails |
| Changing what later steps see | writing `~/.local/bin/git`, `~/.config/git/config`, `~/.gitconfig`, `/tmp`, `RUNNER_TEMP`, the real workspace and its `.git/hooks`, and the runner's file-command files all failed (the places are absent or read-only inside); `::set-env` and `::add-path` printed by the command did not take effect, with `ACTIONS_ALLOW_UNSECURE_COMMANDS` set so that they would have without the action |

**Not testable on a hosted runner:** IPv6. The runner had no IPv6 route out, so the same attempts outside the sandbox did not get out either (a direct connection to `[2606:4700:4700::1111]:443`, `dig -6 @2620:fe::fe`). Inside, the container has an IPv6 address only on its loopback interface and no IPv6 route. That is evidence, not a test; on a runner with IPv6 it would need testing.

**Not blocked, by design or by limit:**

- **Anything sent to a listed host.** "If it can reach an allowed destination, it can send that data there" (AWF's documentation). A listed name covers its subdomains. Allowing `github.com` allows uploading to any repository on it.
- **A different `Host` behind an allowed name.** Recorded, not asserted: a request to `https://api.github.com/` with `Host: example.org` reached GitHub's server, which answered 400. The proxy sees only the name in the TLS handshake. A server that routes by `Host` (a shared CDN front) would route it.
- **Data in a host name, through the proxy.** Recorded, not asserted, and it got out: when the command asked the proxy for `https://<label>-proxy.example.com/`, the proxy refused the request, but a DNS query for that name left the runner. So did queries for the other unlisted names asked of the proxy over HTTPS (`example.org`, `example.com`, `cloudflare-dns.com`). A confined command can therefore send data out by asking for names under a domain whose DNS server it controls, a few dozen bytes a name, as many names as it likes. A model key fits in one or two. The likely cause, from AWF's source and not tested on its own: AWF's Squid configuration has an access rule of type `dst` for the API proxy's address (`src/squid/config-sections.ts`), and Squid resolves a requested name to evaluate such a rule before it reaches the rule that refuses unlisted names. The command's own resolver (Docker's, at 127.0.0.11) did not send the names the command looked up itself off the runner. AWF's documentation says DNS tunnelling "is still theoretically possible"; here it is shown through the proxy. Plan slice 2c.4 is to close it or say why it cannot be closed.
- **What the command does with what it can read.** It can read the copy of the workspace, the system directories (read-only) and the variables it was given. Give it no secret it does not need. This control does not clear OBAAF-GHA-005.
- **Other steps of the job.** It confines one command. Every other step, and every post step, runs with the full network.
- **The runner itself.** AWF's container is "not a security boundary against runner-host compromise" (AWF's documentation). A kernel exploit from inside is out of scope.

**AWF's API proxy is untested here.** AWF always starts a sidecar meant to hold model keys so that the agent never sees them, and the command can reach it at the addresses in `AWF_API_PROXY_*_URL` (the escape test's facts show those variables). The action starts AWF with no key in its environment, so the sidecar has no provider to forward to; by AWF's source, a sidecar given a key would reach that provider's host whether or not it is in `allow`, through a proxy rule of its own. Not run.

## What running it settled

Slice 2c.1 left five questions for this slice. The answers come from the escape tests' facts, which the attempts script records from inside the sandbox, and from AWF's source at v0.29.13.

1. **Which mode runs by default: network isolation, with no `sudo`.** In v0.29.13 the default ("strict security") forces `--network-isolation` and the API proxy on, and turns `--enable-dind`, `--dns-over-https` and host access off with a warning (`src/commands/validators/security-mode.ts`). The run log shows the networks `awf-net` and `…_awf-ext`; inside, the only route is `172.30.0.0/24`. `awf` ran as the runner user, without `sudo`. The documentation site's description (`sudo awf` and host firewall rules) is the `--legacy-security` mode, which the action never passes.
2. **Whether `sudo` does anything inside: no.** `NoNewPrivs` is 1 and the effective capability set is empty; `sudo -n -l` answers that the "no new privileges" flag prevents it from running as root.
3. **Where the command can write.** With AWF's defaults: the workspace, the host's `/tmp`, and the tool directories under the home directory (`.cache`, `.config`, `.local/bin` and others; `src/config/sandbox-mount-policy.json`), all read-write. That is enough to plant a program for a later step. The action narrows it: it points AWF at a home directory under one scratch directory in `/tmp`, runs the command in a copy of the workspace there, and gives AWF its own option `filesystem.allowWrite` with only that directory, which makes every other host mount read-only. Inside, writable: the scratch directory (the copy, `TMPDIR`, and the home and its tool directories); `/dev/shm`, AWF's `/tmp/gh-aw/…` paths and AWF's working directory, which are `tmpfs` in the container and never reach the runner's disk; and two kinds of place that do reach the runner's disk: the top of the command's home, which AWF backs with a directory it creates beside its working directory (`work-chroot-home`), and AWF's log and session directories, mounted at `$HOME/.copilot/logs` and `$HOME/.copilot/session-state`, which AWF itself moves into its temporary directory when it cleans up (`src/artifact-preservation.ts`; with the runner's defaults that is the host's `/tmp`, where they would stay). The action gives AWF a temporary directory inside `RUNNER_TEMP/obaaf-egress/<run>/`, deletes everything there but the proxy's log after the run (with `sudo` where AWF made a directory as root, which the command cannot use), and fails the step if it cannot. The behaviour job checks that files written to the home and to both AWF directories are found nowhere under `RUNNER_TEMP` or `/tmp`. Read-only or absent inside: `/tmp` outside the scratch directory, `/home/runner`, the rest of `RUNNER_TEMP`, the runner's file-command files, the real workspace, `/usr/local/bin`, `/opt`.
4. **IPv6 and DNS for an unlisted name.** No IPv6 route inside. DNS goes to Docker's resolver at 127.0.0.11; names the command looked up itself were not seen leaving the runner. Names it asked the proxy for over HTTPS were: see "Data in a host name, through the proxy" above.
5. **Can the action keep what the command wrote away from later steps and post steps?** Yes, as far as the tests reach: the places a later step or post step would run or load (the files listed under "Changing what later steps see") did not change, AWF's directories under `RUNNER_TEMP` are deleted, and what is in the scratch directory is reached through the action's outputs. The condition the action cannot enforce is the workflow's: a later step that runs or loads something from the output runs it with the full network. Since slice 2c.3 the checker does not credit the control in that case.

Two findings about AWF on the way, neither a weakness in the confinement: with the host's `/tmp` read-only, Docker could not create the mount points for AWF's hidden `/tmp/gh-aw/…` directories, so the action creates them first; and after the run AWF tries to repair file ownership with the image's tag rather than its digest, which fails with a warning when the image was pulled by digest.

## What the action adds to AWF

1. **Everything pinned.** AWF's binary by SHA-256 and each of its nine images by digest, read from the release's `checksums.txt` and `containers.txt`, which its `release-identity.txt` binds to the tag. A new AWF version is a change to `egress.py` and must pass the escape tests. The action does not check AWF's signatures or attestations at run time; the SHA-256 is the check.
2. **A fixed command line.** No input reaches an AWF option. `--enable-dind`, `--env-all`, `--legacy-security`, `--enable-host-access`, `--ssl-bump` and `--upstream-proxy` are never passed, and AWF runs with only `PATH`, `HOME` and `LANG` in its environment, so it finds no proxy to chain through and no token to pass on.
3. **A plain allow-list.** As above.
4. **Writes narrowed** to the scratch directory, and AWF's own writable directories deleted after the run, as above.
5. **A probe before the command.** Inside the same sandbox, immediately before the command, it tries a direct address, a direct IPv6 address, an unlisted host with and without the proxy, `sudo` and the Docker socket. If any succeeds, the command does not run and the step fails with status 3.
6. **Workflow commands stopped** while the command's output is printed, with a token the command cannot know, and the step fails if `GITHUB_ENV`, `GITHUB_PATH`, `GITHUB_OUTPUT`, `GITHUB_STATE` or `GITHUB_STEP_SUMMARY` changed while it ran.
7. **A record.** Names the proxy refused go in the job summary and the `denied` output; the proxy's log stays in `log-dir`.

## How others do it, and where they are the better choice

**GitHub Agentic Workflows (gh-aw)** runs its agents inside AWF too, so the confinement is the same mechanism. The difference is the rest: gh-aw is a whole way of writing agent workflows (its compiler generates the job, an MCP gateway gives the agent its tools, and the agent's changes come out as "safe outputs" that a later job applies), while this action wraps a `run` command in a workflow that already exists. **For a new agent workflow, gh-aw is the better choice** (decision F-21, confirmed by the maintainer on 2026-11-12). This action is for the jobs that exist already, like the first adopter's 19, which start their agents from their own code.

**Harden-Runner** works differently. Its community agent for Linux (`step-security/agent`, read at commit `1ff3fa6`, 2026-11-03) runs on the runner's own virtual machine and covers every step of the job: it points the runner's DNS at a proxy of its own that answers only for allowed names, adds an `iptables` rule accepting each address an allowed name resolved to, in the `OUTPUT` chain and in `DOCKER-USER`, rejects and logs the rest, and with `disable-sudo` or `disable-sudo-and-containers` removes `/etc/sudoers.d/runner` and Docker's sockets. So it filters by address, after a name was resolved, where AWF filters by name at a proxy. **Harden-Runner is the better choice when the whole job must be covered**, including agents that are actions and post steps; it needs v2.16.0 or later with `sudo` and containers removed, or a step with `sudo` can undo it, and its free tier covers public repositories only ([landscape](landscape.md), part 2). Its source was read; it was not run here.

**GitHub's native egress firewall** (`runs-on: ubuntu-24.04-firewall`, technical preview) sits outside the runner's virtual machine, so nothing in the job can touch it, and it covers every step and post step. **Where a repository can use it, use it and not this action.** Not tried here.

**Cimon** (Cycode) also covers the whole job, with an eBPF sensor whose source the pages read do not show. **Self-hosted runners behind a network policy** put the boundary outside the machine, which AWF's own page recommends for self-hosted runners.

## What the checker credits (slice 2c.3)

`obaaf check` reads this action in an agent job and reports what it established under OBAAF-GHA-020; the full list is in [the checker's guide](checker-configuration.md#egress-controls). In short, the finding is cleared only when, for every step that uses the action:

- the action is used from a commit OBAAF lists as released. **None is listed yet**, so today the best the action gets is "cannot tell". A maintainer lists a commit once the escape tests have passed on it (`egress_action_releases` in `src/obaaf/data/detection.yaml`);
- the allow-list is written out, with no expression, and has no name on the public suffix list, private section included (names under which anyone can register a host, such as `github.io` or `workers.dev`), which OBAAF ships as `src/obaaf/data/public_suffix_list.dat`;
- the job runs on GitHub-hosted `ubuntu-24.04`, not in a container;
- the agent is the action's command. The checker recognises few agents by name, so a job could wrap `true` and run its agent in an ordinary step; it reads where the agent runs from where credentials go. No other step, and no `env` of the job or the workflow, may be given a secret or `github.token`, and no other step may run an agent the checker recognises. A job that gives no step a credential at all is "cannot tell", unless the checker recognises the agent in the action's `run` input or a script it runs: an agent that needs no key could be anywhere. A credential given to the action's own step is "cannot tell" too, because of the DNS channel above (slice 2c.4);
- no step that can run after or beside it reads its `workspace` or `scratch` output or the scratch directory under `/tmp`, except `actions/upload-artifact` with it as the `path`. A cache is "not met"; anything else, `git` in the copy included, is "cannot tell", because the checker cannot tell reading from running.

Beside a cleared finding the report says what the action does not stop: anything sent to a listed host, and data in a host name asked of the proxy, which leaves the runner in a DNS query until slice 2c.4 closes it.

## Not done

- The proxy's DNS channel is open, and model keys are refused because AWF's API proxy is untested (above); slice 2c.4.
- IPv6 was not testable on the runners used.
- No real model key or model call went through the sandbox, so AWF's API proxy is untested.
- Only `ubuntu-24.04` hosted runners. Not tried: `ubuntu-22.04`, larger runners, self-hosted runners, ARC.
- An agent that is itself an action cannot be wrapped.
- The source of Cimon's sensor was not read; Harden-Runner and GitHub's native firewall were not run.

## Sources

Read on 2026-11-13 unless marked.

- AWF v0.29.13 source, commit `62b7e8ff1884aa476185369fa6be85585029f4c9`: `action.yml`, `README.md`, `docs/sandbox-design.md`, `docs/network-isolation-design.md`, `docs/mount-policy.md`, `docs/awf-config-spec.md` (section 4.1), `src/commands/validators/security-mode.ts`, `src/cli-options.ts`, `src/config/sandbox-mount-policy.json`, `src/services/agent-volumes/workspace-mounts.ts`, `src/services/agent-volumes/filesystem-write-policy.ts`, `src/services/agent-volumes/docker-socket.ts`, `src/services/agent-service.ts`, `src/sensitive-paths.ts`, `src/host-identity.ts`, `src/squid/config-generator.ts` (log format).
- AWF v0.29.13 release files: `checksums.txt`, `containers.txt`, `release-identity.txt`, at `https://github.com/github/gh-aw-firewall/releases/download/v0.29.13/`.
- Harden-Runner's community agent, `https://github.com/step-security/agent`, commit `1ff3fa6`: `firewall.go`, `dnsproxy.go`, `sudo.go`.
- From slice 2c.1, read on 2026-11-12: AWF's security architecture page and command reference (<https://github.github.io/gh-aw-firewall/>), its security page, its daily review of 2026-07-27 (<https://github.com/github/gh-aw-firewall/discussions/6624>), the escape test report of 2026-08-04 (<https://github.com/github/gh-aw/discussions/50187>), Cimon's pages, and the Harden-Runner, Bullfrog and native-firewall material in [landscape](landscape.md), part 2.
