# The inference proxy

The agent lane gives the agent no secrets (R2, FR7), so it cannot hold the credential for the model API. Paper 1's design puts that credential in an **inference proxy** outside the agent's reach (R3), and limits the agent's network egress to the proxy (R7). This page specifies the proxy's contract. OBAAF does not include a proxy. A reference implementation was planned for version 0.2 and has not been built (DECISIONS.md, D-020); the [flagship plan](flagship.md) first tests the proxies that other tools ship (slice 2a.2). Until one exists, the agent template runs a stub agent that calls no model.

## What the proxy does

1. **Holds the model credential.** The proxy calls the model provider with its own key. The key never enters a CI job.
2. **Identifies the run.** The agent job presents its own job token (`OBAAF_JOB_TOKEN` in the template). The token is read-only, scoped to one repository, and expires when the job ends. The proxy accepts a request only if the token is a job token for a repository on its allow-list, for example by listing the repositories the token can access through GitHub's installation API. A personal access token or a token from another repository is refused.
3. **Never passes the token on.** The job token is used only to identify the run; it is never forwarded to the model provider or anyone else (R3, no token passthrough).
4. **Enforces a budget.** Each run gets a cap on requests and tokens, so a steered agent cannot run up cost (Paper 1, residual risk "harm at the adversary's own level").
5. **Reports the model.** For each run, the proxy records the model identifier and version it served and the number of requests. The agent-run record takes these from the proxy, not from the agent (Paper 1, Table 3). The attestation job can fetch a run's receipt with its own job token from the same repository, and pass it to `obaaf attest agent-run --model-receipt`.
6. **Keeps little.** The proxy logs digests and counts, not prompts or responses, unless the studio chooses otherwise.

## Receipt format

```json
{
  "format": "obaaf-model-receipt/v0.1",
  "repository": "OWNER/REPO",
  "runId": "1234567890",
  "runAttempt": "1",
  "model": "provider-model-name",
  "version": "provider-version-string",
  "requests": 12
}
```

## Network policy

Agent jobs must reach only the proxy and the package sources the task needs (R7). Either:

- run the agent job on GitHub's native egress firewall (`runs-on: ubuntu-24.04-firewall` with `.github/egress-firewall.yaml` in `enforce` mode; a technical preview, on Linux runners), with only the proxy allowed;
- run the agent's command under [OBAAF's egress action](egress-control.md), with only the proxy's host name allowed;
- run the agent job on ephemeral self-hosted runners behind a network policy that allows only the proxy; or
- use a runtime egress monitor that blocks other destinations (the template's optional step, enabled with the repository variable `OBAAF_EGRESS_MONITOR`).

Declare the policy in the job's `OBAAF_EGRESS` variable; the agent-run record copies it. A declaration alone enforces nothing, so `obaaf check` reports agent jobs whose egress is only declared, or limited by a monitor that runs only under a condition, as well as agent jobs with no policy at all (`OBAAF-GHA-020`, low). The firewall and the action can clear the finding; a monitor is "cannot tell" at best. See [the controls the checker reads](checker-configuration.md#controls).

## Open design points

- Confirm the most reliable way to tell a job token from other tokens, and how to bind a request to one run.
- Decide whether the proxy should run as a small cloud service, a container a studio hosts, or both.
- Decide how a studio on another CI system authenticates runs.
