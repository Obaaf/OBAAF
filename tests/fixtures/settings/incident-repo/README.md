# A repository shaped after the first adopter's incidents

These workflow files go with the recordings in the directories beside this one (`admin-token`,
`workflow-token`, `public-no-token`): together they are the repository `example-studio/game` that
`tests/test_settings_rules.py` audits. The settings are in the recordings, written by hand from the
examples in GitHub's REST reference; what the workflows use is here. Nothing in this directory runs: GitHub
reads workflows only from the `.github/workflows` directory at the root of a repository.

| File | What it is for |
| --- | --- |
| `agent.yml` | An agent job that names the environment `main-only` and reads a model key |
| `ci.yml` | Jobs that run on every pull request: a matrix job that is a required check, and one that is not |
| `scan.yml` | Started by `pull_request_target` and by `workflow_run`; an Actions policy allows `pull_request_target` and `workflow_dispatch` for it, not `workflow_run` |
| `release.yml` | Calls `publish.yml` and passes it a secret that is stored only in the environment `release` |
| `publish.yml` | The reusable workflow; its job declares no environment |
| `../obaaf.yml` | `protected_secrets`: every `*_API_KEY` and the held-out token must stay in `main-only` |
