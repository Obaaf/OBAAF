# Jenkins templates

`obaaf-audit.Jenkinsfile` runs the advisory Jenkins audit (see [docs/jenkins.md](../../docs/jenkins.md))
as a Jenkins job.

- Keep it in a repository your platform or security team protects, and point a Pipeline job at it
  ("Pipeline script from SCM"). The audit must never use the Jenkinsfile it audits as its own job
  definition.
- Set `OBAAF_REVISION` to the full commit SHA of the OBAAF release you reviewed. The job installs
  OBAAF from that commit, with every dependency pinned by hash.
- Give it an agent labelled `obaaf-audit` that holds no other credentials. For a private target,
  wrap the target fetch in `withCredentials` with a read-only token for that repository alone.
- Start it with the target's clone URL and a full commit SHA. It archives the text, JSON and SARIF
  reports and the coverage, so a partial scan cannot look complete. It fails when a finding is at
  or above medium; the coverage unknowns in the report are not a pass.

Templates for agent, effect and release jobs on Jenkins are not built yet.
