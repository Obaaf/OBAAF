# Jenkins templates

See [docs/jenkins.md](../../docs/jenkins.md) for what each template relies on and what it does not prove.

| Template | Use it as | Purpose |
| --- | --- | --- |
| `obaaf-audit.Jenkinsfile` | a Pipeline job in a repository your platform or security team protects | runs the advisory Jenkins audit against a target repository at a fixed commit |
| `obaaf-release-build.Jenkinsfile` | the Jenkinsfile of a multibranch project that discovers tags only | builds a release from a protected tag with no credentials, then starts the publish job |
| `obaaf-release-publish.Jenkinsfile` | its own Pipeline job, read from your default branch | finds the tag build that started it, signs the records with a key service, verifies, waits for a named approver, verifies again, uploads |
| `obaaf-policy.example.yaml` | `.obaaf/policy.yaml` on your default branch | the release policy (`signing: keys`) |

## Audit job

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

## Release lane

1. Protect tags matching `v*` in your SCM so only maintainers can create them. Create a multibranch
   project that discovers tags only (no branches, no pull requests) for `obaaf-release-build.Jenkinsfile`,
   and add the "Build tags" strategy (Basic Branch Build Strategies plugin) or start tag builds by hand.
   Keep branches and pull requests in your usual project.
2. Create a key in a key service (for AWS, `ECC_NIST_P256`, `SIGN_VERIFY`), put its public key at
   `.obaaf/keys/release.pub.pem`, and copy `obaaf-policy.example.yaml` to `.obaaf/policy.yaml`, both on
   the default branch and owned by code owners. Set `release.jenkins_project` to the tag project's full
   name and `release.approvers` to your release managers.
3. Create the publish Pipeline job ("Pipeline script from SCM", default branch only) in a folder that
   holds only this job, with four credentials: `obaaf-scm-read` (reads the repository),
   `obaaf-release-signer` (can call only `kms:Sign` on that key), `obaaf-jenkins-reader` (a read-only
   API token for a user that can read both jobs) and `store-upload` (can only publish). Grant Run/Replay
   and Configure on it to nobody who can push branches.
4. Run the tag builds and the publish job on agents that run nothing else. A label alone does not
   enforce that: restrict those agents to these jobs on the controller (for example with the Job
   Restrictions plugin), or use a fresh Kubernetes pod per build.
5. In both files, set `OBAAF_REVISION` and edit the lines marked `EDIT`: the publish job's full name
   (with a leading slash) in the build file, and the tag project and release branch in the publish
   file, which must match the policy.

Templates for the agent and effect lanes on Jenkins are not built yet.
