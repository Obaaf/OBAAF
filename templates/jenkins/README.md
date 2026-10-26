# Jenkins templates

See [docs/jenkins.md](../../docs/jenkins.md) for what each template relies on and what it does not prove.

| Template | Use it as | Purpose |
| --- | --- | --- |
| `obaaf-audit.Jenkinsfile` | a Pipeline job in a repository your platform or security team protects | runs the advisory Jenkins audit against a target repository at a fixed commit |
| `obaaf-release-build.Jenkinsfile` | the Jenkinsfile of your repository's multibranch project, with tag discovery | builds a release from a protected tag with no credentials, then starts the publish job |
| `obaaf-release-publish.Jenkinsfile` | its own Pipeline job named `obaaf-release-publish`, read from your default branch | signs the records with a key service, verifies, waits for a named approver, verifies again, uploads |
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

1. Protect tags matching `v*` in your SCM so only maintainers can create them, and turn on tag
   discovery in the multibranch project (tag builds also need a build strategy that builds tags,
   or a person starting them).
2. Create a key in a key service (for AWS, `ECC_NIST_P256`, `SIGN_VERIFY`), put its public key at
   `.obaaf/keys/release.pub.pem`, and copy `obaaf-policy.example.yaml` to `.obaaf/policy.yaml`, both on
   the default branch and owned by code owners.
3. Create the `obaaf-release-publish` Pipeline job ("Pipeline script from SCM", default branch only)
   in a folder that holds only this job, with three credentials: `obaaf-release-signer` (can call only
   `kms:Sign` on that key), `obaaf-jenkins-reader` (a read-only API token for a user that can read
   both jobs) and `store-upload` (can only publish). Do not grant Run/Replay or Configure on it to
   people who can push branches.
4. Give the build an agent label (`obaaf-release-build`) that runs release builds only, and the
   publish job one (`obaaf-release`) that runs nothing else.
5. In both files, set `OBAAF_REVISION` and edit the lines marked `EDIT`.

Templates for the agent and effect lanes on Jenkins are not built yet.
