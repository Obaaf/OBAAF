# Workflow checker demonstration

These files are input data for OBAAF. They are outside `.github/workflows/`, so GitHub does not execute them. The checker reads their configuration; it does not run their build commands or access a deployment secret.

| Sample | Expected findings | Expected exit code |
| --- | --- | --- |
| `unsafe.yml` | 2 high, 3 medium | 1 |
| `corrected.yml` | None | 0 |

The unsafe sample is copied from the existing pwn-request test fixture. The corrected sample uses a pull-request trigger, read-only permissions, a pinned checkout revision, no persistent checkout credentials, and no deployment secret.

## Run locally

From the repository root, with OBAAF installed:

```sh
obaaf check demo/unsafe.yml --fail-on medium
obaaf check demo/corrected.yml --fail-on medium
```

## Run on GitHub

Open Actions, select **OBAAF checker demo**, and select **Run workflow**. Choose `unsafe` or `corrected` and run on `main`. Open the **Check selected example** step to read the findings.

The unsafe run is deliberately red; the corrected run should be green. This workflow runs only when manually requested. It does not deploy software or enforce a merge requirement.

Zero findings means none of the implemented rules found an issue in the scanned file. It is not a guarantee that an application or repository is secure, and this demonstration does not validate release signatures or the live agent workflows.
