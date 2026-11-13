# Upgrading OBAAF

What changes when you move to a newer OBAAF, and how to do it so that a gate that turns red tells you something. OBAAF is 0.x: a release may change what passes. Release 0.3.0 showed the need. The code after it turns a passing gate red in several ways without a line of the workflows having changed, each on purpose.

## Versions, and what to pin

- **A release** has three numbers (`0.3.0`). It is on PyPI (`pip install obaaf==0.3.0`) and has a tag (`v0.3.0`).
- **Between releases** the code on `main` calls itself a development number (`0.4.0.dev0` on the way to 0.4.0). It is not a release, and it changes without notice. The JSON and SARIF reports, a baseline file and the generated documents say which version wrote them; the text report does not (`obaaf --version` does).
- **Pin what your gate runs**: a release from PyPI, or the `setup-obaaf` action at a full commit SHA. A gate that follows `main` can fail because OBAAF changed, on a day nobody chose.
- How a release is made is in [releasing.md](releasing.md). What each release changed is in the [changelog](../CHANGELOG.md).

## How to upgrade

Move the pin in a pull request of its own, so that the gate runs once with the new version and nothing else changes with it.

1. Read the section below for the version you are moving to.
2. With the new version, run the report without failing anything: `obaaf check . --fail-on never`, with `--baseline FILE` if your gate uses one. Read its first lines and anything marked "Not accepted".
3. Run your gate's own command and look at the exit status. If it is 1, the report says why: each finding that counts says under it what its acceptance lacks, and an old baseline is named with the command that converts it.
4. Do what the section says: convert the baseline, complete the `ignore` entries, correct the declarations.
5. Run the gate's command again. Commit the pin together with the changed baseline and configuration, and have the baseline reviewed like a workflow.

## From 0.3.0 to the code on `main` (0.4.0, not released)

Nobody is affected until they move: a repository pinned to 0.3.0 or to a commit sees no change. This section becomes the note for 0.4.0 when that is released, and may gain entries until then.

### What can turn a passing gate red

| What you have | What happens | What to do |
| --- | --- | --- |
| A baseline written by 0.2.0 or 0.3.0 (`obaaf-baseline/v0.1`) | It is still read and accepts nothing: every finding it covered counts as new, marked "Not accepted" | `obaaf baseline migrate FILE --owner OWNER --reason REASON --expires YYYY-MM-DD`, once. It carries over the findings the old file covers and accepts nothing new |
| An `ignore` entry with no `owner:` | It ignores nothing, and the finding is reported with "because it names no owner" | Add `owner:` (`@user`, `@org/team` or an e-mail address) |
| An `ignore` entry whose reason has fewer than four letters or digits, or whose `until` is more than 366 days ahead | It ignores nothing, and the report says which | Give a reason; bring the date within a year |
| An `ignore` entry whose `until` is a date in another spelling (`20270131`) | A configuration error, exit status 2. (A time of day, `2027-01-31T10:00:00Z`, ended 0.3.0 in a traceback when the entry matched a finding; it is the same error now) | Write `YYYY-MM-DD` |
| A lane declaration that does nothing: `OBAAF_LANE: agnet`, `OBAAF_LANE` in a step's `env`, a `lanes:` entry for a job that is not there | 0.3.0 listed it in a note. It is the finding `OBAAF-CFG-001`, high in most cases, and fails the default gate | Correct or delete it, then run `obaaf check . --lanes`. Correcting it can bring the findings it was hiding. To keep it, accept it in the baseline; an `ignore` entry cannot accept this rule and is a configuration error if it names it |
| An agent job whose egress control is a blocking `step-security/harden-runner` step | 0.3.0 reported no `OBAAF-GHA-020` for it. It is now reported. It is "not met" when the step is not the job's first, runs behind an `if:`, is at a commit OBAAF lists as a release before v2.16.0, leaves `sudo` or containers to the job, or the job runs in a container; otherwise "cannot tell" (a tag or an unlisted commit included). A baseline entry written for "cannot tell" before slice 2c.3 stops counting where the monitor is now "not met", because that is another case of the rule | Set `disable-sudo-and-containers: true` and pin a release from v2.16.0 on, then accept it again; or move the job to GitHub's native egress firewall or OBAAF's egress action, which can clear it |
| A job whose agent CLI is only in the `run` input of OBAAF's egress action, or in a script that input runs | It is now an agent job, with the agent rules (OBAAF-GHA-003, 005, 020 and the rest) | Fix or accept the findings; OBAAF-GHA-020 can be cleared by the action itself (see "Egress control" in the changelog) |
| An agent job that runs `awf ... --` in a script (where a command starts, outside a comment), with an accepted `OBAAF-GHA-020` | The finding is now the case `awf` ("cannot tell"), not `none`, so an acceptance of `none` no longer names it | Accept it again |
| A job whose `if:` only looked like a test of the event (the test inside a string, compared with `false`, or outside `${{ }}`) | It is now checked for every event that can start it, and can have findings it did not have | Fix the findings, or write the `if:` as a plain comparison of `github.event_name` |
| An input written in another case under `with:` (`REF:` for `ref:`) | It is read as the input it is, so a rule that looks at it now sees it | Fix the finding |
| A release policy (`signing: keys`) or `obaaf dsse assemble --public-key` that names a key outside ECDSA P-256 and P-384, Ed25519 and RSA (P-521, secp256k1, DSA, Ed448, X25519, a binary curve) | The key is refused when it is loaded, with an error naming the file, and `obaaf verify release` and `obaaf dsse assemble` end with status 1. Before, a key on another prime curve was accepted, a binary-curve key ended both commands in a traceback (with the pinned cryptography 50.0.1), and the other kinds failed later | Sign with a P-256, P-384, Ed25519 or RSA key and name its public key in the policy |
| A step that gives one input twice under two spellings (`ref:` and `REF:`) | An error for the file, and exit status 1 whatever `--fail-on` says: the checker cannot tell which value GitHub uses | Keep one of the two |

`obaaf audit` is in no release, so nothing about it can change for someone on 0.3.0. If you run it from a commit after 0.3.0: it now applies rules and ends with status 1 on a finding at medium or above (`--fail-on never` gives the old status), and `--format json` prints a report with the snapshot under `snapshot`, where it printed the snapshot; with `--expected`, the comparison is under `drift` in that report, where it printed a document of its own, `obaaf-settings-drift/v0.1` ([the settings audit](settings-audit.md)).

The details of each are in the [changelog](../CHANGELOG.md), under "The lifecycle of a finding", "A lane declaration that does nothing is a finding", "Controls", "Egress control", "Which events can start a job" and "Inputs in any case".

### What a script that reads the output will notice

- **The text report begins differently**: `Accepted risk: ...` and `Other findings: ...` come first. The line `Baseline: N finding(s) accepted by the baseline, M new.` is unchanged.
- **The `ignored:` lines** read `ignored: RULE path:line - accepted by OWNER until DATE: REASON`.
- **A path is printed in quotes** where it heads its findings, unless it is made of visible ASCII characters with no space.
- **The notes no longer list lane declarations that do nothing**; they are findings. In JSON they are in `findings` and no longer in `notes`.
- **JSON keeps every top-level field and every field of a finding.** New: `acceptedRisk` and `summary` before the findings; `state` on every finding, `kind` and `facts` where the rule gives them, `acceptance` where a baseline or ignore entry names the finding, and `controls` where it has any; `fixed`, when there are any, a list of findings cleared by controls the checker verified, which are no longer in `findings`. The entries under `baseline.stale` are the baseline's own entries, so with a converted baseline they have `owner`, `reason` and `expires`, and `kind` and `facts` where the finding had them, and no longer `fingerprint` or `message`; the `no longer found:` lines of the text report end differently for the same reason.
- **SARIF**: an accepted finding has a suppression, and its message says who accepted it. Errors and notes are notifications of the run.
- **`--write-baseline`** needs `--owner`, `--reason` and `--expires` for anything it newly accepts (exit status 2 without them), and does not write over a file that is not a baseline.

### One upgrade, start to finish

A repository with two workflows, a baseline written by 0.3.0 that accepts its four findings, and one job declared `OBAAF_LANE: agnet`. With 0.3.0 its gate, `obaaf check . --baseline .github/obaaf-baseline.json --fail-on low`, passes: "4 finding(s) accepted by the baseline, 0 new", and a note about the declaration. With the code on `main` the same command ends with status 1:

```text
Baseline: 0 finding(s) accepted by the baseline, 5 new.
  The baseline is in the old format (obaaf-baseline/v0.1). Its entries name no owner, reason or expiry date, so none of them accepts a finding. Convert it once, saying who accepts these findings, why and until when:
    obaaf baseline migrate .github/obaaf-baseline.json --owner OWNER --reason REASON --expires YYYY-MM-DD
```

Convert the baseline:

```bash
obaaf baseline migrate .github/obaaf-baseline.json \
  --owner @my-org/build --reason "Inherited on adoption; tracked in issue 12" --expires 2027-03-31
```

It answers "4 finding(s) carried over" and "1 finding(s) were not in the old baseline and are not accepted by the new one". The gate still ends with status 1, now for one finding:

```text
    12  HIGH   OBAAF-CFG-001  Lane declaration that does nothing  [job triage]
```

Correct `agnet` to `agent`. The job is an agent job now, and the gate ends with status 1 for three findings nobody had seen: `OBAAF-GHA-003` (the agent job can write), `OBAAF-GHA-005` (a secret in an agent job) and `OBAAF-GHA-020` (no egress restriction). In a real upgrade you would fix what can be fixed first. Here nothing is fixed and all three are accepted, to show what the command does:

```bash
obaaf check . --write-baseline .github/obaaf-baseline.json \
  --owner @my-org/build --reason "Agent job found on upgrade; its controls are tracked in issue 31" --expires 2027-01-31
```

"3 finding(s) newly accepted by @my-org/build until 2027-01-31, 4 kept with the owner, reason and expiry date they had." The gate passes, and its first line says what that pass rests on: "Accepted risk: 7 finding(s) are accepted and do not fail the check (3 high, 2 medium, 2 low)".

`tests/test_adoption_path.py` runs this sequence.

### The first adopter

Expectrail, which is the author's own project, runs OBAAF pinned to the commit `d014b63` and sees none of this until it moves its pin. On a copy of its files at `776ddd3`, with its own command, the code on `main` ends with status 1 and 40 findings that count: the 38 its old-format baseline covers, one whose `ignore` entry has no owner, and one lane declaration that does nothing. When it moves its pin it has three things to do, each in a pull request its maintainer makes, because they touch its baseline or its configuration:

1. `obaaf baseline migrate .github/obaaf-baseline.json --owner ... --reason ... --expires ...`.
2. `owner:` on the one entry under `ignore:` in `.github/obaaf.yml`.
3. Its entry `byo-smoke.yml#byo-smoke: probe` under `lanes:`. `probe` is not a lane of OBAAF's. It is a label Expectrail's own audit script reads. Either accept the finding in the baseline with that as the reason, or declare the job `trusted` and keep the list of probes in the script.

After the first step alone, on the same copy: 38 accepted, 2 new. No other adopter's upgrade has been observed.
