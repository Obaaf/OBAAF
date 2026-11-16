# Try OBAAF and send us the result

*For people asked by OBAAF's authors to try it on a repository of their own. Written in flagship slice 3.8 (2026-11-16).*

OBAAF checks a repository's GitHub Actions workflows (and, as advice only, its Jenkinsfiles) for jobs that can reach more than they should: a secret an AI agent's job can read, a release workflow that untrusted input can start, an action that is not pinned to a full digest. You run it on your machine, read what it says, and send back one small file of counts. **Nothing leaves your machine unless you send it**, and the file you send holds no file name, job name, secret name, line of code or anything else written in your repository. You read it before you send it.

It takes about ten minutes. You need:

- a clone of a repository that has workflows in `.github/workflows` (or a Jenkinsfile);
- Python 3.10 to 3.14 with `venv`, and `git`, on Linux or macOS. On Debian and Ubuntu, `python3 -m venv` needs the `python3-venv` package. On Windows, use WSL; nothing here was tried on Windows;
- network access to github.com and pypi.org, for the install only.

## 1. Install

This installs a **development version** of OBAAF, not a release: release 0.3.0 on PyPI has no result file. It is pinned to one commit of OBAAF's repository, and its dependencies are installed by exact version and SHA-256 from that commit's lock (the way OBAAF's own GitHub Action installs it). Everything goes into one new directory, `~/obaaf-try`, which you delete at the end. If a command fails, the block stops; delete `~/obaaf-try` before you run it again.

The block uses `python3`. If `python3 --version` says 3.15 or later, it stops: the locked PyYAML 6.0.3 has no file pip will take for Python 3.15 (seen on GitHub's macOS runner, whose `python3` is 3.15). Install a Python from 3.10 to 3.14 beside it and name it first, for example `export OBAAF_PYTHON=python3.14`.

```bash
(
set -e
try_dir="$HOME/obaaf-try"
py="${OBAAF_PYTHON:-python3}"
"$py" -c "import sys; v = sys.version_info[:2]; sys.exit(0 if (3, 10) <= v <= (3, 14) else 'This is Python %d.%d: use Python 3.10 to 3.14 (see step 1)' % v)"
mkdir "$try_dir"
git clone --quiet --no-checkout https://github.com/Obaaf/OBAAF.git "$try_dir/source"
git -C "$try_dir/source" checkout --quiet --detach f4ee9b6c18cf86a1f7a69e9d979d048fbbe3b02e
"$py" -m venv "$try_dir/venv"
"$try_dir/venv/bin/python" -m pip install --quiet --require-hashes --only-binary=:all: -r "$try_dir/source/actions/setup-obaaf/requirements.txt"
"$try_dir/venv/bin/python" -m pip install --quiet --no-deps --no-build-isolation "$try_dir/source"
"$try_dir/venv/bin/obaaf" --version
)
```

`obaaf --version` prints `obaaf 0.4.0.dev0`, which every development build prints; `git -C ~/obaaf-try/source rev-parse HEAD` shows the commit. OBAAF itself is built on your machine from that source; it has no published digest.

## 2. Run the check and read it

In the top directory of your repository's clone:

```bash
. "$HOME/obaaf-try/venv/bin/activate"
obaaf check .
```

The check reads files only; it sends nothing over the network. It prints each finding with why it matters and the exact fix, and ends with status 1 when a finding is at medium or above or a file could not be read, which is normal on a first run. If your CI already runs `obaaf check`, run it here with the same options as well (`--config`, `--baseline`, `--fail-on`).

OBAAF looks closely at what each job can reach. It does not try to be a general workflow linter: [zizmor](https://github.com/zizmorcore/zizmor), [actionlint](https://github.com/rhysd/actionlint), [poutine](https://github.com/boostsecurityio/poutine) and GitHub's code scanning find much that OBAAF does not look for ([why](landscape.md)).

An AI agent's job is recognised from the agent tools OBAAF knows, or from `OBAAF_LANE: agent` in the job's `env`. If one of yours runs an agent some other way (a script, a CLI it does not know), the report does not treat it as an agent job and leaves out the agent rules for it; a [lane declaration](checker-configuration.md) in `.github/obaaf.yml` can say so, or you can just tell us in your reply.

## 3. Optional: read the repository's settings

The check reads files. Most of the incidents on the first project to use OBAAF were in settings instead (an environment any branch could use, an administrator's account that could skip the required checks). `obaaf audit` reads them through GitHub's API, with GET requests only, and compares them with the workflows:

```bash
obaaf audit . --format json --output "$HOME/obaaf-try/obaaf-audit.json"
obaaf audit .
```

The first line writes the report the result file counts; the second prints the same for you to read. It takes the repository's name from the clone's `origin` remote; if it says it could not tell which repository to audit, add `--repo OWNER/REPO` to both lines. With no token it reads what GitHub shows anyone about a public repository. If `GH_TOKEN` or `GITHUB_TOKEN` is already set in your shell, it uses that token and says so; add `--no-token` to both lines to send none. For a private repository, or to let it read more, set `GH_TOKEN` to a token that can read the repository first. Read access is enough for nearly all of it; [settings-audit.md](settings-audit.md#tokens) says which permission reads what, and what needs more. The token is not written to either report. A setting it cannot read is listed by name, and a rule that needs it says "cannot tell", never "pass". It ends with status 1 when it finds something at medium or above.

## 4. Write the result file

```bash
python -m obaaf.result . --audit "$HOME/obaaf-try/obaaf-audit.json" --output "$HOME/obaaf-try/obaaf-result.json"
```

Leave out `--audit` and its file if you skipped step 3 or it wrote no file. If your CI gives `obaaf check` a `--config`, `--baseline` or `--fail-on`, add the same here. It runs the check again and writes the file, which must be outside the repository; it ends with status 0 when the file is written and 2 when it is not. When the check itself fails, a file left from an earlier run is removed, so that you cannot send it by mistake.

## 5. Read the file

```bash
cat "$HOME/obaaf-try/obaaf-result.json"
```

It holds:

- OBAAF's version, the date, the Python version (`3.12`) and the operating system's family (`linux`);
- how many seconds the check took, the exit status it ended with, and whether a configuration file and a baseline were read;
- how many files were checked and how many could not be read;
- how many jobs are in each of OBAAF's lanes (agent, release and so on), counted with your configuration and without it;
- how many findings of each rule there are, at each severity and in each state (new, accepted, fixed, cannot tell), and how each control that would clear one was judged;
- how much risk is accepted, and by how many owners (a number, not who);
- with `--audit`: for each settings rule, its status and counts; for each setting OBAAF reads, whether it was read and, if not, a short reason code (`forbidden`, `no_token`); whether a token was used and which repository roles GitHub said it has; whether the repository is public, private or internal, and whether a person or an organisation owns it.

It never holds a path, a file, job, step, environment, branch, secret or owner name, a message, a line of code, your repository's name, or a token. That is enforced, not hoped for: before writing, OBAAF checks every key and every piece of text in the file against its own words (its rule ids, severities, states, lane and setting names, reason codes) and writes nothing if anything else is there. A value it does not recognise is counted as `other`. The numbers are counts of what the reports hold, so give it only reports OBAAF wrote: a report changed by hand could put anything into them. The tests put a marker word in file and directory names, workflow, job and step names, scripts, `env` names and values, secret and environment names, actions, runner labels, the configuration and its ignore entries, a baseline's owner and reason, CODEOWNERS, an instruction file, a Jenkinsfile and a file that does not parse, and in every string of a settings report, and check that it is not in the file ([tests/test_result_file.py](../tests/test_result_file.py)). Still, read it: it is a few hundred lines, all of them names of OBAAF's and numbers.

**What the counts can still say.** To someone who knows who sent it, the file says something about the repository: whether it is private, how many agent jobs it has, and which kinds of weakness OBAAF found there and whether they are accepted (a high OBAAF-GHA-002, for example, is untrusted code checked out in a privileged workflow). If that matters, send it privately rather than in a public issue, or fix what it points at first.

## 6. Send it back

Reply to whoever asked you to try OBAAF, attach `obaaf-result.json`, and answer what you can of this:

```text
1. How long did it take, from the first command to reading the report? About __ minutes.
2. Where did you get stuck, or what was unclear?
3. Which findings do you think are wrong, and why? (the rule id and a sentence; no code)
4. How many of your jobs run an AI agent, as far as you know?
5. May we mention this result? No / yes, without naming you or your organisation / yes, naming: ___
```

Question 4 lets us compare what you know with what OBAAF recognised. If you would rather report in public, open an issue with the form [OBAAF result](https://github.com/Obaaf/OBAAF/issues/new?template=obaaf-result.yml). An issue is public and shows your GitHub account. GitHub shows the forms only once they are on OBAAF's default branch; if the link opens a blank issue, paste the questions above instead.

## 7. If a finding changed what you shipped

If a finding made you change something before it was merged or released (or after), we would like to hear about it, in a reply or with the form [A finding changed what we shipped](https://github.com/Obaaf/OBAAF/issues/new?template=finding-changed-what-we-shipped.yml):

```text
Rule: OBAAF-___-___
What it pointed at, in your words (no code, and no names you would rather keep):
What you changed, and when (before merging, before a release, after shipping):
Would you have found it without OBAAF? Yes / probably / no / don't know
Was the risk real? Yes / partly / no, but the change was worth making / don't know
OBAAF version or commit:
May we mention it? No / yes, without naming you or your organisation / yes, naming: ___
```

A finding you think is wrong is just as useful: say so in question 3 of the reply.

## 8. Clean up

```bash
deactivate
rm -rf "$HOME/obaaf-try"
```

Nothing was written into your repository, and nothing was installed outside `~/obaaf-try` (pip keeps the files it downloaded in its own cache, usually `~/.cache/pip` on Linux).

## What has been run, and what has not

- OBAAF's CI runs this page's blocks as written, on GitHub-hosted Ubuntu and macOS runners, against a checkout of OBAAF itself: the install, the check, the audit with no token, the result file, a check that the file holds counts only, and the clean-up (the job "The send-us-the-result page, as written" in [`.github/workflows/ci.yml`](../.github/workflows/ci.yml)). It tries the install with the runner's own `python3` first. On 2026-11-16 that was Python 3.14 on Ubuntu, where everything passed, and Python 3.15 on macOS, where pip found no PyYAML 6.0.3 it could take; the block now stops there with its message, and the job installs again with `OBAAF_PYTHON` naming Python 3.14, as step 1 says.
- The result file's guarantees are tested offline in [tests/test_result_file.py](../tests/test_result_file.py), and the commit pinned in step 1 is checked to hold the same `src/obaaf/result.py` as this page's revision.
- Not run: Windows or WSL, Python 3.10 to 3.13 on this page's path (OBAAF's other CI jobs install the same lock on 3.13 and test on 3.10 and 3.13), a private repository, the audit with a token, an Intel Mac, an ARM Linux machine, and a person's time from start to finish. The ten minutes above is an estimate, not a measurement.
