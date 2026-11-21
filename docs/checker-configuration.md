# Checker configuration

`obaaf check` runs with no configuration. A repository can tune it with a file at `.github/obaaf.yml` (also read from `.github/obaaf.yaml` or `obaaf.yml` at the root), and with two environment variables set on a job.

## Telling the checker about your agents

The checker puts each job in every lane it belongs to (untrusted, agent, effect, release; a job in none of them is trusted) and runs each lane's rules on the jobs in that lane. A job that runs an agent and publishes is in the agent lane and in the release lane, and gets the rules of both. The agent controls run only on jobs in the agent lane. It recognizes an agent by the action a job `uses:`, or by an agent CLI in a `run:` script. The recognized actions and commands are the entries of `agent_tools` in `src/obaaf/data/detection.yaml`, one for each tool ([below](#the-agent-tools-the-checker-knows)).

### The agent tools the checker knows

Since flagship slice 2d.5b (decision D-087) each agent tool the checker knows is one entry in `agent_tools`, with the addresses of the tool's own action files, READMEs or documentation it was read from, and the date. Each fact the slice added was read there; the facts kept from OBAAF's lists before it that none of those sources shows (Claude Code's `-p` and its `install.cmd`, Copilot's `-p`, OpenCode's `run`, `opencode-ai` and `opencode.ai/install`, Aider's install scripts, and the actions `cline/cline`, `Codium-ai/pr-agent`, `All-Hands-AI/OpenHands` and `coderabbitai/ai-pr-reviewer`) are named in the entry under `carried`, so that nothing found before is lost. An entry gives the actions that run the tool, the command lines that run it without a person (the program and the option or subcommand its documentation gives for that), the npm and PyPI packages that install it, its install scripts, and the inputs and options that carry its prompt. The checker's lists of agent actions, commands, packages and install scripts are built from the entries when it loads them, so a list cannot disagree with them.

Every tool that ci-agent-audit recognised at its commit `4a88ee6` (2026-11-07) has an entry; its list was used to know which tools to look at, not as a source of facts. On 2026-11-18 the entries were:

| Entry (`id`) | Found by |
| --- | --- |
| `claude-code` | `anthropics/claude-code-action`, `anthropics/claude-code-base-action`; `claude -p`; `@anthropic-ai/claude-code`; `claude.ai/install` |
| `claude-code-security-review` | `anthropics/claude-code-security-review` |
| `gemini-cli` | `google-github-actions/run-gemini-cli`, `google-gemini/gemini-cli-action`; `gemini -p`; `@google/gemini-cli` |
| `codex` | `openai/codex-action`; `codex exec`; `@openai/codex`; `chatgpt.com/codex/install` |
| `github-models` | `actions/ai-inference` |
| `copilot-cli` | `copilot -p`; `@github/copilot`; `gh.io/copilot-install` |
| `pr-agent` | `qodo-ai/pr-agent`, `Codium-ai/pr-agent`, `The-PR-Agent/pr-agent`; `pr-agent --pr_url` or `--issue_url`; PyPI `pr-agent` |
| `coderabbit` | `coderabbitai/ai-pr-reviewer` |
| `openhands` | `All-Hands-AI/OpenHands` and five `OpenHands/extensions/plugins/...` actions; `openhands --headless` |
| `opencode` | `sst/opencode`, `anomalyco/opencode`; `opencode run`; `opencode-ai`, `@opencode/cli`; `opencode.ai/install` |
| `cline` | `cline/cline`; `cline`; npm `cline` |
| `aider` | `aider`; PyPI `aider-chat`, `aider-install`; `aider.chat/install` |
| `qodo` | `qodo-ai/command`; `@qodo/command`, `@qodo/cli` |
| `auggie` | `augmentcode/augment-action`, `augmentcode/augment-agent`; `auggie --print`; `@augmentcode/auggie` |
| `continue` | `continuedev/continue/actions/general-review`; `cn -p`; `@continuedev/cli`; its `install.sh` and `install.ps1` |
| `jules` | `google-labs-code/jules-action` |
| `goose` | `goose run`; its `download_cli.sh` |
| `kilo` | `Kilo-Org/kilocode/github`; `kilo run`; `@kilocode/cli`; `kilo.ai/cli/install` |
| `kiro` | `kiro-cli ... --no-interactive`; `cli.kiro.dev/install` |
| `qwen-code` | `QwenLM/qwen-code-action`; `qwen -p`; `@qwen-code/qwen-code`; its standalone install script |
| `swe-agent` | `sweagent run` |
| `warp` | `warpdotdev/oz-agent-action`, `warpdotdev/warp-agent-action` |
| `amp` | `amp -x` |

**Which actions and called workflows are an agent's** (slice 2d.11, decision D-096). An entry's action names that action and every action in a folder under it, in any letter case: `anthropics/claude-code-action` is also `anthropics/claude-code-action/base-action`. A job that calls a workflow is read the same way, so `anthropics/claude-code-action/.github/workflows/review.yml@v1` is under Claude Code's action. Where a listed action is a whole repository, every workflow of that repository is under it (several, such as `google-github-actions/run-gemini-cli` and `QwenLM/qwen-code-action`, publish workflows that run their agent). Where it is a folder of a larger repository (Continue's `continuedev/continue/actions/general-review`, Kilo Code's `Kilo-Org/kilocode/github` and OpenHands' five `OpenHands/extensions/plugins/...`), that repository's workflows are not, since a workflow is always at `owner/repo/.github/workflows/`. A repository whose name only begins like an action's is another repository: `anthropics/claude-code-action-docs/...` is not under `anthropics/claude-code-action` (before this slice, a called workflow there made its job an agent job). The same holds for your own `agents.actions`, each read without space round it, without an `@ref` (any ref of it is named) and without a `/` at its end: `my-org/agent/` and `my-org/agent@v1` name `my-org/agent` and everything under it, and `my-org` names every action and workflow of `my-org`. `agents.actions` and `agents.commands` must be lists of text. An `agents.actions` entry that is empty once its `@ref` and a `/` at its end are taken off (`@v1`, `/`), or that is a `docker://` image, names no action and is refused. A local entry (`./.github/workflows/agent.yml`) names a job that calls a local workflow whose path begins with it, as before; no step's local action is compared with it, since the checker reads local actions through. An `agents.commands` entry that is not a Python regular expression is refused too (before, the check stopped with a traceback).

An entry's `not_agents` lists the actions in a folder under its actions that run no agent, each with the action's own words, the file, commit and lines they were read from, and what was read to know that it runs no agent. A job that uses only one of them is not an agent job, and OBAAF-GHA-026 reads none of the agent action's settings on it. Every other path under an agent action is still the agent, because the checker cannot tell what a folder it has not read runs. A listed path is taken out only as it is written: its owner and repository in any case, and the folder exactly (`Agent-Approval-Check` is still the agent; a Linux runner does not find it, and a macOS or Windows runner may), and not a folder under it; `..` is worked out first. Your own `agents.actions` are never narrowed by it: a prefix you list names every path under it. A listed path is taken out at every ref, although it was read at one commit: the action may change at `@v1` or `@main`, and a commit of a fork that GitHub serves under the parent's name is not the code that was read.

A step whose `uses:` leaves its repository is taken for an agent's action in any job: a local path whose `..` climbs out of the workspace (`./../../_actions/...`), a local action whose path goes through a link that leads out of the repository (its folder, its action file or a folder above them), or another repository's action whose `..` climbs to or above its `owner/repo` (`actions/checkout/../../../anthropics/...@v4`), a backslash read as a `/`. The runner puts the whole repository of each action a job uses in one folder beside the workspace, so after `anthropics/claude-code-action/agent-approval-check` a step could reach Claude Code's own action that way, and the same holds for any other repository that holds an agent action. The job is an agent job, and no tool is named in its findings' `agents`. Not caught: a `run:` step that copies or clones an agent's action into the workspace for a later `uses: ./...` (the checker reads a local action as it is checked out). Read on 2026-11-19, the list is:

| Action | What it does, in its own words | Read at |
| --- | --- | --- |
| `anthropics/claude-code-action/agent-approval-check` | "Require N human approvals on PRs that contain agent-authored commits (Claude, Claude Code, or any configured bot identity). Posts an `agent-approval-check` commit status" | [`action.yml`, lines 1 to 6, at `f431ada`](https://github.com/anthropics/claude-code-action/blob/f431adaf77e0fecf918431e75a2b5b45b85af002/agent-approval-check/action.yml#L1-L6). Its steps install three Python packages and run its own script, which calls only api.github.com |

That day each listed action's repository was read at its default branch for every other folder with an `action.yml` or `action.yaml` under a listed action. None is listed, so each is still taken for the agent. `anthropics/claude-code-action/base-action` runs Claude Code. Four of `sst/opencode` (the same repository as `anomalyco/opencode`), under `.github/actions/` and `.github/release/`, and `cline/cline/.github/actions/sign-windows-cli` are the projects' own build steps, which another repository is not expected to use; only their `action.yml` was read. `coderabbitai/ai-pr-reviewer` could not be read without signing in, and `All-Hands-AI/OpenHands` has no `action.yml` at its default branch. The other listed actions have no folder with an `action.yml` under them.

**Each agent rule names the agent.** The findings of OBAAF-GHA-003, 004, 005, 012, 020 and 025 have a fact `agents`: the `id` of each entry the job runs, and `agents.actions: <prefix>` or `agents.commands: <pattern>` for each entry of your own configuration that matches, sorted. They are read in the job's steps, in the steps of the local actions it uses, in a workflow it calls in an agent action's repository or folder, and in its default shell. So an acceptance of one of those findings stops covering the job when another named agent is added to it, or takes the place of the one it ran. A job that runs no agent the checker can name (one you declared an agent job, or one whose agent runs in a repository script) has no such fact. The fact is not shown in the text report or in SARIF; the JSON report has it with the finding's other facts.

**Settings the tool's own documentation warns about** (OBAAF-GHA-026, slice 2d.5c1, decision D-088). An entry's `settings` lists values of its actions' inputs that the tool's own documentation warns about, each with the words, quoted, and the file, commit and lines they were read from. A finding for a matching literal prints both. A value is compared trimmed and in any letter case; where two settings name one input, the first that matches is reported; a value the checker cannot read (an expression, a list, a mapping) gets a medium `computed` finding with no source quotation. An unaccepted finding fails the default medium gate. Read on 2026-11-19:

| Action and input | Value | Severity | Entry |
| --- | --- | --- | --- |
| `openai/codex-action`, `safety-strategy` | `unsafe` | high | `codex` |
| `openai/codex-action`, `safety-strategy` | `read-only` | medium | `codex` |
| `openai/codex-action`, `allow-users` | `*`, the whole value (in a list the action reads it as a user's name) | high | `codex` |
| `anthropics/claude-code-action`, `allowed_non_write_users` | `*` | high | `claude-code` |
| `anthropics/claude-code-action`, `allowed_non_write_users` | any other value that is not empty | medium | `claude-code` |
| `anthropics/claude-code-action`, `allowed_bots` | `*` | medium | `claude-code` |
| `anthropics/claude-code-action` and `anthropics/claude-code-base-action`, `show_full_output` | `true` | medium | `claude-code` |
| `google-github-actions/run-gemini-cli`, `gemini_debug` | `true`, read as GitHub's `fromJSON` reads it (the action reads it that way): the first token, a string in double or single quotes or a word up to a separator, so `'"true"'` and `true // off` are `true`; a value that starts with a comment is "cannot tell" | medium | `gemini-cli` (slice 2d.5c2b) |
| `QwenLM/qwen-code-action`, `qwen_debug` | `true`, read the same way | medium | `qwen-code` (slice 2d.5c2b) |
| `OpenHands/extensions/plugins/pr-review`, `enable-uv-cache` | `true`, or `auto`, which turns setup-uv's cache on on GitHub-hosted runners | medium | `openhands` (slice 2d.5c2b) |

A value only another scanner's data calls dangerous is not reported. The actions' defaults, `safety-strategy: drop-sudo` or `unprivileged-user`, and named users or bots in `allow-users` and `allowed_bots` give no finding; an empty `allowed_non_write_users` also gives no finding. The documented warning for `allowed_bots: "*"` concerns public repositories. The checker reports the literal without checking repository visibility. A value is compared with white space taken off its ends as either Python or JavaScript trims it (U+FEFF included); a value with a control, format, separator, private-use or unassigned character left inside it other than a space, a tab, a carriage return or a line feed, and a `with:` that is neither a mapping nor empty (inputs written as one expression, `with: ${{ fromJSON(...) }}`), are "cannot tell". Not read: claude-code-action's `display_report`, a key written in clear, `ACTIONS_STEP_DEBUG`, these actions inside another repository's composite action or reusable workflow, and a `uses:` with an empty path segment, a leading `/` or a backslash (#245).

**Options the tool's own documentation warns about** (OBAAF-GHA-026, slice 2d.5c2a, decision D-090). An entry's `flags` lists command-line options its own files warn about, each with the option's spellings, the values warned about where it takes one (`equals`), the words, quoted, and the file, commit and lines they were read from; an action's `args_inputs` name the inputs it hands the program as options. They are read in those inputs (case `option`) and wherever a step runs the tool's program or package (case `command-option`). Read on 2026-11-19:

| Option | Entry | Severity | Read in |
| --- | --- | --- | --- |
| `--dangerously-skip-permissions`, `--allow-dangerously-skip-permissions` | `claude-code` | high | `claude`, and `claude_args` of `anthropics/claude-code-action` and its base action |
| `--permission-mode bypassPermissions` | `claude-code` | high | the same |
| `--dangerously-bypass-approvals-and-sandbox`, `--yolo` | `codex` | high | `codex`, and `codex-args` of `openai/codex-action` |
| Codex's `--dangerously-bypass-hook-trust` | `codex` | medium | the same |
| `--yolo`, `-y`, `--y`, `--approval-mode yolo`, `--approvalMode yolo` | `gemini-cli` | medium (its documentation turns the sandbox on with them) | `gemini` |
| `--yolo`, `-y`, `--y`, `--approval-mode yolo`, `--approvalMode yolo` | `qwen-code` (slice 2d.5c2b) | high (its documentation says `--yolo` turns on no sandbox) | `qwen` |
| Qwen Code's `--insecure` | `qwen-code` | medium | `qwen` |
| `--auto`, and the hidden `--yolo`, `--dangerously-skip-permissions` and `--dangerouslySkipPermissions`, which skip the checks `--auto` answers | `kilo` (slice 2d.5c2b) | high | `kilo` |
| `--yolo`, `-y`, and `--zen`, `-z`, and `--auto-approve` or `--autoapprove` with any value but `false`, which do what `--yolo` does (Cline puts `true` after a bare one) | `cline` (slice 2d.5c2b) | high | `cline` |
| `--allow-all-tools`, `--allow-all`, `--yolo` | `copilot-cli` (slice 2d.5c2b; the sentences are in GitHub's documentation, `github/docs`) | high | `copilot` |
| Copilot CLI's `--show-secrets`, `--trust-folder`, `--share-gist`, `--share` | `copilot-cli` | medium | `copilot` |
| PR-Agent's `--config-branch` given `$GITHUB_HEAD_REF` (a value the checker cannot read, such as `${{ github.head_ref }}`, is medium "cannot tell"; a branch written out is not reported) | `pr-agent` (slice 2d.5c2b) | high | `pr-agent` |
| `--always-approve`, `--yolo`, `--headless`, and any beginning of them (`--always`, `--yol`, `--head`), as Python's argparse takes it | `openhands` (slice 2d.5c2b) | high | `openhands` |
| Continue's `cn --auto` | `continue` (slice 2d.5c2b) | medium | `cn` |
| OpenCode's `--hostname 0.0.0.0` | `opencode` (slice 2d.5c2b) | medium | `opencode` |
| goose's `--dangerously-unauthenticated` | `goose` (slice 2d.5c2b) | medium | `goose` |

**How a script is read.** A bash or sh script is read twice, and the two readings are added together:

- as bash splits it: quotes, backslashes, `$'...'` and `$"..."` as bash reads them; a heredoc as data unless a shell or an interpreter reads it; a `case` pattern as a pattern; a variable put in where its value is known (an `env` value that is plain text, from the step's `env`, else the job's, else the workflow's, unless the script sets the name; after a step that writes `GITHUB_ENV` or calls `exportVariable`, only the step's own `env`; or a name the script sets once, to plain text), and none at all where the script runs `eval`, `source`, a nameref, or `declare`, `export`, `printf -v` or `read` with a quoted or computed name, which can set any name; a `git` setting whose value names the tool (`alias.r=!cmd`, `diff.external`, given with `-c`, `git config` or `GIT_CONFIG_VALUE_n`); and command substitutions, `bash -c`, `sh -c`, `eval`, `env -S`, `su -c`, `script -c`, `flock -c`, `watch`, `npx -c`, aliases, interpreters given code (`perl -e`, `python3 -c`, `node -e`, `pwsh -Command`), and text a shell reads from a pipe, a heredoc or a here-string read again;
- the widest way: comments and data heredocs taken out, quotes and backslashes removed, brackets and commas made spaces, and the text cut where a shell starts a command. So an option written in a prompt's text, or in a JavaScript or Python argument list, is read as given.

The program counts where a command starts (after `sudo`, `env`, `timeout`, `xargs`, `find -exec`, `npx`, `yarn` and the like), and as an argument of any command whose arguments are not data (`docker run`, `cross-env`, `ssh`, `conda run`); the data commands are a fixed list (`echo`, `grep`, `git`, `find`, the package installers, `docker build` and the like). A quoted argument of such a command that names the tool (`tmux new -d 'claude ...'`, `ssh host 'claude ...'`) is read again as a command line, and so is a step's `shell`. A step in another shell (`pwsh`, `cmd`, `python`; pwsh is the default on a Windows runner), a github-script script and code given to an interpreter are read the widest way, the program found anywhere in them, and by their tokens or words (below). An option is matched in any letter case, as `--name=value` and as `--name value`, and a one-letter option inside a group (`-yp`). Nothing after a word `--` is an option, unless the `--` comes right after an option, whose value it may be; `--name=false` is not a match.

**What is "cannot tell"** (a medium `command-computed` finding), in a step that names the tool:

- a word of the program's command with a variable or substitution outside quotes, `"$@"` or `"${NAME[@]}"`, an unquoted glob, or a `${{ }}` expression;
- a quoted word that could start a warned option (`"--dangerously-$X"`, `"$EMPTY"--yolo`, `"${F:---yolo}"`);
- a warned option that takes a value, given one the checker cannot read;
- the program run by `xargs` or `parallel`;
- a command the checker cannot name (`$C`, `"$(command -v claude)"`, `{claude,}`), or a new name made for a program (`alias`, `hash`, `ln`, `cp`);
- `IFS` set, `eval` or a shell given text the checker cannot read, a script file written in the step and run, text it cannot split (an unclosed quote), and nesting deeper than four levels;
- in PowerShell, a variable, group or splat outside quotes among the program's words (`claude @a`, `claude $flags`, `claude (Get-Content f)`); an environment variable (`$env:PROMPT`) is always one string and so one word, and a variable inside double quotes is one word;
- in cmd, a `%VAR%`, `!VAR!`, `%*` or `%1` anywhere among the program's words, inside double quotes too, because cmd puts the text in before it reads quotes (`claude -p "%PROMPT%"` passes `--dangerously-skip-permissions` when the value is `x" --dangerously-skip-permissions "`);
- in either, a command it cannot name (`& $exe`, `%C%`), `Start-Process claude -ArgumentList` with a variable (Start-Process joins its arguments into one command line), a splatted `Start-Process @p`, and the same inside `{ }` blocks, `cmd /c`, `bash -c`, `npx`, `start` and `call`;
- in code in another language (below), what that code gives the program that the checker cannot read.

**Code in another language** (slice 2d.5c2c): code given to an interpreter (`python3 -c`, `node -e`, `perl -e`, `ruby -e`, `php -r`, an awk program, a heredoc or `echo '...' |` fed to one), a github-script script and a step whose `shell` is python, node, ruby, perl, php or pwsh are read by their tokens as well as the widest way. In such code, these are "cannot tell":

- an argument list with a splat or spread (`*flags`, `...flags`, Perl's `@ARGV`), joined with another (`["claude"] + flags`), held in a name the code changes in a way it cannot read (`cmd.extend(flags)`, `cmd += flags`, a value of a loop over what the checker cannot read appended on its own once for each turn; not the value of an option the same change adds, `cmd += ['--allowedTools', t]`, nor a loop over literal strings), or given whole as a value to a call that takes the list (`exec.exec('claude', flags)`, `spawn('claude', args)`, `os.execvp('claude', args)`), or given with Node's `{shell: true}`, which joins the words into one shell command line;
- a command line in a string given to a call that runs one (`os.system`, `subprocess.run(..., shell=True)`, `execSync`, `exec.exec`, Ruby's backticks and `%x`, Perl's `qx` and `open`, `shell_exec`, awk's `system` and pipes, `Invoke-Expression`) that is joined with a value or holds one (`"claude " + f`, `f"claude {f}"`, `` `claude ${f}` ``, `"claude #{f}"`, `"claude $f"`, `"claude %s" % f`, `"claude {}".format(f)`), including a list joined into such a string (`" ".join([...])`): text put into a string can end its quotes, so the value is read as words outside them;
- a value pasted into the code's text before it runs: a `${{ }}` expression, or a shell expansion in a heredoc whose delimiter is not quoted;
- a value whose known start or end could be a warned option (`"--" + x`, `f"--{x}"`, `x + "-skip-permissions"`), or that holds one as a literal (`os.environ.get("F", "--yolo")`, `"--YOLO".lower()`);
- code the checker cannot split (a string that does not end).

Literal pieces are joined and matched (`"--" + "yolo"` is `--yolo`), a name given a string is that string where it is used, and a list held in a name is read where it is given, with what the code adds to it where it adds literals or one value at a time (`cmd.append('--verbose')`, `args.push('--model', model)`, `cmd + ['--output-format', 'json']`). In JavaScript and PHP, the program's name as an argument of a call that does not run a command (`core.group('claude', fn)`, `path.resolve(dir, 'claude', name)`) is read only for literal options after it. One value in one place of a list (`["claude", "-p", prompt]`), or given as one argument where the language gives it as one (Python and Ruby call arguments, a Perl scalar), is one word that is not one of these options, as a quoted variable is in bash; after a warned option that takes a value (`--permission-mode`) it is "cannot tell". A string is read as a command line only where it reaches a call that runs one (directly, through `shlex.split`, `join` and the like, after a shell's name in a list, or through a name given to such a call); a string that is logged, posted or compared is not.

To clear one, write the options out in the step. A quoted word that starts with a variable or substitution (`claude -p "$PROMPT"`) is read as one word that is not an option, although the tool's own parser may take a value that begins with `-` as one (#254); so is one value in one place of a list in code in another language.

**Not read:** in code in another language, a program name given by escapes or pieces (`"\x63laude"`, `"cl" "aude"`), which the step's check for the tool's name does not see, or by a path built at run time; a list held in a mapping (`opts["cmd"].extend(...)`); Perl's `exec { ... } ...`; code written into another process's input; AppleScript and Tcl beyond the widest reading; a shell that runs another interpreter on the script (`shell: bash -c "python3 {0}"`). Codex's `--sandbox danger-full-access` and its `-c` overrides; settings given to `--settings` (a file or JSON); options in a configuration file or an environment variable the tool reads; a program name a step builds at run time (braces, globs, `printf`, another step's `GITHUB_ENV`, `GITHUB_PATH` or outputs, `vars`, a file), which the agent lane does not see either; `python -m` and a repository script a step runs; `BASH_ENV`; a local Docker or JavaScript action.

**What the other entries say** (slice 2d.5c2b, decision D-094). The rest of the entries' action files, READMEs, documentation and CLI help text were read on 2026-11-19 at the commits their `sources` name. Where nothing there warns about a value, the entry says what was read in `no_warnings`; `obaaf catalog` refuses an entry that has no `settings`, no `flags` and no `no_warnings`, and one that has `no_warnings` beside settings or flags. Eleven entries have it.

Two program names are shared with other well-known tools: AWS's Copilot CLI is also `copilot`, and pressly's database migration tool is also `goose`. An entry says so in `shared_program`, with the other tool's own commands, options or drivers in `other_program`; a command the checker cannot read is then not "cannot tell" where every place the step names the program is followed by them (`copilot svc deploy --env ${{ inputs.env }}`, `goose postgres "$DB" up`). A warned option written out is reported either way. A program after a package runner may carry its version or extras: `uvx openhands@latest`, `uvx openhands[all]`, `uv tool run openhands==1.2.0` (with uv's options anywhere before `run`) and `pipx run` are read; `pipx install` is not a run.

Not reported, and why:

- A mode a tool runs in by default, which no option names: a one-shot `cline "prompt"` is in yolo mode unless given `--auto-approve false`, `--act` or `--plan`; `google-github-actions/run-gemini-cli`, `google-gemini/gemini-cli-action` and `QwenLM/qwen-code-action` run their CLI with `--yolo` themselves, whatever their inputs say (#265).
- Not a gap but a cost: a program's name given as an argument of a command that is not on the data list is read as the program, so `ollama run qwen $PROMPT` or `python eval.py --agent openhands $ARGS` is "cannot tell" (#264).
- Options a tool's own files describe with no sentence of warning (decision F-267): OpenCode's `--auto` and its hidden `--yolo` and `--dangerously-skip-permissions`; Aider's `--yes-always`; Qwen Code's `--approval-mode auto` (the CLI's default) and `auto-edit`; Copilot CLI's `--allow-all-paths` and `--allow-all-urls` alone.
- Copilot CLI's other spellings (`--allowAllTools`, a beginning of an option): its parser is not in its public files.
- GitHub Models' `actions/ai-inference` runs Copilot CLI itself with `--model` and `--allow-tool=` built from its inputs, which are not read as Copilot's options. `PR_AGENT_CONFIG_BRANCH`, PR-Agent's variable for its config branch, is not read.
- Tools whose options are documented only on a web page, not in a file at a commit: Kiro CLI (kiro.dev) and Amp (ampcode.com). CodeRabbit's `coderabbitai/ai-pr-reviewer` could not be read: GitHub refused an anonymous read of the repository.
- Environment variables that do what a warned option does, or turn on an agent's approval mode: Copilot's `COPILOT_ALLOW_ALL`, Aider's `AIDER_YES_ALWAYS`, goose's `GOOSE_MODE`.
- The other entries' files warn about events or credentials, not values: Jules' warning is about which events run it, Claude Code Security Reviewer's that it is not hardened against prompt injection, Augment's that its tokens are credentials. `qodo-ai/command` was retired on 2026-11-01. SWE-agent's and Warp's files warn about nothing.

**What the entries do not cover**, as read on 2026-11-18:
- Docker images that run an agent (`docker://...pr-agent`, Amp's review image): an image is not matched to an entry.
- A form of a tool's command its documentation did not give where it was read: Auggie's `-p`, Kiro's `kiro` and `q` programs, OpenHands' and SWE-agent's packages, Amp's package, and any command of Cline but its program name.
- CodeRabbit's other actions: their repositories asked for a sign-in, so nothing could be read.
- The settings and options of the other 20 tools: slice 2d.5c2b. The two actions' settings are read since slice 2d.5c1, and the options of Claude Code, Codex and Gemini CLI since slice 2d.5c2a.
- An agent that no entry names, such as a project's own model entry points: name it in `agents.actions` or `agents.commands`, or declare the job an agent job.
- A command written as text is read as run. The patterns are matched anywhere in a step's command lines, as they were before the slice, so `echo "goose run the migrator"` or a comment `# use kilo run` makes an agent job, and such text names an agent in the `agents` fact; editing it can change the finding.
- The Jenkins rules: their reading of piped installs still knows only the agent names it knew before (`claude`, `gemini`, `codex`, `opencode`, `aider`, `copilot`, `qodo`).
- `auggie -p`, `cn --print`, a prompt piped into `qwen` with no option, `python -m pr_agent.cli`, an agent in a matrix value, and a called local workflow's agent for the calling job's own findings.

The checker also reads repository `.sh` and `.bash` wrappers to find an agent CLI:

```yaml
jobs:
  triage:
    runs-on: ubuntu-latest
    steps:
      - run: bash scripts/run-agent.sh   # the agent starts inside the script
```

It can trace a simple copy in the same `run:` block back to the original repository directory, including a symbolic temporary path:

```yaml
      - run: |
          SNAPSHOT=$(mktemp -d)
          cp -r scripts "$SNAPSHOT/scripts"
          bash "${SNAPSHOT}/scripts/run-agent.sh"
```

It also reads the repository's own actions. A step that uses one (`uses: ./.github/actions/run-agent`, or `$/...`) makes the job an agent job when that action is a composite action and an agent runs in its steps. This is so since flagship slice 2d.4a; before it, an agent inside a local action put the job in no agent lane. The action's steps are read for an agent as a job's steps are, with more put in:
- an agent action, or an agent CLI in any command line of a step;
- each `${{ inputs.name }}` worked out from the using step's `with:`, or else from the action's `default`, also inside `( )`, `||`, `&&` and `format()`; `${{ env.NAME }}` from the step's environment, with its own inputs put in; any other expression that reads an input is read the widest way, as each input it reads, a comparison at its top level as true or false, and another context as empty;
- the using step's `env`, under the action step's own;
- a repository script a step runs, looked for from the repository's root, and from the action's folder or a folder under it when the step's `working-directory` is there or its script changes to it with `cd` or `pushd` (a `cd` the checker does not read is not followed, as it is not from a job's own step; `github.action_path` and `$GITHUB_ACTION_PATH` in any spelling, and a variable the step's `env` sets to it, are put in);
- the further local actions they use, up to ten deep.

Both `action.yml` and `action.yaml` are read when both are there, and an agent in either counts. Whether GitHub takes what follows an `@` in a local path as part of it, and a backslash as a separator (`.\x` on Windows), was not checked, so each reading is read.

```yaml
# .github/actions/run-agent/action.yml
runs:
  using: composite
  steps:
    - run: claude -p "$PROMPT"
      shell: bash
```

**Not read through: a note.** The checker cannot read through some local actions:
- a JavaScript or Docker action;
- an action with no `action.yml` or `action.yaml` in the repository (an earlier step may make one);
- a path that leads outside the repository or holds an expression;
- an expression that reads an input or the environment nested more than 64 parentheses deep, or more than eight `||`, `&&` or `format()` deep, or that can give more than 16 texts; or an input or `env` value that, put in, makes a text longer than 200,000 characters;
- an action whose `runs.using` is not one it reads, whose `runs.steps` is not a list, or with a step that is not a mapping;
- a chain of actions that comes back to itself or is more than ten deep;
- every local action of a workflow checked on its own, whose repository the checker does not know.

These are listed in one note. It names the first five places by file, job, action and reason, and counts the rest. A note is not a finding and does not change the exit status: whether such an action runs an agent is not known, and taking every one for an agent would report every job that uses a JavaScript action of its own.

**Cannot be read at all: an error, which fails the check.** This covers an action file that is not YAML the checker reads (a parse error, a duplicate key, a tag, a disputed line break), is not a mapping, cannot be opened or is larger than 1 MB. It also covers a check whose local actions would cost more units to read than it spends on them (30,000 for the check, and 100 for each step of a job that uses a local action, which only that step's reading may spend), and nesting too deep for the checker. A reading of an action costs one unit, three for each of its steps, one for each 200 bytes of its files, and one for each 200 characters the caller's inputs add to its steps' text. The time this takes grows with the size of the workflows and actions, and no faster. Two cases measured on 2026-11-18, for scale: a 150 KB workflow with 2,500 steps that each give a 30-step local action a different input took 17 s, where a 250 KB workflow of 2,500 `actions/checkout` steps took under 1 s; and an action whose one step puts its input in 850 times costs about three times as much for each use (10 ms, measured on 200 uses), so 2,500 such uses would take about 26 s. These are examples, not a proven worst case. An action is read once for each set of values of the inputs its expressions read and of the environment it is given, and once more for each place in a chain where a cycle or the depth cuts a reading short. A workflow file in any of these states is an error too, and the action's author writes it as freely.

**The other rules read the action's steps too (since slice 2d.4b2).** A composite action's steps run in the job that uses it, on its runner, with its token, workspace and cache, so every rule reads them as steps of that job. The rules are run a second time on a copy of the workflow in which each step that uses a local composite action is followed by the action's steps, and the job is in the lanes those steps put it in (a step that publishes makes it a release job; `--lanes` shows these). The second pass's findings are kept:
- a finding on a step of the action, named by where it is: `./.github/actions/x: actions/checkout@v4` (the action and its step's name, `id`, `uses` or number), with the using step's name before it when that step has one (`Check out > ./.github/actions/x: ...`), and the workflow line of the using step;
- a finding on a step of the job, or on the job, of a case the first pass gave there, in place of the first pass's: its facts, controls and severity then say what the action's steps do, as for steps written in the job (a value a `GITHUB_ENV` write in the action feeds, a fetch of a pull request's code before an agent), so an acceptance of it can stop matching. It is never less severe than before, or nearer to cleared;
- a finding of another case of a rule, on a step of the job or the job, where the first pass has none of that rule there as severe, or where the action's steps put the job in a lane it was not in.

A "cannot tell" finding on a job's own step after any local action has a digest of the steps before it that covers the action's steps, so it changes with the upgrade, and with any later edit to the action.

A finding the second pass does not give is kept as it was. So a check, a control or a pin inside an action never clears a finding of the job's own steps; a check inside an action does count for an upload later in the same action. OBAAF-GHA-023 reads each use of the action's steps as its file writes them (not its inputs' defaults). The secrets rules read the job's own text, not its steps.

Each step of the action gets the inputs the using step gives in `with:` (or the action's `default`) put into the expressions that read them, as expressions (one that then gives plain text is that text, so `push: ${{ inputs.push }}` given `false` is `false`, except in `if:` and `continue-on-error`; a `with:` written as one expression is every input, and named in the note): `ref: ${{ inputs.ref }}` given `${{ github.event.pull_request.head.sha }}` reads as a checkout of the pull request's head, and a script that echoes `${{ inputs.title }}` given an issue's title is OBAAF-GHA-010. An expression that reads `inputs` another way (`toJSON(inputs)`, `(inputs).x`, `inputs.*`, a computed index) gets every input's value in its place, and is named in the note above. Each step also gets the using step's `env` under its own, the using step's `if:` and its own both (`${{ (A) && (B) }}`; `if: false` is that expression), and the using step's `continue-on-error` when that may be true. A step that uses another local action is followed by that action's steps; a step with neither `run` nor `uses` is named in the note. Not read: the action's `outputs` where the job reads them.

**The bounds of this reading are errors, which fail the check:** more than 1,000 steps of local actions for one job, or 2,000,000 characters of their text (with the inputs put in, each alias counted where it is given, and one for each key and item); 10,000 steps or 10,000,000 characters for the check; one text of more than 200,000 characters once its inputs are put in. Past one, the job's actions are not read for the rules (past the check's, no later job's either); the error is given for each job past its bound, and once past the check's. A text the action writes itself, with no input put in, is read as written whatever its length. Measured on 2026-11-18, for scale: a check at the check's bound (30 jobs that each use a 49-step, 100 KB action 20 times) took 11 s, where the reading before this slice took 0.4 s; 990 steps in one job took under a second.

An action from another repository is not read at all. A `./` path is read in the repository as checked out, so an action that an earlier step writes or replaces in the workspace is not what the checker read; OBAAF-GHA-008 reports a `./` action used after a step that checks out another repository at its path, or downloads or restores files over it.

This is best-effort static inspection. It does not execute shell code or read the
temporary destination. The copy source must be readable within the repository;
symlinks that escape it are not followed. Arbitrary variable assignments, fetched
or generated scripts, copies across separate steps, nested wrapper chains, and
complex shell control flow are not resolved. A copy alias means the source may
be executed; it is not proof of runtime reachability.

Always run `obaaf check . --lanes` and confirm that agent jobs are classified as
`agent` before relying on the findings. When the checker finds agent instruction
files (`AGENTS.md`, `CLAUDE.md`, and the like) but places no job in the agent lane,
it prints an advisory note. For wrappers it cannot resolve, declare the entry
point so the agent controls apply:

```yaml
# .github/obaaf.yml
agents:
  commands:
    - 'run-agent\.sh'          # a Python regular expression, matched against each run: line
  actions:
    - my-org/internal-agent    # a private action that runs an agent: it and every path under it, at any ref
```

With that, the `triage` job above is placed in the agent lane, and the agent controls (for example a write token or a secret reaching the job) are reported.

You can also set the lane on a single job explicitly:

```yaml
jobs:
  triage:
    env:
      OBAAF_LANE: agent        # untrusted, agent, effect, release, or trusted
```

A declaration adds a lane. It never takes a job out of a lane the checker inferred, so it can add rules and cannot remove any: declaring `release` on a job that runs an agent leaves it an agent job and makes it a release job as well. Declaring `trusted` adds no lane and removes none. When `trusted` is the only lane declared for a job and the checker puts the job in a lane anyway, the reason shown for that lane ends with `declared trusted, which cannot override what the job does`. Case and surrounding space do not matter (`Agent` is `agent`).

`OBAAF_LANE` is read in a job's `env` and in the workflow's `env`, and nowhere else, and under that exact name. A declaration that does nothing is a finding, `OBAAF-CFG-001`: a value that is not a lane (a misspelling, an expression, an empty value), the variable in another spelling (`obaaf_lane`), and `OBAAF_LANE` set in a step's `env`, a container's or a service's. See [A declaration that does nothing](#a-declaration-that-does-nothing).

When a job is in a lane both because of what it does and because it was declared, the declaration is the reason shown (`set by OBAAF_LANE`, `set in the checker configuration`).

## Lane overrides

```yaml
# .github/obaaf.yml
lanes:
  "release.yml#publish": release
```

A lane override only adds rules, like `OBAAF_LANE`: the job is put in the lane you name as well as the lanes the checker inferred, and if `OBAAF_LANE` names another lane the job is in that one too. A key without `#job` applies to every job in the file. Use the workflow path shown by `--lanes`, for example `.github/workflows/release.yml#publish`, when checking a repository root. The same key applies when you check that one workflow on its own (`obaaf check .github/workflows/release.yml --config .github/obaaf.yml`); a Jenkinsfile checked on its own is known by its file name only.

For a Jenkinsfile the key names a stage (`Jenkinsfile#Ship`) and also covers the stages nested in it; `Jenkinsfile` alone covers every stage. See [jenkins.md](jenkins.md).

For a file this run reads, an entry is a finding (`OBAAF-CFG-001`, reported in the configuration file, on the entry's line) when its value is not a lane or when it names a job or Jenkins stage the file does not have. When a repository is checked, so is an entry for a file that is not there. An entry for a file outside the run (another file when one file is checked, a Jenkinsfile when only workflows are checked) is not looked at. `lanes:` must be a mapping; any other value that is not empty is a configuration error and the check does not run.

### A declaration that does nothing

A lane declaration exists to add rules to a job. One that changes nothing leaves the job without those rules, and nothing else in the report would show it: a job declared `OBAAF_LANE: agnet` is not an agent job to the checker, so none of the agent findings appear and the check passes. Until 0.3.0 such a declaration was listed in the notes at the end of the report, which do not affect the result. It is now a finding, `OBAAF-CFG-001`, so it fails the check until it is corrected or accepted.

```text
.github/workflows/triage.yml
     9  HIGH   OBAAF-CFG-001  Lane declaration that does nothing  [job triage]
        Job 'triage' sets OBAAF_LANE to 'agnet', which is not a lane (untrusted, agent, effect, release, trusted), so the declaration changes nothing.
```

What is reported, and where:

| The declaration | Reported in |
| --- | --- |
| `OBAAF_LANE` in a job's `env` or the workflow's `env`, set to a value that is not a lane | the workflow |
| the variable in another spelling in a job's `env` or the workflow's `env`: any name that looks like `OBAAF_LANE` or is one letter from it, once case, spaces, separators, invisible characters and look-alike letters from other scripts are set aside (`obaaf_lane`, `OBAAF-LANE`, `OBAAF.LANE`, `OBAAF_LANES`, `OBAAFLANE`, a Cyrillic `О`). A name that only holds it (`MY_OBAAF_LANE`) is not one | the workflow |
| `OBAAF_LANE` in a step's `env`, a `parallel` group's, a container's or a service's, whatever its value; also in another spelling (case `elsewhere`) | the workflow |
| the variable in any spelling where nothing reads it as a declaration (case `elsewhere`, or `workflow-elsewhere` outside the jobs): a key of a step's `with`, of the matrix, of a called workflow's `with` or of a `workflow_dispatch` input given a value; an `env` written as one expression that names it; a `run` script that writes it to `GITHUB_ENV`. A definition under the name (an input of `workflow_call` written as a mapping) is not a declaration | the workflow |
| `OBAAF_LANE` in a Jenkinsfile, in an `environment` block or a `withEnv` that reaches at least one step, set to a value that is not a lane or computed when the build runs | the Jenkinsfile |
| in a Jenkinsfile, the variable in another spelling in an `environment` block or a `withEnv` (`jenkins-misnamed`), and an assignment to it in a script, `env.OBAAF_LANE = 'agent'` in any spelling (`jenkins-scripted`) | the Jenkinsfile |
| a `lanes:` entry whose value is not a lane | the configuration file |
| a `lanes:` entry that names a job or Jenkins stage its file does not have, or a file that is not there. A stage written without a block (`stage 'Build'`) holds no step, and an entry for it is reported | the configuration file |
| a `lanes:` entry whose key is not text (`5:`, `true:`) | the configuration file |

The line is the line the declaration is written on. One that reaches a job or a step through a YAML alias or a merge key (`<<:`) is reported on the first line of that job or step. One entry can be two findings: `'ci.yml#wrok': agnet` has a value that is not a lane and names a job that is not there.

**Severity.** The finding is high. The checker cannot know which findings are missing because of the declaration, and the agent lane alone has high-severity rules, so anything lower would let a gate set to `--fail-on high` pass a job whose agent rules never ran. It is low where nothing can be missing: the declaration names `trusted`, which adds no rule even where it is read; it is written where it is not read, or under another spelling, in a job that is in the lane it names anyway; or it is a `lanes:` entry for a Jenkins stage that is not there and names `untrusted` or `effect`, which change nothing on a stage. If the job later leaves that lane the finding becomes high, and a baseline entry that accepted it at low no longer covers it.

**Fixing it.** Correct the value, spell the variable `OBAAF_LANE`, move it to the job's `env`, correct the `lanes:` key, or delete the declaration. For a workflow the key is the path and job that `obaaf check . --lanes` prints (`.github/workflows/ci.yml#build`). For a Jenkinsfile it is the file and the stage's own name (`Jenkinsfile#Ship`, or `Jenkinsfile#Outer > Inner`), without the word `stage` that `--lanes` prints before it. A finding in a Jenkinsfile names what the declaration reaches by the same labels: a stage by its name, a method that nothing in the file calls as `name()`, a `post` block as `post always`. One label differs: steps outside any stage are `pipeline` in `--lanes` and under `lanes:`, and the empty text (`""`) in the finding's `stages`, because a stage may itself be named `pipeline`. `--lanes` prints these declarations too, as notes, because it lists lanes and reports no findings.

**Accepting it: with a baseline entry, not an `ignore` entry.** A baseline entry carries an owner, a reason and an expiry date, and names the declaration it accepts: the file it is written in, the job and step for one in a workflow, the names of the stages it reaches for one in a Jenkinsfile, the `lanes:` key for one in the configuration, the variable's name where that is misspelt, and the value it was set to. Change any of them and it is another finding. Two declarations that agree in all of them (two steps of the same name with the same stray declaration) need an entry each. Two Jenkins stages with the same label are one stage to the checker, here as in `--lanes` and under `lanes:`, so a declaration moved from one to the other is the same finding. The label is the stage's name with the stages it is nested in (`Outer > Inner`), so a stage that is itself named `Outer > Inner` shares it. A `lanes:` key that is not text and a text key spelled the same (`true:` and `'true':`) are one finding too; neither names a file. A value, key or name longer than 200 characters is identified by its length and SHA-256 digest, so that a baseline stays readable. An `ignore` entry cannot do this: it accepts a rule in a file, whatever the finding says, so one entry for the configuration file would accept every `lanes:` entry that does nothing, including ones written later. An `ignore` entry that names `OBAAF-CFG-001` is therefore a configuration error, and the check does not run.

**The configuration file's path.** A finding about a `lanes:` entry names the configuration file from the directory every other path in the report is given from: `.github/obaaf.yml` when a repository is checked, and `../obaaf.yml` when one workflow is checked on its own with `--config .github/obaaf.yml`, because that workflow is `ci.yml` in the same report. A baseline written for one of those two ways of running the check therefore does not accept the finding in the other, as it does not for the findings in the workflow itself.

**Not reported.** A lane variable set by a command the checker does not read as writing `GITHUB_ENV`, or written in a file a step sources. (Until flagship slice 2d.2f, a Jenkinsfile's other spellings and `env.OBAAF_LANE = ...` were not reported either, and a second configuration file was ignored without a word.)

**Agent command patterns** (`agents.commands`) are searched anywhere in a `run` script, a github-script script and the `run` of OBAAF's egress action. In other places a step can give a command (another action's inputs, a `docker://` step's entrypoint and arguments, `shell`, `env` values), a pattern counts only where it matches at the start of a command, after assignments, wrappers such as `sudo` or `npx`, and a shell's `-c` (flagship slice 2d.2f), so that free text in an input is not taken for an agent.

**One configuration file.** The checker reads `.github/obaaf.yml`, `.github/obaaf.yaml` or `obaaf.yml` at the root. Two of them, or a file named like a configuration where the checker does not look (`.obaaf.yml`, `obaaf.yaml` at the root, `OBAAF.yml` in any letter case, at the root or in `.github`), stop the check with a configuration error (exit status 2), because the lanes, acceptances and protected secrets in the file it does not read would otherwise be dropped without a word.

`obaaf check . --lanes` shows the first lane a job is in, in the order agent, effect, release, untrusted, and names the others after it: `ci.yml#ship: agent (uses openai/codex-action; also release: uploads or publishes artifacts)`.

## Authority and hygiene

Every rule is one of two categories, reported separately in the summary and in the SARIF output (as `obaaf-category`):

- **authority**: who or what can change, build, release or sign, and the controls that bound an agent's authority. These are the findings to gate on first.
- **hygiene**: pinning and hardening. Today these are `OBAAF-GHA-008` (pin actions and images to a digest) and `OBAAF-GHA-020` (restrict agent egress). They matter, but they should not bury the authority findings, and a pilot does not need to clear every one to be a success.

Gate CI on one category with `--fail-on`:

```bash
obaaf check . --fail-on authority:medium   # fail only on authority findings at medium or above
```

`--fail-on` also accepts a plain severity (`high`, `medium`, `low`) or `never`. A bare category (`authority` or `hygiene`) means that category at low severity and above.

GHA-008 stays high for agent, release and effect jobs.
It is low for other jobs only when their token permissions are explicit and
limited, no secrets are referenced, and no privileged outside event can start
them. Other jobs retain medium pinning findings. Low severity still recommends
pinning; `--fail-on low` includes these findings.

Informational findings are included in text, JSON and SARIF, but do not fail any
severity threshold. SARIF records use their actual reported severity; a rule's
documented default is not necessarily the severity of each occurrence.

<a id="protected-secrets"></a>
## Protected secrets

List the secrets that must never be available outside an environment. Anyone with write access can read a repository secret by pushing a branch with a new workflow, so these belong in an environment limited to the default branch ([GitHub settings](github-settings.md#secrets)):

```yaml
# .github/obaaf.yml
protected_secrets:
  PYPI_TOKEN: release          # must be used only by jobs in the `release` environment
  PRIVATE_SET_TOKEN: private-set
```

A plain list (`protected_secrets: [PYPI_TOKEN]`) accepts any declared environment. Names are case-insensitive and may use `*` and `?` globs, with at least three letters or digits (`*_API_KEY`, not `*_*`). When several entries match a secret, every one applies. OBAAF-GHA-024 is reported, at high severity, for every job that uses a listed secret without the named environment, including jobs that can take every secret (`toJSON(secrets)`, or `secrets[...]` with a computed index). Environment names compare case-insensitively, as GitHub does. An environment named by an expression is reported at medium, because the checker cannot tell which environment it will be.

Run `obaaf check . --settings path/to/settings.json` to use the evidence in a file saved by `obaaf audit --snapshot-out`. The checker makes no network request. It prints the snapshot’s UTC timestamp and an assessment of each `protected_secrets` entry on standard error; only a literal secret name with a literal environment can be verified on that line, and a glob or a plain-list entry is “cannot tell” there. The environment control of OBAAF-GHA-005 includes the date and evidence for the concrete secret names each job reads: each name is assessed in the environment the job declares, when `protected_secrets` names that environment for it, so a secret matched by a glob entry such as `*_API_KEY: main-only` can be verified there, and one matched only by a plain-list entry cannot. A repository scan checks the snapshot path for code ownership alongside configuration and baseline files. On a full repository scan, a snapshot with no matching code owner raises OBAAF-REPO-001 separately (medium, so a gate at medium fails unless it is accepted). The settings evidence can still report verified: the assessment is independent of that finding. A single-file scan, a lane listing, or a snapshot outside the checked repository (including a link from outside to a file inside it) leaves the assessment at “cannot tell” because those cases omit that ownership check. A path through a linked folder counts by where the file really is, which is the path the ownership check reads.

Evidence must come from the checked github.com repository and be at most 30 days old. A missing identity, future date, incomplete inventory or unread policy leaves the answer unknown. For selected branches, every policy must name a literal branch observed as protected. For GitHub’s “protected branches only” mode, the snapshot must also show that a classic branch protection rule exists, because without any rules GitHub permits all branches to deploy. [GitHub deployment branches and tags](https://docs.github.com/en/actions/reference/workflows-and-actions/deployments-and-environments#deployment-branches-and-tags)

A job that calls a reusable workflow (`uses:` at job level) cannot declare an environment. Passing it a protected secret is reported, with the advice to declare the environment in the called workflow's job instead. `secrets: inherit` is not reported, because it passes repository and organization secrets only, never an environment's.

The checker refuses a configuration with a setting it does not know, so a misspelt key such as `protected-secrets` cannot turn a rule off silently.

The rule checks the workflow files against what you declared. It cannot see that the secret has actually been removed from the repository and organization, or that the environment's deployment branches are limited, so check those in the settings.

<a id="lifecycle"></a>
## What happens to a finding

Every finding is in one of four states. JSON output gives the state of each finding as `state`. The text report prints a line under a finding when there is something to say about it: who accepted it and until when, why an entry that names it does not count, or what was established about its controls. A finding with no such line is new. Findings ignored by configuration are listed at the end, one line each, with who accepted them and until when. Every report [begins with the accepted risk](#accepted-risk).

| State | What it means | Does it fail the check? |
| --- | --- | --- |
| **new** | Nobody has decided anything about it, or the decision does not count (see below). | Yes, at or above `--fail-on` |
| **accepted** | A valid acceptance names it: an [ignore entry](#ignore) or a [baseline entry](#baseline) with an owner, a reason and an expiry date. | No, until the date passes |
| **fixed** | Every control that clears the finding was read and verified by the checker. It is listed at the end of the report with the controls. | No |
| **cannot tell** (`cannot-tell` in JSON) | No control that would clear it is known to be missing, but the checker could not read what decides at least one of them. | Yes. The checker never assumes a control it cannot read. |

Two rules report controls: a secret in an agent job (OBAAF-GHA-005) and an agent job with no egress restriction (OBAAF-GHA-020). Every other finding is new or accepted.

<a id="controls"></a>
### Controls that clear a finding

Under a finding that has controls the report lists each one with a verdict:

- **verified**: the checker read what decides it, and it holds.
- **not met**: the checker read it, and it does not hold.
- **cannot tell**: the checker could not read what decides it. This is never treated as a pass.

A finding is fixed when every control is verified. If none is known to be missing and at least one could not be read, the finding is "cannot tell". If any is not met, it is new. Controls do not change which finding an acceptance names, so a finding can be accepted whatever its controls say.

```text
.github/workflows/agent.yml
     5  HIGH   OBAAF-GHA-005  Secret available to an agent job  [job agent]
        Agent job 'agent' receives MODEL_API_KEY.
        Controls (it is cleared when all 5 are verified):
          verified     each of the job's secrets is listed in protected_secrets, and the job declares the environment named there (MODEL_API_KEY in environment 'main-only')
          cannot tell  the secrets are stored only in that environment, and only protected branches may use it (where a secret is stored and which branches may use environment 'main-only' are repository settings, which obaaf check does not read; obaaf audit reads environments and their branch rules)
          verified     no pull request, issue or comment starts the job, and its checkout steps and the event fields it reads take nothing from one (started only by workflow_dispatch; 1 checkout step(s) take the ref the event names)
          not met      a control the checker recognises limits the job's network access to an allow-list (no blocking egress control in the job)
          not met      the agent's command cannot read any of the job's secrets: each goes only to a proxy that holds it for the command, or to nothing the command runs (no step of the job runs the agent's command behind a proxy that holds its keys, so the agent runs where the job's secrets are and can read them, or reach them through what it leaves for later steps. A key the agent can read can leave in the job's log or an artifact whatever the network allows)
```

**OBAAF-GHA-005 cannot be cleared today**: its second control now accepts a qualifying audit snapshot, but its fifth control, since slice 2c.7, can be verified only for a job whose secrets all go to OBAAF's egress action's API proxy at a listed commit, and none is listed yet. **OBAAF-GHA-020 can be**, by GitHub's native egress firewall, and by OBAAF's egress action once OBAAF lists a released commit of it (none is listed yet). Until a finding is cleared, the controls say what is in place and what is missing, and the finding is accepted with an owner, a reason and an expiry date, or it fails the check. JSON output gives the controls of each finding as `controls`, each with an `id` that stays the same when the wording changes.

What each control is, and what the checker reads to decide it:

| Control (`id`) | Verified when | Not met when | Cannot tell when |
| --- | --- | --- | --- |
| `secrets-protected` | Every secret the job references matches an entry in [`protected_secrets`](#protected-secrets), and the job declares the environment the entry names (any environment, for an entry that names none). This is what OBAAF-GHA-024 checks for the secrets that are listed. | A secret is not listed; the job can take every secret (`toJSON(secrets)`, `secrets[...]`, `secrets: inherit`); the job declares no environment, or another one; the job calls a reusable workflow, which cannot declare an environment. | The job's environment is an expression, is not written as text (a number, true or false, a list or a mapping: YAML readers do not agree on how numbers are spelt), or differs from the one named only in the case of letters outside ASCII. |
| `environment-restricted` | The selected snapshot establishes exclusive storage of every named secret in its required environment and protected-branch-only access. | The job declares no environment or calls a reusable workflow, so its secrets come from the repository or organization; or complete evidence contradicts exclusive storage or branch restrictions. | Missing, stale, partial or inapplicable evidence. The finding includes the observation date and reason when a snapshot is selected. |
| `no-outsider-input` | Only `push`, `workflow_dispatch`, `schedule` or `release` can start the job; every `actions/checkout` step takes the ref the event names or one written out in the workflow; and no `${{ }}` in the job, and no `if:` of the job or its steps, reads a field someone without write access can write (the fields OBAAF-GHA-010 lists). | A pull request, an issue, a comment or another outsider's event can start the job, a run that follows any other run included; a checkout step names a pull request's ref; a script uses a command the checker knows to fetch a pull request's code (`gh pr checkout`, `gh pr diff`, `git fetch` or `git pull` of `pull/N/head`, a `.patch` address); an expression or condition reads such a field (a commit message, for example). | Another event can start the job (`workflow_call`, `repository_dispatch`, `merge_group`, a run that the job's `if:` limits to runs started by `push`, `release`, `workflow_dispatch` or `schedule`), or no event was found; a checkout names another repository or a ref computed when the job runs, or takes its inputs from an expression; the job calls a reusable workflow. |
| `egress-enforced` | One of two controls holds, [as below](#egress-controls): GitHub's native egress firewall, or OBAAF's egress action around the agent's command. | The control the job has is read and does not hold: no blocking control, one behind an `if:`, a monitor that does not start first, or only a declaration in `OBAAF_EGRESS`; and each case marked "not met" below. | The control the job has cannot be read to the end: each case marked "cannot tell" below. Harden-Runner and the Agent Workflow Firewall run from a script are never better than this. |
| `key-out-of-reach` (since slice 2c.7) | Every secret of the job (`GITHUB_TOKEN` aside, which is OBAAF-GHA-003's, as it is for this finding's list of secrets) is set in the `env` of steps that use OBAAF's egress action and goes to AWF's API proxy (named in `model-keys`) or to nothing the command runs (named in neither input), as [the egress action's reading](#egress-controls) places it; each such step uses the action at a commit OBAAF lists as released (**none is listed yet**, so today this is "cannot tell" at best), and the job runs on GitHub-hosted `ubuntu-24.04` and not in a container. | A secret is passed to the command (named in `env`, or written into `run`, directly or through `${{ env.KEY }}`); a secret is given to another step, to the job outside its steps (its `env`, its `if:`) or to the workflow's `env`; the action would refuse to run; or no step uses the action, so the agent runs where the job's secrets are. GitHub's native firewall limits the network and holds no key, so a job on it is "not met" here. Also, because the step that holds the key runs the action's own steps outside the sandbox with the key in their environment: an agent the checker recognises in a step that can run before or beside it (earlier, in its `parallel` group, or beside a `background` step), a credential (`github.token` included) given to such a step, or a job that can request OIDC tokens or gives its token the `models` permission, any of which may put the agent outside the sandbox before it. | A secret the checker cannot place (an input or an `env` computed when the job runs, a secret in another input); the action at a tag, a branch or an unlisted commit, for a step that holds a key or one that runs before or beside it; another runner, or a container; `ACTIONS_ALLOW_UNSECURE_COMMANDS`, which lets any line a step prints set a variable for the steps after it, in any letter case or with space around it, or a key written as an expression, in the workflow's, the job's or the step's `env` or the `env` of a step before or beside it, or an `env` computed when the job runs; a step before or beside it whose script (its `run`, or an `actions/github-script` script), its `env` values or its inputs have the words `GITHUB_ENV`, `exportVariable` or the runner's `_runner_file_commands` file (any case), or a word that may leave a process running (the same words as for the egress control below: `&` as an operator, `nohup`, `setsid` and the others), or that runs beside it; service containers given volumes or options; a job that does not declare its token's permissions; a key that reaches neither the proxy nor the command, with no agent recognised in the confined command and a step before or beside it, where an agent that needs no key could run; the Agent Workflow Firewall run from a script, whose API proxy may hold a key; a job that calls a reusable workflow. Steps after it are not read for this control: the step's process has ended. Since slice 2c.10b (decision D-070) these no longer count: bash's variables (`BASH_ENV`, `ENV`, `SHELLOPTS`, `BASHOPTS`, `PS4`, `IFS`, `BASH_FUNC_…`), Python's (`PYTHONPATH`, `PYTHONSTARTUP`, `PYTHONHOME`), the `PATH`, the loader's (`LD_PRELOAD`, `LD_LIBRARY_PATH`, `LD_AUDIT`) in an `env`, and a step before it whose script writes `GITHUB_PATH`, calls `addPath` or names `BASH_ENV` ([#139](https://github.com/Obaaf/OBAAF/issues/139)): at every commit that can be listed the action's steps are Python by its full path, isolated and without `site`, start every program with a fixed `PATH` and nothing else of the environment, and empty the loader's variables in their own `env`, which outranks the job's, the workflow's and `GITHUB_ENV` (the escape tests' `own-steps` job; [the action's page](egress-control.md), item 12). Since slice 2c.11b (decision D-072, after D-070 and D-071) a name that begins `OPENSSL_` no longer counts either: slice 2c.10b had added them, because OpenSSL's configuration made libcrypto, which their Python loads for `hashlib`, load a module the job named into the process that holds the key, and at every commit that can be listed (from slice 2c.11a's change, `cc2ba59`, the floor) `egress.py` removes every such variable from its own process before that import (the escape tests' `openssl-modules` job). |

What the third control does not read, so that "verified" is not taken for more than it is. Its name says what it covers: the events, the checkout steps and the event fields. It does not cover what a script, an action other than `actions/checkout` or the agent itself fetches while the job runs (issue text fetched with `gh`, a web page, a pull request fetched by a command the checker does not know); a workflow that starts this one with `workflow_dispatch` and passes on text an outsider wrote; a value another job hands over through `needs.*.outputs`; or the content of a local action.

Why the fifth control (decision D-055): a limit on the network protects data, and protects a key the agent can read less than it seems, because the agent can print the key to the job's log, which whoever can read the run can read (GitHub hides a secret's exact value there, and the agent can write it in any other form), or leave it in an artifact. So the fourth control alone does not make a key in the agent's hands safe, and the fifth asks whether the agent's command can read the key at all. Where it cannot, because the key is held by AWF's API proxy, the command can still use the key through the proxy: it can make the provider act for it (calls charged to the key, remote MCP servers, URLs the provider fetches), and the step that uses the action holds the key in its own process, outside the sandbox. The control's detail says both beside a verified verdict, and says where each credential given to the action goes whatever the verdict. What it does not read: what an action used before the step that holds the key leaves running or writes to `GITHUB_ENV`; what a script file run before it writes there, or a write or a detached process spelt so that none of the words above appear (`subprocess.Popen(..., start_new_session=True)`, a variable that builds the name `GITHUB_ENV`); what the install scripts of a package an accepted install step (slice 2c.8) installs do, as root under `sudo`, before the step that holds the key; the `pre:` step of an action used later in the job, which runs when the job starts; and a variable such as `ACTIONS_ALLOW_UNSECURE_COMMANDS` that an earlier step sets for the steps after it in a way the checker does not see (an action's own `exportVariable`, say). No other variable counts, set that way or in an `env` (slice 2c.12, issue [#198](https://github.com/Obaaf/OBAAF/issues/198), decision D-075): from the floor on, the action's steps fix in their own `env` what is read as they start and empty their environment before they read anything else, so they read nothing else a workflow can set for them ([the action's guide](egress-control.md), items 13 and 14). The second control also requires an explicit, qualifying audit snapshot.

<a id="egress-controls"></a>
#### What clears OBAAF-GHA-020

The checker reads every control the job might have and keeps the one that comes out best, because one real control is enough. Each is verified only where every condition below was read and holds (decision D-050).

- **GitHub's native egress firewall** covers every step of the job, post steps included, from outside the runner's virtual machine. *Verified* when every run of the job is on `ubuntu-24.04-firewall` and the repository's `.github/egress-firewall.yaml` sets `mode: enforce`. *Not met* when the file is missing or spelt otherwise (the name is case sensitive), sets `mode: log`, or the job's token has no `contents` permission (the firewall's README: without `contents: read` no policy file is enforced, and there is no warning); or when some runs of a matrix are on another runner. *Cannot tell* when the file cannot be read to the end (not YAML, duplicate keys, a link, larger than 1,000,000 bytes, a merge key `<<`, which YAML 1.1 and 1.2 readers read differently, or U+0085, U+2028 or U+2029, which YAML readers do not agree are line breaks), it has a key other than the three the README describes (`mode`, `allow`, `no-default-urls`), or one of them in another letter case beside it (`MODE: log`), its mode is anything else, it allows an entry that is not a plain host name or that is or has under it a public suffix (the README does not say whether a name covers the names under it), other workflows can call this one (whose policy file then applies is not established), or a single workflow file was checked rather than a repository; and for a job on labels the checker cannot name, in a repository whose policy enforces, because a larger runner with the firewall image carries labels of its owner's choosing. The firewall is a technical preview, and the report says so beside a cleared finding, with the default endpoints it allows unless `no-default-urls: true` (`github.com`, `codeload.github.com`, and GitHub's own blob storage and Actions endpoints), that the runner is taken at its label (a self-hosted runner given the firewall's label would have no firewall), and what it does not stop: anything sent to an allowed host, printed to the job's log or saved as an artifact. The README was read again on 2026-11-15: enforcement (`mode: enforce`, deny by default) is in its technical preview, and older third-party pages that call the preview audit-only are out of date.
- **OBAAF's egress action** (`Obaaf/OBAAF/actions/egress`, [its page](egress-control.md)) confines one command, so it holds only for the command it runs. A copy of it in the repository (`./actions/egress`) is any repository's own action and is not taken for it. *Verified* when, for every step that uses it: the action is pinned to a commit OBAAF lists as released (**none is listed yet**, so today this is "cannot tell"); its `allow` is written out, and every entry is a host name the action accepts and none is, or has under it, a public suffix from the [public suffix list](https://publicsuffix.org/), private section included (a listed name covers every name under it, so `github.io`, or `amazonaws.com` with `s3.amazonaws.com` under it, would let in anyone's site); it gives a `run`; the job runs on GitHub-hosted `ubuntu-24.04`, the only runner the action was tested on, and not in a container; the agent is that command; and **no step but `actions/upload-artifact` can run after it or beside it**.
  - *The agent is that command* is read from where credentials go, because an agent needs a key and the checker recognises few agents by name. No other step, and no `env` of the job or the workflow, may be given in the workflow a secret (`GITHUB_TOKEN` included) or `github.token`; the job may not be able to request OIDC tokens (`id-token: write`), which any step can turn into a cloud credential, or give its token the `models` permission, which every action receives without being asked (`actions/checkout` takes it as its default `token`); and no other step may run an agent the checker recognises (by action, by command, or in a repository script). Since slice 2c.8, a step before the action that does nothing but install an agent's CLI globally and print its version is not taken for running it: every command in its script must be `npm install -g`, `pnpm add -g`, `yarn global add` or `bun add -g` of a package an agent tool's entry lists under `installs` (`@anthropic-ai/claude-code`, `@openai/codex` and `@google/gemini-cli` since slice 2c.8; `@github/copilot`, `@augmentcode/auggie`, `@continuedev/cli`, `@kilocode/cli` and `@qwen-code/qwen-code` since slice 2d.5b) (an `@version` allowed; options only from `-g`, `--global`, `--no-fund`, `--no-audit`, `--ignore-scripts`, `--silent`; `sudo` only with `-E`, `-H` or `-n`), or `--version` of a program those entries name (`claude --version`, `codex`, `gemini`, `copilot`, `auggie`, `cn`, `kilo`, `qwen`), in any order. The step must be a plain `bash` or `sh` step with no `env` or `working-directory`, the job and the workflow must set no `env` and no `defaults.run`, and the script may hold no `$`, quote, pipe, redirection, `&`, glob, backslash or trailing comment, because each of those can make the same words run something else. Not read, because the workflow does not show it: what earlier steps put in the environment (through `GITHUB_ENV`, `GITHUB_PATH` or files in the home directory), and package-manager configuration in the working directory, which `pnpm`, `yarn` and `bun` may read; either could make the install run something else. A step that names one of those packages in any other way is *cannot tell*, unless it also runs an agent (`claude -p`, `npx`, `npm exec`, `pnpm dlx`, `yarn dlx`, `bunx`, a path into the package such as `…/claude-code/cli.js`, and the other patterns), which is an agent outside, as is any such step after the action. A job that does not declare its token's permissions is "cannot tell": the repository's default is not read. A job in which no credential reaches the confined command or AWF's API proxy (below) is "cannot tell", unless the checker recognises the agent in the action's `run` input or in a script it runs, because an agent that needs no key could run in any step.
  - *Where the confined step's credentials go* (since slice 2c.5, decision D-052) is read as the action reads its inputs. A credential set in the step's `env` under a name its `model-keys` input names (`ANTHROPIC_API_KEY` or `OPENAI_API_KEY`) goes to AWF's API proxy, which the command can use and cannot read, and which reaches that provider's API host whatever `allow` says: the finding shows that host after the allow-list, as `api.anthropic.com (through AWF's API proxy)`, as one of the finding's facts. A credential set in the step's `env` under a name its `env` input names, or written in its `run` input, is passed to the command, which can send it to a listed host (and have that host act for it, if the credential lets it) or print it to the job's log. So is a credential of the step's `env` written into `run` through the `env` context (`${{ env.ANTHROPIC_API_KEY }}`), which GitHub fills with the step's own `env` when it writes the inputs, whatever `model-keys` says. Either is the evidence that the agent is the confined command, and neither stops the control from being verified: the network is limited as the allow-list (and the provider's host) says, and the report says the rest beside the cleared finding. That evidence is text the workflow's author writes (a credential in a comment in `run` counts), as all of D-050's evidence is. A credential set in the step's `env` under a name neither input names, and written into no input, reaches neither, and is no evidence. *Not met* when a name would make the action refuse to run in one of these ways: a model key, a GitHub token name or another name AWF withholds under `env`, a name `model-keys` does not take (another provider, another case), something that is not a variable name, a model key no `env` of the step, the job or the workflow sets, or, at a commit OBAAF lists, a name the action reserves under `env`, matched exactly as it matches them (`PATH`, `HOME`, `NODE_OPTIONS`, the proxy variables, a name beginning `AWF_`, `ACTIONS_` or `OTEL_`, a name ending `_BASE_URL` or `_API_TARGET`, and the rest of `RESERVED_NAMES`, `RESERVED_PREFIXES` and `RESERVED_SUFFIXES` in `actions/egress/egress.py`; since the review of A3a, review-gpt #283). Other ways the action refuses at run time are not read (a name under `env` set nowhere, an empty key, a line break in a value). *Cannot tell* when `env` or `model-keys` is computed when the job runs or is not written as text, the step's `env` is computed and holds a credential, a credential in it is set under a name that differs from another only in case or is not written as text (`true:`), the whole `env` context is written into `run` (`${{ toJSON(env) }}`), a credential is given anywhere else in the step (another input, a condition), or an `env` value holding one is written into another input. OBAAF-GHA-005's fifth control (fourth until slice 2c.7) says, whatever its verdict, where each credential the checker could place goes, what it could not place, and what would make the action refuse. The checker reads the inputs as the action does from the merge of slice 2c.4 on, the action keeps the runner's sockets in `/tmp` and the copy's links out of the command's reach from slice 2c.6's last change to it (`7c1bded`), and its own steps run no shell, look nothing up through the `PATH`, empty the loader's variables and fail when the run step reports nothing from slice 2c.9's (`c1b590c`, decision D-069), remove every `OPENSSL_` variable before libcrypto loads from slice 2c.11a's (`cc2ba59`, decision D-071), and start in a fixed locale and time zone and empty their environment before they read anything else from slice 2c.12b's last change to the action (`f3b50d4`, decision D-075), so only commits at or after `f3b50d4` may be listed as released (`egress_action_floor` in `src/obaaf/data/detection.yaml`; a test refuses an older one, and one whose own steps differ from the floor's where the verdicts rest on them; slices 2c.11b and 2c.12b).
  - *No step but `actions/upload-artifact` after it*: any other step that can run after it or beside it (a script, `git` in the copy, another action) could run or load what the command wrote with the full network, and the checker cannot tell reading from running, so it is "cannot tell". Steps before it are read too, for what their post steps or the processes they leave running could reach: a step that names `/tmp`, the scratch directory (`obaaf-egress`) or the action's outputs is "cannot tell", and so is one that may leave a process running: `&` as an operator, or any mention of `nohup`, `setsid`, `disown`, `daemonize`, `start-stop-daemon`, `systemd-run`, `coproc`, `batch`, `at` followed by a time word, a digit or an option (not a quoted or computed time), a container engine (`docker`, `docker-compose`, `podman`, `podman-compose`, `nerdctl`) or a terminal multiplexer (`screen`, `tmux`), detached or not, because shell can detach one in more spellings than the checker could list; and service containers given volumes or options. The whole script is searched, comments and quoted text included, so a word in a comment adds a "cannot tell" rather than hiding one. `actions/cache` with such a path, anywhere in the job, is *not met*: its post step saves after the job, for a later run to load.
  - *Not met* also when the allow-list has a name the action refuses, or `allow` or `run` is missing. A cleared finding says what the action does not stop: anything sent to a listed host, the credentials passed to the command included; data in a name under a listed name, which leaves the runner in a DNS query to that name's DNS servers (since slice 2c.4, a name the proxy refuses does not leave the runner); with a model key, anything the command sends the provider through AWF's API proxy, and whatever the provider is asked to fetch or connect to for it (remote MCP servers, URLs), since the proxy refuses only the providers' hosted web search and fetch tools; and anything the command prints to the job's log or leaves for a later `actions/upload-artifact` step to save, which whoever can read the run's logs and artifacts can read.
- **Harden-Runner** (`step-security/harden-runner`) runs beside the job, on the same machine. *Not met* when it is not the job's first step on its own, runs behind an `if:`, is a release before v2.16.0 by its commit (which fixed two published bypasses of the block policy), leaves `sudo` or containers to the job (`disable-sudo-and-containers` is not `true`; `disable-sudo` alone keeps Docker, from which a step can undo its rules), or the job runs in a container on a GitHub-hosted runner, where its source at v2.16.0 sets up nothing. Its version is read only from a commit OBAAF lists with the release it was tagged as on 2026-11-13, never from a tag or a comment beside a commit; a tag or an unlisted commit is "cannot tell" whatever it says. Otherwise it is *cannot tell*, always: whether the repository is public, or covered by a paid tier (the free tier does not cover private repositories), is not in the workflow. It is also "cannot tell" when its policy comes from StepSecurity's policy store (`policy:` or `use-policy-store:`; it falls back to audit mode on some errors in fetching it), or on a runner that is not GitHub-hosted. Its source at v2.16.0 also switches block mode to audit when it cannot reach its cache (`src/setup.ts`), which a workflow cannot show.
- **The Agent Workflow Firewall run from a script** (`awf ... --` where a command starts, outside what the checker takes for a comment, which follows `'` and `"` but not every form of shell quoting) is *cannot tell*: which AWF version runs, with which options, and whether the agent is the command it wraps are read from a shell command line, which the checker does not do well enough. With `--enable-dind` anywhere in such a script, comments included, which AWF's documentation says allows a bypass, it is *not met*.

What none of these reads: a control outside the workflow and the repository (a self-hosted runner behind a network policy, which an ignore entry with an owner, a reason and an expiry date records); a process an earlier step leaves running in a form the checker does not recognise (`sudo -b`, `systemctl start`, a program that detaches itself), or an earlier action's post step that finds the scratch directory without being given it; a key kept in a configuration variable (`vars.`) or handed from another job's outputs (`needs.*.outputs`), which the checker does not count as a credential; whether the confined command can reach a service container of the job (the escape tests did not try); and whether the hosts on an allow-list can be trusted with what the agent sends them.

A baseline entry that accepts OBAAF-GHA-020 for a control the checker cannot verify (a monitor, the firewall, OBAAF's action or AWF) is for the workflow file as it stood, byte for byte; the finding shows the first 32 characters of the file's SHA-256, and for the firewall the policy file's as well. Any later change to that file makes the finding a new one, to be looked at again. That is blunt on purpose: the checker cannot verify the control, so it does not judge which changes to it matter. An [ignore entry](#ignore) names the rule, the file and the job and holds until its date; use one if the finding should stay accepted while the file changes.

Which events can start a job is read from the tokens of the job's `if:`. Only a comparison of `github.event_name` with a text (`==` or `!=`, either way round), on its own or joined to other conditions by `&&` and `||`, rules an event out. A negation, a comparison of a comparison, a function, and words inside a string rule nothing out. An `if:` that has `${{ }}` and anything outside it, even a space or the line break of a `|` block, is a text to GitHub and is always true, so it rules nothing out either. In a workflow that other workflows call, `github.event_name` is the caller's event, so no test rules `workflow_call` out. A job that needs another job is limited to the events that job runs on, unless its `if:` has `always(`, `failure(` or `cancelled(` anywhere in it, or `success()` anywhere but as one of the conditions joined by `&&`.

Input names under `with:` are read with A to Z in either case, as GitHub reads them: `REF:` is the `ref` input. A step that gives the same input twice in two spellings is reported as an error, because the checker cannot tell which value GitHub uses. So is an input name with a letter outside ASCII, because it is not established what GitHub's upper-casing makes of one.

### An acceptance needs an owner, a reason and an expiry date

Accepting a finding is a decision somebody makes for a while. The checker enforces three things about it, in an ignore entry and in a baseline entry alike:

- **an owner**: a user (`@octocat`), a team (`@my-org/build`) or an e-mail address, the forms a CODEOWNERS file takes. The checker checks the form only. It cannot tell whether the account exists, or that `@tbd` is nobody.
- **a reason**, in words. The checker cannot judge a reason. It refuses one with fewer than four letters or digits, which rules out an empty one, a dot, `n/a` and `tbd`, and nothing more: `aaaa` is a reason to the checker, and so are four letters of a script whose letters look like punctuation.
- **an expiry date** (`YYYY-MM-DD`) that has not passed and is at most 366 days ahead. An acceptance is looked at again at least once a year; a date of 2999 would be a permanent acceptance with a date on it.

An entry that lacks one of these, has expired, or is dated too far ahead accepts nothing. Its finding counts as new and fails the check like any other, and the report says under the finding what the entry lacks:

```text
    12  HIGH   OBAAF-GHA-005  Secret available to an agent job  [job triage]
        Agent job 'triage' receives MODEL_API_KEY.
        Not accepted: the baseline entry that names this finding does not count, because it expired on 2026-10-01.
```

<a id="accepted-risk"></a>
### The report begins with the accepted risk

An accepted finding does not fail the check, so a gate can be green with any amount of accepted risk behind it. The first thing each report says is therefore how much is accepted, at what severity, by whom and until when. "0 new" comes after that.

```text
Accepted risk: 38 finding(s) are accepted and do not fail the check (19 high, 19 low).
  @my-org/build: 36 (18 high, 18 low); the first expires 2027-03-31
  @octocat: 2 (1 high, 1 low); the first expires 2026-12-01
  36 accepted by baseline entries, 2 by ignore entries in the checker configuration.
  Nearest expiry: 2026-12-01 (in 19 days).
Expiring soon: 2 acceptance(s) expire within 30 days, the first on 2026-12-01 (in 19 days). From the day after its date an accepted finding counts again and can fail the check: fix it, or renew the acceptance in a reviewed change.
  2026-12-01  @octocat  OBAAF-GHA-005 .github/workflows/agent.yml:12 [job triage]  (ignore entry)
  2026-12-01  @octocat  OBAAF-GHA-020 .github/workflows/agent.yml:12 [job triage]  (ignore entry)
Other findings: 0 new, 0 cannot tell, 0 fixed by controls the checker verified.
```

What the lines mean:

- **Accepted risk** counts the findings whose state is accepted, whether a baseline entry or an ignore entry accepted them. A finding named by an entry that does not count is not accepted: it is counted as new, or as cannot tell when it has controls and none of them is known to be missing. With nothing accepted the line reads `Accepted risk: none.`
- **One line for each owner**, with the number of findings they accepted, by severity, and the first date on which one of their acceptances runs out. The owner who accepted most comes first. Two spellings are one owner when they differ only in the case of the letters A to Z, because `@Octocat` and `@octocat` are one account to GitHub, or in how an accented letter is stored; the owner is shown as spelt on the first of their findings in order of file and line. Nothing else is merged: the checker does not know that two different names are one person, and it does not add up two addresses that only look alike. The text report lists ten owners and says how many more there are; JSON lists all of them.
- **Expiring soon** lists the acceptances that run out within 30 days, the soonest first, ten at most in text. An acceptance is valid on its date and stops on the day after. Nothing else warns: on that day the finding counts again, and a gate that passed fails. `--expiry-warning DAYS` changes the window, and `--expiry-warning 0` turns the list off. The list never changes the exit status.
- **Other findings** gives the other three states in one line: new, cannot tell, and fixed.
- **Baseline entries that no longer match a finding** and **Errors**, when there are any, are each counted in one more line, because both can fail a check whose findings are all accepted. The entries are listed further down and the errors straight after these lines. Something the checker could not read fails the check whatever `--fail-on` says.

These counts cover all severities. Use the exit status to see whether the check passed at your chosen threshold.

The days are counted from the day the check ran (`asOf` in JSON), and every acceptance in a report is judged on that one day, also when the check crosses midnight. The lines the report had before are still there, below these, with four differences. A finding ignored by configuration is listed with its owner (`ignored: RULE path:line - accepted by OWNER until DATE: REASON`). The `obaaf baseline migrate` command printed for an old baseline repeats the options the check was given, where a line told the reader to add them. Where a file's path heads its findings, a character that does not print (a line break, a tab, a no-break space) is written as an escape, as everywhere in the report; the path is then printed without quotes only if what is left is made of visible ASCII characters and nothing else (letters, digits and punctuation, no space), and in quotes otherwise. Every line of text that the checker writes in its own words has a space in it and none begins with a quotation mark, so a directory named like a line of the report cannot pass for one, whether it is written with spaces or with characters that only look blank. And the Jenkins coverage lines show a line break or another character that does not print as an escape, as the rest of the report already did. The older line `Baseline: N finding(s) accepted by the baseline, M new.` is unchanged, and its "new" is every finding the baseline does not accept, the ones the checker cannot tell about included, so M can be larger than the count of new findings in the first lines.

**JSON** has the same numbers in `acceptedRisk`, before the findings: `asOf`, `total`, `bySeverity`, `bySource` (`baseline` and `ignore`), `owners` (each with `owner`, `total`, `bySeverity` and `nearestExpiry`), `nearestExpiry`, `daysToNearestExpiry`, and `expiringSoon` (`withinDays`, `total`, and `findings`, each with its rule, severity, path, line, job, owner, expiry date, `daysLeft` and source). The `acceptance` of a finding has `daysLeft` when it is valid. Every field earlier versions wrote is still there under the same name.

The full text report ends with an action list before its version line. Run `obaaf check . --summary` for the accepted risk and the list, with any scan errors, an old-format baseline and stale-entry warnings. It is a text view: it refuses `--format json` or `sarif`, `--lanes` and `--write-baseline`. Use the same configuration, baseline, platform, settings snapshot and gate threshold as the original check. The text and summary carry an explicit snapshot path into their suggested `obaaf check` commands, including baseline writing. Lane commands in text and JSON use the same check inputs: a finding's fix and a JSON to-do item's `nextAction` end with `Lane check:` and the command. If a path cannot be shown faithfully on one line, the advice names `obaaf check --lanes` instead, to run with the original arguments. A check of one workflow file lists its jobs by file name (`build.yml#build`); write a `lanes:` key as the path from the repository root that `obaaf check . --lanes` prints, which a check of one file given that configuration with `--config` also matches.

The JSON report also has a `todo` list. Each outstanding finding counts once. An invalid acceptance groups under its reason, and other findings group by the action they need. Each entry gives the cause ID, kind, sentence, count, `bySeverity`, `fixKind` and `nextAction`. The `command` contains the suggested invocation when the CLI supports that operation. A manual step has a null command; its `nextAction` may still end with a command to inspect something, such as `Lane check:` and the lane listing. A `previousMatches` count means stale entries share the rule, path and job of findings in this group. Those entries accept nothing. For changeable tool versions, `pinCandidates` counts recognizable package installs and `byHand` counts the rest. A candidate still needs an explicit version and a proven patch before it can be applied. An install written once under a YAML anchor and reached through aliases is by hand, because one edit changes every step that reaches it. The list holds findings only: a baseline entry that no longer matches and a file the checker could not read can fail the gate with an empty list, and they are listed elsewhere in the report.

**SARIF** says it in four places, because readers of SARIF differ in what they read:

- The run's `properties` hold `obaaf-accepted-risk`, the same object as `acceptedRisk` in JSON, and `obaaf-summary`.
- The run's `invocations[0].toolExecutionNotifications` begins with the accepted risk as a sentence. After it come, when there are any: a warning for acceptances expiring soon, one error for each thing the checker could not read (and `executionSuccessful` is then `false`), a warning for a baseline in the old format and for each baseline entry that no longer matches a finding, and the notes.
- An accepted finding is a result with a suppression: `"suppressions": [{"kind": "external", "status": "accepted", "justification": "Accepted by @my-org/build until 2027-03-31: ..."}]`, and the owner, reason, date and days left as data in `properties` under `obaaf-acceptance`. Every other result has `"suppressions": []`, which is how SARIF says a result is not suppressed; that includes a finding named by an entry that does not count.
- The result's message says the same in words after the finding's own sentence, then why an entry does not count, then the controls with their verdicts. The controls are also data, in `properties` under `obaaf-controls`.

**What GitHub code scanning shows of this.** GitHub's page on [its SARIF support](https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning) (read on 2026-11-12) lists the fields code scanning uses, and says the rest are ignored. Suppressions, invocations and their notifications, `baselineState`, and the property bags of a run and of a result are not on the list. So, going by that page, an accepted finding uploaded to code scanning is an open alert like any other, and what tells a reader that it was accepted is the sentence in its message; the accepted-risk total, the expiry warning, the notes and a file that could not be read are not shown there at all. No upload was made to check this. Two things follow. Dismissing an alert in GitHub and accepting a finding in OBAAF are separate records, and only the second has an expiry date that fails a gate. And a team that reads only code scanning should keep the step that runs `obaaf check` able to fail, because that is how a file the checker could not read shows: the command exits 1 for one whatever `--fail-on` says.

<a id="baseline"></a>
## Adopting the checker without hiding regressions

A project that adopts the checker with existing findings usually starts in reporting mode (`--fail-on never`). Reporting mode lets new findings in unnoticed. A baseline keeps the existing findings visible while failing on anything new. [From a report to a gate](from-report-to-gate.md) has the whole path, one step at a time; [Upgrading](upgrading.md) has what changes when you move to a newer OBAAF. The command:

```bash
# record today's findings, once, in somebody's name
obaaf check . --write-baseline .github/obaaf-baseline.json \
  --owner @my-org/build --reason "Inherited on adoption; tracked in issue 12" --expires 2027-03-31
obaaf check . --baseline .github/obaaf-baseline.json --fail-on low
```

With `--baseline`, a finding that a valid baseline entry accepts is still reported, with who accepted it and until when. It is marked `(baseline)` in text, `"baselined": true` and `"state": "accepted"` in JSON, and `baselineState: unchanged` with an accepted [suppression](#accepted-risk) in SARIF, and it does not fail the check. Every other finding at or above `--fail-on` fails it. So does a baseline entry at or above `--fail-on` that no longer matches any finding: run `--write-baseline` again and commit the result, so the improvement is locked in and the finding cannot come back unnoticed.

An entry looks like this:

```json
{
  "rule": "OBAAF-GHA-005",
  "severity": "high",
  "path": ".github/workflows/agent.yml",
  "job": "triage",
  "kind": "secrets",
  "facts": { "secrets": ["MODEL_API_KEY"] },
  "owner": "@my-org/build",
  "reason": "Inherited on adoption; tracked in issue 12",
  "expires": "2027-03-31"
}
```

What an entry accepts:

- **Exactly the finding its fields describe**: the rule, the file, the job and step, which of the rule's cases it is (`kind`), and the values it is about (`facts`: which secrets, which triggers, which action). There is no fingerprint beside the text, so the lines a reviewer reads in a diff are the acceptance. A job that receives one more secret is a different finding and counts as new.
- **Not its line number, and not the wording of a rule's message.** Moving code does not disturb a baseline, and neither does a release of OBAAF that words a rule's message differently. There are three exceptions, where text is the finding:
  - *OBAAF-GHA-003 (an agent job can write)*: why the job is an agent job is one of its facts, as the text the checker shows (`uses anthropics/claude-code-action`, `runs an agent CLI in 'Agent'`, `set by OBAAF_LANE`). When that text changes, the finding counts as new: another recognised action, a command in another step, a declaration added where the agent was recognised before, or a later release that words the reason differently. The text is not a description of the agent. Another command in a step of the same name, a second agent added after the first, and any change of agent in a job that is declared an agent job all leave it as it was, and the acceptance still covers the job. 0.3.0 behaved the same way.
  - *OBAAF-INS-001 (hidden characters)*: each character is a fact together with a digest of the line it is on. A line ends at a line feed or a carriage return and nowhere else: a form feed, a vertical tab or U+2028 does not end it. A line that moves up or down is the same finding. The same character with any other text on its line is another finding, because what a direction override does depends on the text beside it. Text on the lines before and after is not part of it, except for a direction control (U+202A to U+202E, U+2066 to U+2069 and the marks): its digest covers its whole paragraph, from the blank line before it to the next one, because rendered Markdown joins those lines and the control reorders them all (since slice 2d.2h). A file that is not UTF-8, or larger than 2,000,000 bytes, is one finding identified by a digest of its bytes.
  - *Jenkins findings* have no `kind` or `facts` yet. They are identified by their message (`"message": "..."` in the entry), line numbers in it included, so moving code or a change of wording does disturb them.
- **At the severity it was accepted at, or lower.** If the finding is now more severe than the entry says, the entry does not cover it.
- **One finding per entry.** Two findings that differ only in their line need two entries.
- **A step by its name.** A finding on a step names it by the step's `name`, else its `id`, else the action it uses, else its position (`step 3`). Give a name to a step that carries an accepted finding, or a step inserted above it makes the finding a new one.

Writing a baseline again never renews an acceptance by itself. Entries of the file being replaced that are still valid keep their own owner, reason and expiry date (and are written at the finding's present severity, if that is lower than it was). Only findings that no valid entry accepts are written with the `--owner`, `--reason` and `--expires` you give, and if there are any and you give none, nothing is written. So a diff of the baseline shows who accepted what, why, and until when, one entry at a time. `--write-baseline` replaces a baseline: it does not write over a file that exists and is not one. Findings already ignored by configuration are not written to the baseline. Findings whose ignore entry has expired or does not count are not newly accepted either: renew, complete or remove the entry instead. An entry for a finding that has since been given an ignore entry is not stale.

Since slice 3.2b `--write-baseline` ends as `obaaf check --baseline FILE` with the file it wrote and the same `--fail-on` would. It leaves out a finding an `ignore` entry names without counting, and one no entry can accept (`OBAAF-REPO-001` for a file that decides what the check accepts and has no code owner, the baseline being written included), lists each as a `not written:` line on standard error, and ends with 1 when one of them is at or above `--fail-on`; below it, a `warning:` and 0. The baseline is written either way. Give it the `--fail-on` your gate uses.

The baseline is a list of accepted risks, so review changes to it like changes to the workflows: put it under CODEOWNERS. Since slice 2d.2h `obaaf check --baseline FILE` reports `OBAAF-REPO-001` when the file is in the repository and has no code owner, and the same for the configuration, `.github/CODEOWNERS` and `.github/egress-firewall.yaml`; no ignore or baseline entry accepts that finding. Prefer an `ignore` entry for a finding you have decided does not apply.

<a id="baseline-migrate"></a>
### A baseline written by 0.2.0 or 0.3.0

Those versions wrote `obaaf-baseline/v0.1` files, whose entries name no owner, reason or expiry date. The file is still read, and each entry still finds its finding, but none of them accepts one: with `--fail-on low` the check fails until the file is converted. The report says so once, with the command, which repeats the `--config` and `--platform` the check was given:

```bash
obaaf baseline migrate .github/obaaf-baseline.json \
  --owner @my-org/build --reason "Inherited on adoption; tracked in issue 12" --expires 2027-03-31
```

`migrate` runs the check on the path you give after the file name (the current directory if you give none; use the path the baseline was written for), carries over the findings the old file covers that are still found and that a new baseline entry may accept, and gives them the owner, reason and date you state. It accepts nothing the old file did not cover, and tells you which old entries no longer match and how many findings are outside the baseline. It names each match it does not carry over and why: a finding no entry can accept (OBAAF-REPO-001 for a file that decides what the check accepts and has no code owner), a finding waiting on an ignore entry that has expired or is not valid, and, as a count, findings a valid ignore entry accepts. Among the findings outside the baseline it names those no entry can accept and those waiting on an ignore entry. When it can carry over no match and leaves at least one open, it writes nothing and exits 1. It replaces the file in place unless you give `--output`. Convert with the first version that has this command: an old entry matches on the exact wording of its finding, and later versions may word messages differently.

<a id="ignore"></a>
## When a finding does not apply

Suppress a finding you have reviewed with an expiring `ignore` entry. Every entry needs a rule, a path, an owner, a reason and an `until` date, and the path may not match everything:

```yaml
# .github/obaaf.yml
ignore:
  - rule: OBAAF-GHA-013
    path: .github/workflows/ci.yml
    job: build
    owner: "@my-org/build"
    reason: Reviewed fork selector and ephemeral runner lifecycle, see issue 42
    until: 2027-01-31
```

An ignore entry is an acceptance, so [the same three things](#lifecycle) are enforced. A configuration file whose entries have no `owner` (every file written for 0.3.0 or earlier) still loads, but those entries ignore nothing until an owner is added, and neither does an entry dated more than 366 days ahead; the report says which. An entry with no rule, path, reason or `until`, or with an `until` that is not a plain date (`YYYY-MM-DD`), is a configuration error and the check does not run.

This is also how to record a reviewed runner pool without suppressing findings
for other jobs. GHA-013 distinguishes:

- A known self-hosted pool, including a literal matrix containing one: high for
  untrusted or agent work.
- An unresolved expression explicitly naming both a standard hosted label and a
  self-hosted alternative: informational, because the selected runner is unknown.
- Other unknown labels or runtime inputs, such as `${{ inputs.runner }}`: medium.

The informational result does not certify a selector as fork-safe or a pool as
ephemeral. Verify where outside contributions execute and how the runner is
destroyed, then record evidence and a review expiry with an entry like the above.
Do not use an ignore entry merely to obtain a green check.

## Trying unreleased checker changes

If you installed OBAAF 0.3.0 from PyPI, use the [checker guide for v0.3.0](https://github.com/Obaaf/OBAAF/blob/v0.3.0/docs/checker-configuration.md).
The [unreleased changelog](../CHANGELOG.md#unreleased) lists changes since that release,
including the finding lifecycle, acceptance metadata and legacy baseline migration.
To try those changes, install a reviewed commit in a separate environment:

```bash
python -m pip install "obaaf @ git+https://github.com/Obaaf/OBAAF.git@<reviewed-full-commit-sha>"
obaaf check . --lanes
obaaf check . --fail-on never
obaaf check . --fail-on authority:medium
```

Replace the placeholder with the full SHA of the reviewed commit. Record that SHA
and the output of `obaaf --version`. Several commits can report the same development
version, such as `0.4.0.dev0`. When using templates bundled with a development
build, pass the commit you installed to `obaaf templates install --obaaf-sha`.
For GitHub Actions, `Obaaf/OBAAF/actions/setup-obaaf@<reviewed-full-commit-sha>`
installs that exact checkout using its dependency constraints. A new PyPI release
is a separate maintainer action after validation.

## Jenkins

Jenkinsfiles use the same file. `jenkins.files` adds pipelines with other names (globs from the
repository root), `jenkins.exclude` leaves out test fixtures, `agents.steps` names shared-library
steps that run an agent, and lane overrides and ignore entries name a stage as `file#stage` and
`job: <stage>`. See [Jenkins](jenkins.md).

## Egress

`OBAAF_EGRESS` records the egress policy an agent job is meant to run under. It documents intent, it is not enforcement. See `OBAAF-GHA-020`, [the controls the checker reads](#controls) and the agent lane templates for how egress is enforced.

## Reference

The full rule list, with the requirement and fix for each, is in [the pipeline checker rules](../spec/checker-rules.md).
