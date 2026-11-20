"""Optional report-only companion scans for the Linux GitHub-hosted runner."""

# Upstream image manifests for linux/amd64. See docs/upgrading.md for the releases and verification.
SCANNERS = {
    "zizmor": (
        "ghcr.io/zizmorcore/zizmor@sha256:bb5d47cd29a3f534bbdfa49eaee3b1c8bfc3de3152ec6e4d73a678a129354e34",
        "--offline --no-config --no-exit-codes /source",
    ),
    "actionlint": (
        "docker.io/rhysd/actionlint@sha256:9d36088643581e728c969f35141f88139fec77280b2be23c1f66f8e40e1025e7",
        "-config-file /policy.yaml -shellcheck= -pyflakes=",
    ),
    "poutine": (
        "ghcr.io/boostsecurityio/poutine@sha256:0ae43043afd3d24957294cc5e19f12b9e0e8c7adc8b4c0504982ec3d0936ac03",
        "analyze_local /source --config /policy.yaml --disable-version-check",
    ),
}


def steps(selected: list[str]) -> bytes:
    """Append only selected steps, in stable order even when options are repeated or reordered."""
    out = []
    for name, (image, arguments) in SCANNERS.items():
        if name not in selected:
            continue
        script = [
            'token=$(cat /proc/sys/kernel/random/uuid)',
            'echo "::stop-commands::$token"',
            '''trap 'echo "::$token::"' EXIT''',
        ]
        if name != "zizmor":
            script += [
                'policy=$(mktemp "$RUNNER_TEMP/obaaf-scanner-XXXXXX.yaml")',
                "echo '{}' > \"$policy\"",
                'chmod 644 "$policy"',
            ]
        script += [
            # Pull first, so a Docker or registry failure fails the step on its own status. `docker run`
            # also exits 1 when it cannot reach the daemon, which actionlint's finding status would hide.
            f'docker pull --quiet {image} > /dev/null || exit "$?"',
            'status=0',
            'docker run --rm --network none --read-only --cap-drop ALL --security-opt=no-new-privileges ' + '\\',
            '  --user "$(id -u):$(id -g)" --tmpfs /tmp --env HOME=/tmp --workdir /source ' + '\\',
            '  --mount "type=bind,src=$GITHUB_WORKSPACE/source,dst=/source,readonly" ' + '\\',
        ]
        if name != "zizmor":
            script.append('  --mount "type=bind,src=$policy,dst=/policy.yaml,readonly" ' + '\\')
        script += [f'  {image} ' + '\\', f'  {arguments} || status=$?']
        if name == "actionlint":
            # Upstream documents 1 for lint findings, 2 and 3 for invocation and fatal failures.
            script += ['if [[ "$status" == 1 ]]; then status=0; fi']
        script += ['exit "$status"']
        out += ["", f"      - name: Report {name} findings", "        shell: bash", "        run: |",
                *("          " + line for line in script)]
    return ("\n".join(out) + "\n").encode() if out else b""
