# F2 Intake of third-party code, SDKs, and assets

Control family F2 treats everything that enters the project from outside as code: engines, SDKs, plugins, asset packs and partner deliveries. Many arrive from vendor portals rather than package registries, so ordinary dependency tools never see them. It covers profile requirements [G2.1](../../spec/profile.md#g21-keep-a-binary-manifest), [G2.2](../../spec/profile.md#g22-quarantine-third-party-assets-and-plugins) and [G2.3](../../spec/profile.md#g23-review-player-facing-sdks).

This is draft guidance for OBAAF version 0.1. The studio pilot will test and revise it. Terms are explained in the [glossary](../glossary.md).

<a id="item-1-8"></a>
## Item 1.8: SDK and plugin list

**Why.** You cannot review, update or remove what you do not know you ship. A marketing SDK with spyware features reached 101 Android apps and more than 421 million downloads.

**Do this.**

- List every third-party SDK and plugin that ships to players: name, version, where it came from, and who owns updating it.
- Keep the list in version control. The OBAAF manifest source file, `obaaf-sources.yaml`, can be this list (see item 2.6 and [the example](../../templates/github-actions/obaaf-sources.example.yaml)).
- Check the list against the current build before each release.

**Keep as evidence.** The list, matching the current build.

<a id="item-2-5"></a>
## Item 2.5: Asset and plugin quarantine

**Why.** Game assets and plugins can run code when they are opened. Unity runs editor code marked to run on launch whenever the editor starts or recompiles scripts ([Unity manual](https://docs.unity3d.com/6000.1/Documentation/Manual/running-editor-code-on-launch.html)). Malicious Blender files have carried scripts that run when the file is opened with automatic script execution on ([Morphisec](https://www.morphisec.com/blog/morphisec-thwarts-russian-linked-stealc-v2-campaign-targeting-blender-users-via-malicious-blend-files/)), and Godot scripts have been used to spread malware ([BleepingComputer](https://www.bleepingcomputer.com/news/security/new-godloader-malware-infects-thousands-of-gamers-using-godot-scripts/)).

**Do this.**

- Set up a quarantine machine or virtual machine with no source-control credentials, no store accounts and no access to build hosts.
- Open new asset packs, plugins and partner deliveries there first, in a throwaway project, with automatic script execution turned off in every tool that has the setting.
- Read the editor scripts a package contains (for example, anything in an `Editor` folder, or scripts that run when the editor loads) before the package enters the real project.
- Precompiled code cannot be read this way: Unity plugins shipped as DLLs, and Unreal plugins shipped as binaries, run when the editor loads them. Accept them only from the vendor's own channel, record their digests (item 2.6), prefer plugins that ship source, and watch the quarantine machine's network traffic and file changes while the editor loads them.
- Write the procedure down, and note each intake: what, when, who reviewed it.

**Keep as evidence.** The written procedure, the quarantine machine's settings, and the record of the latest intake.

<a id="item-2-6"></a>
## Item 2.6: Digest checks for vendored files

**Why.** A vendored binary can be replaced without anyone noticing, because a binary change looks like any other in review. A recorded digest turns an unrecorded change into a failed build (G2.1).

**Do this.**

1. Declare your vendored components (engine builds, SDKs, plugins, other binaries) in `obaaf-sources.yaml`, with the paths each one occupies.
2. Create the manifest: `obaaf manifest create --components obaaf-sources.yaml --out obaaf-manifest.json`, review it, and commit both files.
3. Add `obaaf manifest check --manifest obaaf-manifest.json` to every build. The [untrusted](../../templates/github-actions/workflows/obaaf-untrusted-ci.yml) and [release](../../templates/github-actions/workflows/obaaf-release.yml) templates already do.
4. When you update a component on purpose, regenerate the manifest in the same reviewed change.

**Keep as evidence.** The manifest file and the build step that checks it.

<a id="item-2-11"></a>
## Item 2.11: SDK behavior review

**Why.** A player-facing SDK runs on every player's device with the game's permissions. Its behavior can change with any update.

**Do this.**

- Before adopting an SDK, and before each update ships in a release build, record what data it collects, where it sends it, and what permissions it needs.
- Check the vendor's documentation and privacy terms, and observe a test build's network traffic to confirm the destinations.
- Store the review next to the SDK's entry in your list (item 1.8), with the version reviewed.

**Keep as evidence.** Review records for the SDK versions in the current build.
