# F5 Signing

Control family F5 protects the keys that make an update look like it came from the studio. Stolen code-signing certificates let attackers sign malware in a studio's name in the Winnti and APT41 campaigns. It covers profile requirements [G5.1](../../spec/profile.md#g51-hold-keys-in-hardware-or-a-key-service), [G5.2](../../spec/profile.md#g52-sign-only-artifacts-with-release-lane-provenance) and [G5.3](../../spec/profile.md#g53-plan-revocation-and-rotation).

This is draft guidance for OBAAF version 0.1. The studio pilot will test and revise it. Terms are explained in the [glossary](../glossary.md).

<a id="item-1-5"></a>
## Item 1.5: Key inventory

**Why.** After a theft, you can only revoke the keys you know about, and the time to revoke decides how long malware signed in your name stays trusted.

**Do this.** List every signing key, certificate and store upload credential, with:

- what it signs or uploads (for example Windows executables, Apple builds, Android uploads, a self-hosted patcher, a store account),
- where it is held (hardware token, cloud key service, platform-managed signing, or a file on a named machine),
- who can use it, and when it expires.

**Keep as evidence.** The inventory naming each key's location and authorized users.

<a id="item-2-3"></a>
## Item 2.3: Keys in hardware or a key service

**Why.** A key held in hardware, a cloud key service or platform-managed signing can be used but not copied (FR11). An intruder on a build machine can still use such a key while they are there, but cannot take it away, and revoking their access ends it.

**Do this.**

- Move each signing key out of files: into a hardware token, a cloud key service, or the platform's own signing. This covers every key that signs what players run: Windows code signing, Apple signing certificates, Android signing, and the key your own patcher checks (item 2.10).
- Where a platform signs for you, a key may remain on your side. With Google Play App Signing, Google holds the key that signs the distributed app, but you still hold an upload key ([Google](https://support.google.com/googleplay/android-developer/answer/9842756)), usually as a keystore file. That key belongs in a key service or hardware token too. Google can reset it if it is lost or stolen.
- Sign through the service from the release lane only, after the release is verified, so no build step can read or use the key. In OBAAF's templates, that is the marked step in the [publish workflow](../../templates/github-actions/workflows/obaaf-publish.yml); version 0.1 does not implement it for any platform yet. Signing changes the files, so attest the signed files as well.
- OBAAF's templates sign their own attestations through GitHub's Sigstore with the workflow's identity, using a certificate that is issued per job and expires within minutes, so no long-lived key exists for provenance. That does not sign the game itself.
- Check build hosts for leftover key files and remove them.
- Run `obaaf check`: rule `OBAAF-GHA-018` reports workflows that load key files or key secrets into build steps.

**Keep as evidence.** The key-service configuration, and a check of build hosts showing no key files.

<a id="item-2-9"></a>
## Item 2.9: Revocation plan

**Why.** When a key or account is stolen, the first hours matter. A written plan avoids working out under pressure who can revoke what.

**Do this.** For each entry in the key inventory (item 1.5), write down:

- who owns it, and a backup person,
- how to revoke or rotate it (for a certificate, the issuing authority's revocation process; for a store credential, how to reset it and remove sessions),
- whom to tell: the platform holders, your players if needed, and partners,
- how to rebuild and re-sign the current release with the new key.

**Keep as evidence.** The plan, with named owners.
