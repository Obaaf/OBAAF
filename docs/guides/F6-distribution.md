# F6 Distribution and updates

Control family F6 protects the accounts, servers and steps that put a build in front of players. Hijacked publishing accounts pushed malicious updates to released games in 2023, and one publisher's official update server delivered a trojan in 2013. It covers profile requirements [G6.1](../../spec/profile.md#g61-upload-from-a-dedicated-identity) to [G6.5](../../spec/profile.md#g65-updaters-verify-signatures).

This is draft guidance for OBAAF version 0.1. The studio pilot will test and revise it. Terms are explained in the [glossary](../glossary.md).

<a id="item-1-1"></a>
## Item 1.1: MFA on publishing accounts

**Why.** Developer publishing accounts were used to push malicious updates to released Steam games; Valve now requires confirmation by phone before a build goes live on a released game's default branch ([BleepingComputer](https://www.bleepingcomputer.com/news/security/steam-enforces-sms-verification-to-curb-malware-ridden-updates/)).

**Do this.**

- List every account that can publish builds: store partner portals, console portals, your own launcher's admin console, and the accounts behind them.
- Turn on multi-factor authentication for each, preferably with an authenticator app or security key rather than text messages where the platform allows.
- Remove publishing rights from accounts that no longer need them.

**Keep as evidence.** The security settings of each publishing account.

<a id="item-1-2"></a>
## Item 1.2: Dedicated upload account

**Why.** An upload identity that can only publish builds limits what a stolen pipeline credential can do. Steam recommends a dedicated build account for uploads ([Steamworks](https://partner.steamgames.com/doc/sdk/uploading)).

**Do this.**

- Create a separate account (or service account or API key) used only by your pipeline for uploads.
- Give it only the permissions uploads need. On Steam, that is a build account with the Edit App Metadata and Publish App Changes To Steam permissions for the one app, as the [steam-deploy action](https://github.com/game-ci/steam-deploy) documents, pointing to Steamworks' guidance on build accounts ([Steamworks: uploading](https://partner.steamgames.com/doc/sdk/uploading)). It needs no right to manage users, pricing or finances.
- Keep its credentials as secrets of the release environment only (see [F3 item 2.4](F3-build-execution.md#item-2-4)).

**Keep as evidence.** The account's permissions in the store's partner portal.

<a id="item-1-3"></a>
## Item 1.3: A person sets builds live

**Why.** If a pipeline can both upload and release to players, anyone who controls the pipeline can release to players. On Steam, setting a build live on a released game's default branch needs a confirmation by phone ([BleepingComputer](https://www.bleepingcomputer.com/news/security/steam-enforces-sms-verification-to-curb-malware-ridden-updates/)), and the steam-deploy action's documentation says that setting the default branch live from an upload "has been observed to not work" ([steam-deploy](https://github.com/game-ci/steam-deploy#releasebranch)).

**Do this.**

- Let automation upload builds only to testing or beta channels (for example a Steam beta branch, or a Google Play testing track).
- Have a person promote a build to the public channel in the store's interface, after checking the version and the release notes.
- Write the procedure down, so it holds when you are busy.

**Keep as evidence.** The release procedure and the store's release settings.

<a id="item-2-10"></a>
## Item 2.10: Updater checks signatures

**Why.** The 2013 Winnti campaign delivered malware through a publisher's official update server. Update systems survive a server compromise when the client checks signatures made with keys kept off the server ([The Update Framework](https://doi.org/10.1145/1866307.1866315)).

**Do this.**

- Make your launcher or patcher verify a signature on every update before applying it, with a public key built into the client.
- Keep the matching private key off every update server, in a key service or hardware token (see [F5](F5-signing.md#item-2-3)).
- Make it refuse updates older than the installed version, and signed update lists that have expired, so a compromised server cannot roll players back to a vulnerable version or keep them from seeing new ones. The Update Framework describes these rollback and freeze attacks.
- Test it: serve an update with a bad signature, and an older signed update, to a test client, and confirm both are rejected.
- Answer N/A only if you do not run your own launcher or patcher.

**Keep as evidence.** The updater code or vendor documentation, and the result of the bad-signature test.

<a id="item-2-12"></a>
## Item 2.12: Set-live and permission alerts

**Why.** Multi-factor authentication does not stop an attacker who has stolen a logged-in session, as in the Downfall mod case. Alerts do not stop the session either, but an alert when a build goes live, or when permissions change, lets you react within minutes.

**Do this.**

- Turn on whatever notifications each store offers for builds going live and for changes to publishing permissions, and send them to a shared channel that someone watches. Check what each store actually sends; do not assume.
- Where a store has no such notification, run a scheduled job that checks the live build through the store's API and alerts when it changes unexpectedly.
- Test the alert once, and keep the result.

**Keep as evidence.** The alert configuration and a recent alert.

<a id="item-3-8"></a>
## Item 3.8: Staged rollout and tested rollback

**Why.** Frequent, urgent updates leave little time for review. Releasing to a fraction of players first limits the damage of a bad update, and a tested rollback makes recovery fast.

**Do this.**

- Use the stage controls your platforms offer, such as percentage rollouts on Google Play, phased release on the App Store, or a public beta branch first on Steam. For your own launcher, release to a small percentage before everyone.
- Write down how to roll back on each platform (for example, setting the previous build live again, or halting a rollout and shipping a fixed version).
- Rehearse a rollback at least twice a year, and keep the record.

**Keep as evidence.** The rollout configuration and the record of a rollback test.

<a id="item-4-3"></a>
## Item 4.3: Two-person set-live

**Why.** One stolen session or one rushed person can still ship a bad build. Paper 2 (section 7.1 and Table 7) finds that when an attacker steals a developer's session, as in the Downfall case, multi-factor authentication does not help, because the attacker acts as the developer: only a two-person release prevents it. The same holds for the Chemia and BlockBlasters cases if an account was taken over; a publisher that ships malware on purpose is outside what a studio's self-assessment covers.

**Know what a pipeline gate covers.** A second approval in your pipeline gates only the pipeline's own upload. Someone holding a developer's session can still set a build live in the store's own interface, where no pipeline is involved. So answer yes only if every way of setting a build live on a public channel needs two people, including the store's interface.

**Do this.**

- Check whether each store you ship on can require two people to set a build live, and turn it on where it can. Many cannot.
- Where the store cannot, one option, not yet tested in the pilot, is to split the publishing account's factors between two people. One holds the password; the other holds the second factor that the store asks for when a build goes live (on Steam, the phone confirmation for a released game's default branch). Confirm with the store's documentation that the second factor is asked for at that moment, not only at sign-in. It weakens if the second factor can be moved to the first person, for example through a SIM swap or text messages synced to their computer, and it makes the account shared, which item 1.7 discourages; record why you accept that.
- Also gate the pipeline path. A GitHub environment proceeds after one approval, so chain two jobs that each use their own environment (for example `release-check` and `release`), each with required reviewers and self-review prevention. Then list both environments and set `min_approvals: 2` in [the release policy](../../templates/github-actions/obaaf-policy.example.yaml); the release verifier counts distinct approvers across them.
- Record both confirmations each time.

**Keep as evidence.** The release procedure, the store setting or the split of factors, and the approval records.
