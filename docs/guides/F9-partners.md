# F9 Partners

Control family F9 limits what contractors and porting partners can reach. Console ports and outsourced work often go through third-party vendors, and a compromised partner account is as dangerous as a compromised employee account. It covers profile requirement [G9.1](../../spec/profile.md#g91-scope-and-expire-partner-access).

This is draft guidance for OBAAF version 0.1. The studio pilot will test and revise it. Terms are explained in the [glossary](../glossary.md).

<a id="item-2-8"></a>
## Item 2.8: Scoped partner access

**Why.** Separate, scoped access that expires limits what a stolen partner account can reach, and building partner work in the untrusted lane keeps it away from release credentials until someone reviews it.

**Do this.**

- Give every contractor and partner individual accounts (see [F1 item 1.7](F1-source-and-assets.md#item-1-7)), limited to the repositories, streams or folders their work needs.
- Record an end date for each grant, and review the list on that date. If your tools cannot expire access automatically, set a calendar reminder and keep the list current.
- Have partners contribute through pull requests from their own forks, which run in the [untrusted lane](../../templates/github-actions/workflows/obaaf-untrusted-ci.yml) with a read-only token and no secrets, never directly to release branches or release machines. Do not give partners write access to branches in your repository: a pull request from a branch in the same repository runs workflow files that its author can edit, and it receives the repository's secrets.
- Remove access as soon as an engagement ends.

**Keep as evidence.** The access list with an end date for each partner account.
