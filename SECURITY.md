# Security policy

OBAAF is a security framework, so flaws in it matter twice: in the tools themselves, and in the advice and templates studios copy.

## Reporting a vulnerability

Please do not open a public issue. While the repository is private, write to the maintainer directly. After public release, use GitHub's private vulnerability reporting for this repository.

Include what you found, how to reproduce it, and which file, template or rule is affected. You will get an acknowledgment within five working days.

## What counts

- A template that, used as documented, exposes a secret, a write token or a cache to untrusted input.
- A way to make `obaaf verify release` pass for an artifact, approval or agent record that should fail.
- A risky workflow pattern that `obaaf check` should report but does not (a false negative). False positives are ordinary bugs.
- Guidance in `docs/` or `spec/` that would weaken a studio's security if followed.

## Flaws found in other products

If testing OBAAF uncovers a flaw in a vendor's product, such as a CI platform or an AI agent, it is reported to that vendor before anything about it is published (responsible disclosure, as the specification requires).
