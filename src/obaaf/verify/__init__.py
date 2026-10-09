"""The OBAAF release verifier (`obaaf verify release`, FR6).

It decides whether release artifacts may be uploaded. It requires, for every
artifact, verified SLSA provenance and an OBAAF build record from the expected
signer; the release approvals the policy asks for; and, for every
agent-authored commit in the release range, a verified agent-run record and an
approval by someone other than the requester. Anything missing blocks the
upload.

Signatures are verified in one of two ways: by the GitHub CLI (`gh attestation
verify`, for Sigstore bundles from GitHub Actions) or, for studios that sign
with a key held in a cloud key service or hardware module, by checking DSSE
envelopes against the public key.
"""
