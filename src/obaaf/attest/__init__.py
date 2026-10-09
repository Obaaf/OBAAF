"""Generators for OBAAF's records: snapshot, agent run, approval, build record, manifest.

The generators write in-toto predicates (and optionally whole statements). In
the GitHub Actions templates the predicates are signed by actions/attest in a
job that holds the OIDC permission, so no long-lived key exists (FR11).
"""
