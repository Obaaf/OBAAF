"""Predicate type URIs for OBAAF's in-toto attestations.

The URIs live under www.obaaf.com, a domain the project controls (DECISIONS.md,
D-007). Each type URI resolves to a page that describes its format, and each
schema's `$id` resolves to the schema itself; site/build.py publishes both.
Change them only here.

OBAAF 0.1 used provisional `obaaf.example` URIs. Records signed with those URIs do
not verify under 0.2 or later; sign new records with the current templates.
"""

NAMESPACE = "https://www.obaaf.com"

STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
SLSA_PROVENANCE_V1 = "https://slsa.dev/provenance/v1"

AGENT_RUN = f"{NAMESPACE}/attestation/agent-run/v0.1"
AGENT_APPROVAL = f"{NAMESPACE}/attestation/agent-approval/v0.1"
BUILD_RECORD = f"{NAMESPACE}/attestation/build-record/v0.1"
GENERIC_BUILD_TYPE = f"{NAMESPACE}/buildtypes/generic/v0.1"

OBAAF_TYPES = {"agent-run": AGENT_RUN, "agent-approval": AGENT_APPROVAL, "build-record": BUILD_RECORD}
SCHEMA_FOR_TYPE = {
    AGENT_RUN: "schemas/agent-run.schema.json",
    AGENT_APPROVAL: "schemas/agent-approval.schema.json",
    BUILD_RECORD: "schemas/build-record.schema.json",
}
SCHEMA_ID = {
    AGENT_RUN: f"{NAMESPACE}/schemas/agent-run/v0.1.json",
    AGENT_APPROVAL: f"{NAMESPACE}/schemas/agent-approval/v0.1.json",
    BUILD_RECORD: f"{NAMESPACE}/schemas/build-record/v0.1.json",
}
