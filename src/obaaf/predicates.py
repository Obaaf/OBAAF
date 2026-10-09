"""Predicate type URIs for OBAAF's in-toto attestations.

These URIs are provisional. They use the reserved `.example` domain so that no
draft attestation can be mistaken for a released format, and they will change
before version 1.0, once the project has a domain it controls (DECISIONS.md,
D-007). Change them only here.
"""

STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
SLSA_PROVENANCE_V1 = "https://slsa.dev/provenance/v1"

AGENT_RUN = "https://obaaf.example/attestation/agent-run/v0.1"
AGENT_APPROVAL = "https://obaaf.example/attestation/agent-approval/v0.1"
BUILD_RECORD = "https://obaaf.example/attestation/build-record/v0.1"

OBAAF_TYPES = {"agent-run": AGENT_RUN, "agent-approval": AGENT_APPROVAL, "build-record": BUILD_RECORD}
SCHEMA_FOR_TYPE = {
    AGENT_RUN: "schemas/agent-run.schema.json",
    AGENT_APPROVAL: "schemas/agent-approval.schema.json",
    BUILD_RECORD: "schemas/build-record.schema.json",
}
