"""Dead Simple Signing Envelope (DSSE) verification with a public key.

Implements the DSSE v1 protocol: the signature covers
PAE(payloadType, payload) = "DSSEv1" SP LEN(type) SP type SP LEN(body) SP body.
Supported keys: ECDSA P-256 (SHA-256) and P-384 (SHA-384), Ed25519, and RSA
(PKCS#1 v1.5 or PSS with SHA-256). This covers keys held in cloud key services
and hardware modules, which sign without exposing the private key (FR11).
"""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

IN_TOTO_PAYLOAD_TYPE = "application/vnd.in-toto+json"


class SignatureError(ValueError):
    pass


def pae(payload_type: str, payload: bytes) -> bytes:
    type_bytes = payload_type.encode("utf-8")
    return b"DSSEv1 %d %s %d %s" % (len(type_bytes), type_bytes, len(payload), payload)


def _b64decode(value: str) -> bytes:
    value = value.strip()
    padded = value + "=" * (-len(value) % 4)
    try:
        if "-" in value or "_" in value:
            return base64.urlsafe_b64decode(padded)
        return base64.b64decode(padded, validate=True)
    except (ValueError, TypeError) as exc:
        raise SignatureError(f"invalid base64: {exc}") from exc


def extract_envelope(document: Any) -> dict:
    """Accept a bare DSSE envelope or a Sigstore bundle that carries one."""
    if isinstance(document, dict):
        if "payloadType" in document and "payload" in document:
            return document
        if isinstance(document.get("dsseEnvelope"), dict):
            return document["dsseEnvelope"]
    raise SignatureError("not a DSSE envelope or a bundle containing one")


@dataclass
class PublicKey:
    key: Any
    key_id: str
    source: str

    @classmethod
    def load(cls, path: str | Path) -> "PublicKey":
        from cryptography.hazmat.primitives import serialization

        data = Path(path).read_bytes()
        try:
            key = serialization.load_pem_public_key(data)
        except ValueError as exc:
            raise SignatureError(f"{path}: not a PEM public key ({exc})") from exc
        der = key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        return cls(key=key, key_id=hashlib.sha256(der).hexdigest(), source=str(path))

    def verify(self, signature: bytes, message: bytes) -> bool:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa

        try:
            if isinstance(self.key, ed25519.Ed25519PublicKey):
                self.key.verify(signature, message)
                return True
            if isinstance(self.key, ec.EllipticCurvePublicKey):
                algorithm = hashes.SHA384() if self.key.curve.key_size >= 384 else hashes.SHA256()
                self.key.verify(signature, message, ec.ECDSA(algorithm))
                return True
            if isinstance(self.key, rsa.RSAPublicKey):
                for pad in (padding.PKCS1v15(), padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                                              salt_length=padding.PSS.AUTO)):
                    try:
                        self.key.verify(signature, message, pad, hashes.SHA256())
                        return True
                    except InvalidSignature:
                        continue
                return False
        except InvalidSignature:
            return False
        raise SignatureError(f"unsupported key type in {self.source}")


def verify_envelope(document: Any, keys: list[PublicKey]) -> tuple[dict, PublicKey]:
    """Verify a DSSE envelope with any of the keys; return (in-toto statement, key used)."""
    envelope = extract_envelope(document)
    if envelope.get("payloadType") != IN_TOTO_PAYLOAD_TYPE:
        raise SignatureError(f"unexpected payloadType {envelope.get('payloadType')!r}")
    payload = _b64decode(envelope["payload"])
    message = pae(envelope["payloadType"], payload)
    for sig in envelope.get("signatures", []):
        signature = _b64decode(sig.get("sig", ""))
        for key in keys:
            if key.verify(signature, message):
                try:
                    statement = json.loads(payload)
                except ValueError as exc:
                    raise SignatureError(f"signed payload is not JSON: {exc}") from exc
                return statement, key
    raise SignatureError("no signature verifies with the trusted keys")


def sign_envelope(statement: dict, private_key: Any, key_id: str = "") -> dict:
    """Create a DSSE envelope. For tests and offline experiments only: in a pipeline, sign
    through a key service or hardware module so no build step can read the key (FR11)."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519

    payload = canonical_payload(statement)
    message = pae(IN_TOTO_PAYLOAD_TYPE, payload)
    if isinstance(private_key, ed25519.Ed25519PrivateKey):
        signature = private_key.sign(message)
    elif isinstance(private_key, ec.EllipticCurvePrivateKey):
        algorithm = hashes.SHA384() if private_key.curve.key_size >= 384 else hashes.SHA256()
        signature = private_key.sign(message, ec.ECDSA(algorithm))
    else:
        raise SignatureError("sign_envelope supports Ed25519 and ECDSA keys")
    return {
        "payloadType": IN_TOTO_PAYLOAD_TYPE,
        "payload": base64.b64encode(payload).decode("ascii"),
        "signatures": [{"keyid": key_id, "sig": base64.b64encode(signature).decode("ascii")}],
    }


# ------------------------------------------------------------- signing through a key service
# A pipeline signs with a key it cannot read: a cloud key service or a hardware module signs
# the bytes, and OBAAF builds the envelope around the signature. `prepare` writes what to sign;
# `assemble` checks the returned signature against the public key before writing the envelope,
# so a wrong key or a corrupted signature fails in the pipeline, not at release time.

def canonical_payload(statement: dict) -> bytes:
    """The exact payload bytes OBAAF signs for a statement (also used by sign_envelope)."""
    return json.dumps(statement, separators=(",", ":"), sort_keys=True).encode("utf-8")


def to_sign(statement: dict) -> bytes:
    """The DSSE pre-authentication encoding: the bytes a key service signs."""
    return pae(IN_TOTO_PAYLOAD_TYPE, canonical_payload(statement))


def _decode_signature_file(data: bytes) -> bytes:
    """Signatures arrive as raw bytes, or as base64 text (`aws kms sign --output text`)."""
    text = data.strip()
    if text and all(c in b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=-_\r\n" for c in text):
        try:
            return _b64decode(text.decode("ascii"))
        except SignatureError:
            pass
    return data


def _ecdsa_der(signature: bytes, key: Any) -> bytes:
    """Accept an ECDSA signature as DER or as raw r||s (IEEE P1363, which some key services return)."""
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

    if not isinstance(key, ec.EllipticCurvePublicKey):
        return signature
    size = (key.curve.key_size + 7) // 8
    if len(signature) == 2 * size:      # may also be valid DER: assemble tries the bytes as given first
        r = int.from_bytes(signature[:size], "big")
        s = int.from_bytes(signature[size:], "big")
        return encode_dss_signature(r, s)
    return signature


def assemble(statement: dict, signature: bytes, public_key: PublicKey) -> dict:
    """A DSSE envelope for `statement` with a signature made elsewhere; raises SignatureError unless
    the signature verifies with `public_key`."""
    payload = canonical_payload(statement)
    message = pae(IN_TOTO_PAYLOAD_TYPE, payload)
    raw = _decode_signature_file(signature)
    for candidate in (raw, _ecdsa_der(raw, public_key.key)):
        if public_key.verify(candidate, message):
            return {
                "payloadType": IN_TOTO_PAYLOAD_TYPE,
                "payload": base64.b64encode(payload).decode("ascii"),
                "signatures": [{"keyid": public_key.key_id, "sig": base64.b64encode(candidate).decode("ascii")}],
            }
    raise SignatureError(f"the signature does not verify with {public_key.source}: wrong key, wrong algorithm, "
                         "or a statement that changed after it was prepared")
