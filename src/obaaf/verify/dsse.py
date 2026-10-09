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

    payload = json.dumps(statement, separators=(",", ":"), sort_keys=True).encode("utf-8")
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
