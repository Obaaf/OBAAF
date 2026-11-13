"""Signature keys: only the kinds OBAAF documents are loaded, and every other kind is refused with an error
that names the file, never a traceback (slice 2d.6 of the flagship plan).

Found by the review of #113: `PublicKey.load` took any key `load_pem_public_key` returned and `verify` ran
ECDSA on any curve, choosing the hash by the curve's size; and a binary-curve key, which the cryptography
library cannot load at all since its version 47, raised `UnsupportedAlgorithm` out of `load`.
"""

from __future__ import annotations

import json
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa, x25519

from helpers import TempDir, run_cli
from obaaf.verify import dsse, release

# A public key on the binary curve sect283k1, made with `openssl ecparam -name sect283k1 -genkey` and
# `openssl ec -pubout`. Recent versions of the cryptography library cannot load it.
SECT283K1 = b"""-----BEGIN PUBLIC KEY-----
MF4wEAYHKoZIzj0CAQYFK4EEABADSgAEABZeD6WIixSjcoL8ekspQa+99tFIYWZF
k5N2ZCWnqGeymDbqB1t2TtewjRhwiLYBRsmXr/WZNLgiawx0pnNTDnwUoJ1T3MO3
-----END PUBLIC KEY-----
"""


def public_pem(private_key) -> bytes:
    return private_key.public_key().public_bytes(serialization.Encoding.PEM,
                                                 serialization.PublicFormat.SubjectPublicKeyInfo)


UNSUPPORTED = {
    "secp521r1.pem": (lambda: ec.generate_private_key(ec.SECP521R1()), "the curve 'secp521r1'"),
    "secp256k1.pem": (lambda: ec.generate_private_key(ec.SECP256K1()), "the curve 'secp256k1'"),
    "dsa.pem": (lambda: dsa.generate_private_key(2048), "DSAPublicKey"),
    "ed448.pem": (lambda: ed448.Ed448PrivateKey.generate(), "Ed448PublicKey"),
    "x25519.pem": (lambda: x25519.X25519PrivateKey.generate(), "X25519PublicKey"),
}


class LoadTest(unittest.TestCase):
    def test_every_kind_outside_the_documented_set_is_refused_and_named(self):
        with TempDir() as tmp:
            for name, (make, what) in UNSUPPORTED.items():
                path = Path(tmp) / name
                path.write_bytes(public_pem(make()))
                with self.assertRaises(dsse.SignatureError, msg=name) as caught:
                    dsse.PublicKey.load(path)
                message = str(caught.exception)
                self.assertIn(name, message)
                self.assertIn(what, message)
                self.assertIn("supported: ECDSA P-256 and P-384, Ed25519 and RSA", message)

    def test_a_key_the_library_cannot_load_is_refused_not_raised(self):
        with TempDir() as tmp:
            path = Path(tmp) / "sect283k1.pem"
            path.write_bytes(SECT283K1)
            with self.assertRaises(dsse.SignatureError) as caught:
                dsse.PublicKey.load(path)
            self.assertIn("sect283k1.pem", str(caught.exception))

    def test_the_documented_kinds_load(self):
        with TempDir() as tmp:
            for name, make in (("p256.pem", lambda: ec.generate_private_key(ec.SECP256R1())),
                               ("p384.pem", lambda: ec.generate_private_key(ec.SECP384R1())),
                               ("ed25519.pem", ed25519.Ed25519PrivateKey.generate),
                               ("rsa.pem", lambda: rsa.generate_private_key(65537, 2048))):
                path = Path(tmp) / name
                path.write_bytes(public_pem(make()))
                self.assertEqual(dsse.PublicKey.load(path).source, str(path))

    def test_text_that_is_not_a_key_is_still_not_a_pem_public_key(self):
        with TempDir() as tmp:
            path = Path(tmp) / "junk.pem"
            path.write_bytes(b"not a key\n")
            with self.assertRaisesRegex(dsse.SignatureError, "not a PEM public key"):
                dsse.PublicKey.load(path)


class VerifyTest(unittest.TestCase):
    def check(self, curve, right, wrong):
        private = ec.generate_private_key(curve)
        with TempDir() as tmp:
            path = Path(tmp) / "k.pem"
            path.write_bytes(public_pem(private))
            key = dsse.PublicKey.load(path)
        message = b"DSSEv1 test"
        self.assertTrue(key.verify(private.sign(message, ec.ECDSA(right)), message))
        self.assertFalse(key.verify(private.sign(message, ec.ECDSA(wrong)), message))

    def test_p256_is_verified_with_sha256_and_p384_with_sha384_only(self):
        self.check(ec.SECP256R1(), hashes.SHA256(), hashes.SHA384())
        self.check(ec.SECP384R1(), hashes.SHA384(), hashes.SHA256())

    def test_a_key_on_another_curve_built_without_load_is_refused_by_verify(self):
        other = ec.generate_private_key(ec.SECP521R1())
        key = dsse.PublicKey(key=other.public_key(), key_id="x", source="built by hand")
        with self.assertRaisesRegex(dsse.SignatureError, "unsupported curve 'secp521r1' in built by hand"):
            key.verify(b"sig", b"message")


class CommandTest(unittest.TestCase):
    def test_dsse_assemble_refuses_such_a_key_with_a_message(self):
        with TempDir() as tmp:
            tmp = Path(tmp)
            statement = tmp / "statement.json"
            statement.write_text(json.dumps({"_type": "https://in-toto.io/Statement/v1", "subject": []}),
                                 encoding="utf-8")
            (tmp / "sig.bin").write_bytes(b"\x00" * 64)
            for name, data in (("sect283k1.pem", SECT283K1),
                               ("secp521r1.pem", public_pem(ec.generate_private_key(ec.SECP521R1())))):
                (tmp / name).write_bytes(data)
                code, out, err = run_cli("dsse", "assemble", "--statement", str(statement), "--signature",
                                         str(tmp / "sig.bin"), "--public-key", str(tmp / name),
                                         "--out", str(tmp / "out.json"))
                self.assertEqual(code, 1, name)
                self.assertIn("error: ", err)
                self.assertIn(name, err)
                self.assertNotIn("Traceback", err)
                self.assertFalse((tmp / "out.json").exists())

    def test_a_release_policy_key_of_another_kind_stops_loading(self):
        with TempDir() as tmp:
            path = Path(tmp) / "ed448.pem"
            path.write_bytes(public_pem(ed448.Ed448PrivateKey.generate()))
            with self.assertRaisesRegex(dsse.SignatureError, "ed448.pem: a key of the kind 'Ed448PublicKey'"):
                release.load_keys([path])


if __name__ == "__main__":
    unittest.main()
