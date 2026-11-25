"""Slice 2c.13: a name beginning `OPENSSL_` in an `env` of a step outside OBAAF's sandbox can make it run
code the checker did not read. Node.js, which runs every JavaScript action, initialises OpenSSL when it
starts and loads the configuration `OPENSSL_CONF` names, and the modules or engines that configuration
names, into the action's process (the review of #366 reproduced a library's constructor running on
Node.js 22). Slice 2c.11a found the same of the egress action's own Python, which drops those names
before it loads libcrypto; a JavaScript action does not drop them."""

import unittest

from obaaf.checker.rules import CANNOT_TELL, VERIFIED
from test_egress_recognised import SHA, egress, keyed, run_check, secret_finding, verdict, workflow

CHECKOUT = f"      - uses: actions/checkout@{SHA}\n        with: {{persist-credentials: false}}\n"


def controls(result):
    return {c.id: c.verdict for c in secret_finding(result).controls}


class OpenSslNamesTest(unittest.TestCase):
    def test_the_job_without_them_is_verified(self):
        result = run_check(workflow(CHECKOUT + keyed()))
        self.assertEqual(verdict(egress(result)), VERIFIED)
        self.assertEqual(controls(result)["key-out-of-reach"], VERIFIED)

    def test_an_openssl_name_on_a_step_outside_the_sandbox_is_cannot_tell(self):
        cases = {
            "the step's OPENSSL_CONF": (CHECKOUT + "        env: {OPENSSL_CONF: ./openssl.cnf}\n" + keyed(), ""),
            "the job's OPENSSL_MODULES": (CHECKOUT + keyed(), "    env: {OPENSSL_MODULES: ./m}"),
            "the workflow's, in lower case": (CHECKOUT + keyed(), None),
            "OPENSSL_ENGINES with a space": (CHECKOUT + "        env: {' OPENSSL_ENGINES ': ./e}\n" + keyed(), ""),
        }
        for name, (steps, job_extra) in cases.items():
            with self.subTest(name):
                top = "env: {openssl_conf: ./openssl.cnf}" if job_extra is None else ""
                result = run_check(workflow(steps, job_extra=job_extra or "", top=top))
                self.assertEqual(verdict(egress(result)), CANNOT_TELL, name)
                self.assertIn("can make it run code the checker did not read", egress(result).controls[0].detail)
                self.assertEqual(controls(result)["key-out-of-reach"], CANNOT_TELL, name)

    def test_names_that_only_begin_alike_are_not(self):
        for env in ("{OPENSSLCONF: x}", "{MY_OPENSSL_CONF: x}", "{SSL_CERT_FILE: /etc/ssl/certs/ca.pem}"):
            with self.subTest(env=env):
                result = run_check(workflow(CHECKOUT + f"        env: {env}\n" + keyed()))
                self.assertEqual(verdict(egress(result)), VERIFIED)


if __name__ == "__main__":
    unittest.main()
