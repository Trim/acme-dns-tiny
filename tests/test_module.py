import unittest, sys
from subprocess import Popen, PIPE
from io import StringIO
import acme_dns_tiny
from .monkey import gen_configs
from .acme_account_delete import delete_account

CONFIGS = gen_configs()

class TestModule(unittest.TestCase):
    "Tests for acme_dns_tiny.get_crt()"

    def test_success_cn(self):
        """ Successfully issue a certificate via common name """
        old_stdout = sys.stdout
        sys.stdout = StringIO()
        result = acme_dns_tiny.main([CONFIGS['goodCName'].name])
        sys.stdout.seek(0)
        crt = sys.stdout.read().encode("utf8")
        sys.stdout = old_stdout
        out, err = Popen(["openssl", "x509", "-text", "-noout"], stdin=PIPE,
            stdout=PIPE, stderr=PIPE).communicate(crt)
        self.assertIn("BEGIN", crt.decode("utf8"))
        self.assertIn("Issuer", out.decode("utf8"))

    def test_success_san(self):
        """ Successfully issue a certificate via subject alt name """
        old_stdout = sys.stdout
        sys.stdout = StringIO()
        result = acme_dns_tiny.main([CONFIGS['goodSAN'].name])
        sys.stdout.seek(0)
        crt = sys.stdout.read().encode("utf8")
        sys.stdout = old_stdout
        out, err = Popen(["openssl", "x509", "-text", "-noout"], stdin=PIPE,
            stdout=PIPE, stderr=PIPE).communicate(crt)
        self.assertIn("BEGIN", crt.decode("utf8"))
        self.assertIn("Issuer", out.decode("utf8"))

    def test_success_cli(self):
        """ Successfully issue a certificate via command line interface """
        crt, err = Popen([
            "python3", "acme_dns_tiny.py", CONFIGS['goodCName'].name
        ], stdout=PIPE, stderr=PIPE).communicate()
        out, err = Popen(["openssl", "x509", "-text", "-noout"], stdin=PIPE,
            stdout=PIPE, stderr=PIPE).communicate(crt)
        self.assertIn("BEGIN", crt.decode("utf8"))
        self.assertIn("Issuer", out.decode("utf8"))

    def test_weak_key(self):
        """ Let's Encrypt rejects weak keys """
        try:
            result = acme_dns_tiny.main([CONFIGS['weakKey'].name])
        except Exception as e:
            result = e
        self.assertIsInstance(result, ValueError)
        self.assertIn("Key too small", result.args[0])

#     def test_invalid_domain(self):
#         """ Let's Encrypt rejects invalid domains """
#         try:
#             result = acme_dns_tiny.main([CONFIGS["invalidCSR"].name])
#         except Exception as e:
#             result = e
#         self.assertIsInstance(result, ValueError)
#         self.assertIn("Invalid character in DNS name", result.args[0])
# 
#     def test_nonexistant_domain(self):
#         """ Should be unable verify a nonexistent domain """
#         try:
#             result = acme_dns_tiny.main([CONFIGS["inexistantDomain"].name])
#         except Exception as e:
#             result = e
#         self.assertIsInstance(result, ValueError)
#         self.assertIn("urn:acme:error:connection", result.args[0])

    def test_account_key_domain(self):
        """ Can't use the account key for the CSR """
        try:
            result = acme_dns_tiny.main([CONFIGS['accountAsDomain'].name])
        except Exception as e:
            result = e
        self.assertIsInstance(result, ValueError)
        self.assertIn("Certificate public key must be different than account key", result.args[0])


if __name__ == "__main__":
    try:
        unittest.main()
    finally:
        # delete account key registration at end of tests
        delete_account(CONFIGS["key"]["accountkey"].name)
