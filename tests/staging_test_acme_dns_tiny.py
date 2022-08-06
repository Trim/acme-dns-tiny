"""Tests for acme_dns_tiny script to be run with real ACME server"""
import unittest
import sys
import os
import subprocess
import configparser
from io import StringIO
import dns.version
import acme_dns_tiny
from tests.config_factory import generate_acme_dns_tiny_config
from tools.acme_account_deactivate import account_deactivate

ACME_DIRECTORY = os.getenv("GITLABCI_ACMEDIRECTORY_V2",
                           "https://acme-staging-v02.api.letsencrypt.org/directory")
ACME_TIMEOUT = os.getenv("GITLABCI_ACMETIMEOUT", "10")


def _openssl(command, options, communicate=None):
    """Helper function to run openssl command."""
    with subprocess.Popen(["openssl", command] + options,
                          stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE) as openssl:
        out, err = openssl.communicate(communicate)
        if openssl.returncode != 0:
            raise IOError("OpenSSL Error: {0}".format(err))
        return out.decode("utf8")


class TestACMEDNSTiny(unittest.TestCase):
    """Tests for acme_dns_tiny.get_crt()."""

    @classmethod
    def setUpClass(cls):
        print("Init acme_dns_tiny with python modules:")
        print("  - python: {0}".format(sys.version))
        print("  - dns python: {0}".format(dns.version.version))
        cls.configs = generate_acme_dns_tiny_config()
        sys.stdout.flush()
        super(TestACMEDNSTiny, cls).setUpClass()

    # To clean ACME staging server and close correctly temporary files
    # pylint: disable=bare-except
    @classmethod
    def tearDownClass(cls):
        # close temp files correctly
        for conf_name, file in cls.configs.items():
            # for each configuration file, deactivate the account and remove linked temporary files
            if conf_name != "cname_csr":
                parser = configparser.ConfigParser()
                parser.read(file)
                try:
                    account_deactivate(
                        parser["acmednstiny"]["AccountKeyFile"], ACME_DIRECTORY, ACME_TIMEOUT)
                except:
                    pass
                try:
                    os.remove(parser["acmednstiny"]["AccountKeyFile"])
                except:
                    pass
                try:
                    os.remove(parser["acmednstiny"]["CSRFile"])
                except:
                    pass
            try:
                os.remove(file)
            except:
                pass
        super(TestACMEDNSTiny, cls).tearDownClass()

    # helper function to valid success by making assertion on returned certificate chain
    def _assert_certificate_chain(self, cert_chain):
        # Output have to contain at least two certificates to create a chain
        certlist = list(filter(None, cert_chain.split("-----BEGIN CERTIFICATE-----")))
        self.assertTrue(len(certlist) >= 2)
        for cert in certlist:
            self.assertIn("-----END CERTIFICATE-----", cert)
        # Use openssl to check validity of chain and simple test of readability
        readablecertchain = _openssl("x509", ["-text", "-noout"],
                                     cert_chain.encode("utf8"))
        self.assertIn("Issuer", readablecertchain)

    def test_success_cn(self):
        """Successfully issue a certificate via common name."""
        old_stdout = sys.stdout
        sys.stdout = StringIO()

        acme_dns_tiny.main([self.configs['good_cname'], "--verbose"])
        certchain = sys.stdout.getvalue()

        sys.stdout.close()
        sys.stdout = old_stdout

        self._assert_certificate_chain(certchain)

    def test_success_cn_without_contacts(self):
        """Successfully issue a certificate via CN, but without Contacts field."""
        old_stdout = sys.stdout
        sys.stdout = StringIO()

        acme_dns_tiny.main([self.configs['good_cname_without_contacts'], "--verbose"])
        certchain = sys.stdout.getvalue()

        sys.stdout.close()
        sys.stdout = old_stdout

        self._assert_certificate_chain(certchain)

    def test_success_cn_with_csr_option(self):
        """Successfully issue a certificate using CSR option outside from the config file."""
        old_stdout = sys.stdout
        sys.stdout = StringIO()

        acme_dns_tiny.main(["--csr", self.configs['cname_csr'],
                            self.configs['good_cname_without_csr'], "--verbose"])
        certchain = sys.stdout.getvalue()

        sys.stdout.close()
        sys.stdout = old_stdout

        self._assert_certificate_chain(certchain)

    def test_success_wild_cn(self):
        """Successfully issue a certificate via a wildcard common name."""
        old_stdout = sys.stdout
        sys.stdout = StringIO()

        acme_dns_tiny.main([self.configs['wild_cname'], "--verbose"])
        certchain = sys.stdout.getvalue()

        sys.stdout.close()
        sys.stdout = old_stdout

        self._assert_certificate_chain(certchain)

    def test_success_san(self):
        """Successfully issue a certificate via subject alt name."""
        old_stdout = sys.stdout
        sys.stdout = StringIO()

        acme_dns_tiny.main([self.configs['good_san'], "--verbose"])
        certchain = sys.stdout.getvalue()

        sys.stdout.close()
        sys.stdout = old_stdout

        self._assert_certificate_chain(certchain)

    def test_success_wildsan(self):
        """Successfully issue a certificate via wildcard in subject alt name."""
        old_stdout = sys.stdout
        sys.stdout = StringIO()

        acme_dns_tiny.main([self.configs['wild_san']])
        certchain = sys.stdout.getvalue()

        sys.stdout.close()
        sys.stdout = old_stdout

        self._assert_certificate_chain(certchain)

    def test_success_cli(self):
        """Successfully issue a certificate via command line interface."""
        with subprocess.Popen(["python3", "acme_dns_tiny.py",
                               self.configs['good_cname'], "--verbose"],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE) as cli:
            certout, _ = cli.communicate()
            certchain = certout.decode("utf8")
            self._assert_certificate_chain(certchain)

    def test_success_cli_with_csr_option(self):
        """Successfully issue a certificate via command line interface using CSR option."""
        with subprocess.Popen(["python3", "acme_dns_tiny.py", "--csr", self.configs['cname_csr'],
                               self.configs['good_cname_without_csr'], "--verbose"],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE) as cli:
            certout, _ = cli.communicate()
            certchain = certout.decode("utf8")
            self._assert_certificate_chain(certchain)

    def test_failure_dns_update_tsigkeyname(self):
        """Fail to update DNS records by invalid TSIG Key name."""
        self.assertRaisesRegex(RuntimeError,
                               "Unable to add DNS resource to _acme-challenge.{0}."
                               .format(os.getenv("GITLABCI_DOMAIN")),
                               acme_dns_tiny.main, [self.configs['invalid_tsig_name'],
                                                    "--verbose"])


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
