"""Test acme_account_deactivate script with real ACME server"""
import unittest
import os
import configparser
import acme_dns_tiny
from tests.config_factory import generate_acme_account_deactivate_config
import tools.acme_account_deactivate

ACME_DIRECTORY = os.getenv("GITLABCI_ACMEDIRECTORY_V2",
                           "https://acme-staging-v02.api.letsencrypt.org/directory")


class TestACMEAccountDeactivate(unittest.TestCase):
    """Tests for acme_account_deactivate."""

    @classmethod
    def setUpClass(cls):
        cls.configs = generate_acme_account_deactivate_config()
        try:
            acme_dns_tiny.main([cls.configs['config']])
        except ValueError as err:
            if str(err).startswith("Error register"):
                raise ValueError("Fail test as account has not been registered correctly: {0}"
                                 .format(err)) from err

        super(TestACMEAccountDeactivate, cls).setUpClass()

    # To clean ACME staging server and close correctly temporary files
    # pylint: disable=bare-except
    @classmethod
    def tearDownClass(cls):
        # Remove temporary files
        parser = configparser.ConfigParser()
        parser.read(cls.configs['config'])
        try:
            os.remove(parser["acmednstiny"]["AccountKeyFile"])
        except:
            pass
        try:
            os.remove(parser["acmednstiny"]["CSRFile"])
        except:
            pass
        try:
            os.remove(cls.configs['config'])
        except:
            pass
        super(TestACMEAccountDeactivate, cls).tearDownClass()

    def test_success_account_deactivate(self):
        """ Test success account key deactivate """
        with self.assertLogs(level='INFO') as accountdeactivatelog:
            tools.acme_account_deactivate.main(["--account-key", self.configs['key'],
                                                "--acme-directory", ACME_DIRECTORY])
        self.assertIn("INFO:acme_account_deactivate:The account has been deactivated.",
                      accountdeactivatelog.output)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
