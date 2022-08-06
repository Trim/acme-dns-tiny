"""Test acme_account_rollover script with real ACME server"""
import unittest
import os
import configparser
import acme_dns_tiny
from tests.config_factory import generate_acme_account_rollover_config
from tools.acme_account_deactivate import account_deactivate
import tools.acme_account_rollover

ACME_DIRECTORY = os.getenv("GITLABCI_ACMEDIRECTORY_V2",
                           "https://acme-staging-v02.api.letsencrypt.org/directory")
ACME_TIMEOUT = os.getenv("GITLABCI_ACMETIMEOUT", "10")


class TestACMEAccountRollover(unittest.TestCase):
    """Tests for acme_account_rollover."""

    @classmethod
    def setUpClass(cls):
        cls.configs = generate_acme_account_rollover_config()
        acme_dns_tiny.main([cls.configs['config']])
        super(TestACMEAccountRollover, cls).setUpClass()

    # To clean ACME staging server and close correctly temporary files
    # pylint: disable=bare-except
    @classmethod
    def tearDownClass(cls):
        # Remove temporary files
        parser = configparser.ConfigParser()
        parser.read(cls.configs['config'])
        try:
            # deactivate account key registration at end of tests
            # (we assume the key has been rolled over)
            account_deactivate(
                cls.configs["new_account_key"], ACME_DIRECTORY, ACME_TIMEOUT)
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
            os.remove(cls.configs["new_account_key"])
        except:
            pass
        try:
            os.remove(cls.configs['config'])
        except:
            pass
        super(TestACMEAccountRollover, cls).tearDownClass()

    def test_success_account_rollover(self):
        """ Test success account key rollover."""
        with self.assertLogs(level='INFO') as accountrolloverlog:
            tools.acme_account_rollover.main(["--current", self.configs['old_account_key'],
                                              "--new", self.configs['new_account_key'],
                                              "--acme-directory", ACME_DIRECTORY])
        self.assertIn("INFO:acme_account_rollover:Keys rolled over.", accountrolloverlog.output)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
