"""Unit tests for the acme_dns_tiny script"""
import unittest
import sys
import os
import configparser
import dns.version
import acme_dns_tiny
from tests.config_factory import generate_acme_dns_tiny_unit_test_config


class TestACMEDNSTiny(unittest.TestCase):
    "Tests for acme_dns_tiny.get_crt()"

    @classmethod
    def setUpClass(cls):
        print("Init acme_dns_tiny with python modules:")
        print(f"  - python: {sys.version}")
        print(f"  - dns python: {dns.version.version}")
        cls.configs = generate_acme_dns_tiny_unit_test_config()
        sys.stdout.flush()
        super(TestACMEDNSTiny, cls).setUpClass()

    # Close correctly temporary files
    @classmethod
    def tearDownClass(cls):
        # close temp files correctly
        for file in cls.configs.values():
            parser = configparser.ConfigParser()
            parser.read(file)
            try:
                os.remove(parser["acmednstiny"]["AccountKeyFile"])
            except:  # pylint: disable=bare-except
                pass
            try:
                os.remove(parser["acmednstiny"]["CSRFile"])
            except:  # pylint: disable=bare-except
                pass
            try:
                os.remove(file)
            except:  # pylint: disable=bare-except
                pass
        super(TestACMEDNSTiny, cls).tearDownClass()

    def test_failure_notcompleted_configuration(self):
        """ Configuration file have to be completed """
        self.assertRaisesRegex(ValueError, r"Some required settings are missing.",
                               acme_dns_tiny.main, [self.configs['missing_tsigkeyring'],
                                                    "--verbose"])


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
