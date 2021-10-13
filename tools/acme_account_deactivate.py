#!/usr/bin/env python3
"""Tiny script to deactivate account on an ACME server."""
import sys
import argparse
import subprocess
import json
import base64
import binascii
import re
import copy
import logging
import requests

LOGGER = logging.getLogger("acme_account_deactivate")
LOGGER.addHandler(logging.StreamHandler())


def _b64(text):
    """Encodes text as base64 as specified in ACME RFC."""
    return base64.urlsafe_b64encode(text).decode("utf8").rstrip("=")


def _openssl(command, options, communicate=None):
    """Run openssl command line and raise IOError on non-zero return."""
    with subprocess.Popen(["openssl", command] + options, stdin=subprocess.PIPE,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE) as openssl:
        out, err = openssl.communicate(communicate)
        if openssl.returncode != 0:
            raise IOError("OpenSSL Error: {0}".format(err))
        return out


# pylint: disable=too-many-statements
def account_deactivate(accountkeypath, acme_directory, log=LOGGER):
    """Deactivate an ACME account."""

    def _send_signed_request(url, payload):
        """Sends signed requests to ACME server."""
        nonlocal nonce
        if payload == "":  # on POST-as-GET, final payload has to be just empty string
            payload64 = ""
        else:
            payload64 = _b64(json.dumps(payload).encode("utf8"))
        protected = copy.deepcopy(private_acme_signature)
        protected["nonce"] = nonce or requests.get(acme_config["newNonce"]).headers['Replay-Nonce']
        del nonce
        protected["url"] = url
        if url == acme_config["newAccount"]:
            if "kid" in protected:
                del protected["kid"]
        else:
            del protected["jwk"]
        protected64 = _b64(json.dumps(protected).encode("utf8"))
        signature = _openssl("dgst", ["-sha256", "-sign", accountkeypath],
                             "{0}.{1}".format(protected64, payload64).encode("utf8"))
        jose = {
            "protected": protected64, "payload": payload64, "signature": _b64(signature)
        }
        joseheaders = {
            'User-Agent': adtheaders.get('User-Agent'),
            'Content-Type': 'application/jose+json'
        }
        try:
            response = requests.post(url, json=jose, headers=joseheaders)
        except requests.exceptions.RequestException as error:
            response = error.response
        if response:
            nonce = response.headers['Replay-Nonce']
            try:
                return response, response.json()
            except ValueError:  # if body is empty or not JSON formatted
                return response, json.loads("{}")
        else:
            raise RuntimeError("Unable to get response from ACME server.")

    # main code
    adtheaders = {'User-Agent': 'acme-dns-tiny/3.0'}
    nonce = None

    log.info("Fetch informations from the ACME directory.")
    acme_config = requests.get(acme_directory, headers=adtheaders).json()

    log.info("Get private signature from account key.")
    accountkey = _openssl("rsa", ["-in", accountkeypath, "-noout", "-text"])
    signature_search = re.search(r"modulus:\s+?00:([a-f0-9\:\s]+?)\r?\npublicExponent: ([0-9]+)",
                                 accountkey.decode("utf8"), re.MULTILINE)
    if signature_search is None:
        raise ValueError("Unable to retrieve private signature.")
    pub_hex, pub_exp = signature_search.groups()
    pub_exp = "{0:x}".format(int(pub_exp))
    pub_exp = "0{0}".format(pub_exp) if len(pub_exp) % 2 else pub_exp
    # That signature is used to authenticate with the ACME server, it needs to be safely kept
    private_acme_signature = {
        "alg": "RS256",
        "jwk": {
            "e": _b64(binascii.unhexlify(pub_exp.encode("utf-8"))),
            "kty": "RSA",
            "n": _b64(binascii.unhexlify(re.sub(r"(\s|:)", "", pub_hex).encode("utf-8"))),
        },
    }

    log.info("Ask to the ACME server the account identifier to complete the private signature.")
    http_response, result = _send_signed_request(acme_config["newAccount"],
                                                 {"onlyReturnExisting": True})
    if http_response.status_code == 200:
        private_acme_signature["kid"] = http_response.headers['Location']
    else:
        raise ValueError("Error looking or account URL: {0} {1}"
                         .format(http_response.status_code, result))

    log.info("Deactivating the account.")
    http_response, result = _send_signed_request(private_acme_signature["kid"],
                                                 {"status": "deactivated"})

    if http_response.status_code == 200:
        log.info("The account has been deactivated.")
    else:
        raise ValueError("Error while deactivating the account key: {0} {1}"
                         .format(http_response.status_code, result))


def main(argv):
    """Parse arguments and deactivate account."""
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="Tiny ACME script to deactivate an ACME account",
        epilog="""This script permanently *deactivates* an ACME account.

You should revoke all TLS certificates linked to the account *before* using this script,
as the server won't accept any further request when account is deactivated.

It will need to access the ACME private account key, so PLEASE READ THROUGH IT!
It's around 150 lines, so it won't take long.

Example: deactivate account.key from staging Let's Encrypt:
  python3 acme_account_deactivate.py --account-key account.key --acme-directory \
https://acme-staging-v02.api.letsencrypt.org/directory"""
    )
    parser.add_argument("--account-key", required=True,
                        help="path to the private account key to deactivate")
    parser.add_argument("--acme-directory", required=True,
                        help="ACME directory URL of the ACME server where to remove the key")
    parser.add_argument("--quiet", action="store_const",
                        const=logging.ERROR,
                        help="suppress output except for errors")
    args = parser.parse_args(argv)

    LOGGER.setLevel(args.quiet or logging.INFO)
    account_deactivate(args.account_key, args.acme_directory, log=LOGGER)


if __name__ == "__main__":  # pragma: no cover
    main(sys.argv[1:])
