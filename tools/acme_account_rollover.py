#!/usr/bin/env python3
# pylint: disable=too-many-statements
"""Tiny script to rollover two keys for an ACME account"""
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

LOGGER = logging.getLogger("acme_account_rollover")
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


# pylint: disable=too-many-locals
def account_rollover(old_accountkeypath, new_accountkeypath, acme_directory, timeout, log=LOGGER):
    """Rollover the old and new account key for an ACME account."""
    def _get_private_acme_signature(accountkeypath):
        """Read the account key to get the signature to authenticate with the ACME server."""
        accountkey = _openssl("rsa", ["-in", accountkeypath, "-noout", "-text"])
        signature_search = re.search(
            r"modulus:\s+?00:([a-f0-9\:\s]+?)\r?\npublicExponent: ([0-9]+)",
            accountkey.decode("utf8"), re.MULTILINE)
        if signature_search is None:
            raise ValueError("Unable to retrieve private signature.")
        pub_hex, pub_exp = signature_search.groups()
        pub_exp = "{0:x}".format(int(pub_exp))
        pub_exp = "0{0}".format(pub_exp) if len(pub_exp) % 2 else pub_exp
        return {
            "alg": "RS256",
            "jwk": {
                "e": _b64(binascii.unhexlify(pub_exp.encode("utf-8"))),
                "kty": "RSA",
                "n": _b64(binascii.unhexlify(re.sub(r"(\s|:)", "", pub_hex).encode("utf-8"))),
            },
        }

    def _sign_request(url, keypath, payload, is_inner=False):
        """Signs request with a specific right account key."""
        nonlocal nonce
        if payload == "":  # on POST-as-GET, final payload has to be just empty string
            payload64 = ""
        else:
            payload64 = _b64(json.dumps(payload).encode("utf8"))
        if keypath == new_accountkeypath:
            protected = copy.deepcopy(private_acme_new_signature)
        elif keypath == old_accountkeypath:
            protected = copy.deepcopy(private_acme_old_signature)
        else:
            raise RuntimeError("Unknown keypath to sign request")

        if is_inner or url == acme_config["newAccount"]:
            if "kid" in protected:
                del protected["kid"]
        else:
            del protected["jwk"]

        if not is_inner:
            protected["nonce"] = (nonce
                                  or requests.get(
                                      acme_config["newNonce"],
                                      headers=adtheaders,
                                      timeout=timeout)
                                  .headers['Replay-Nonce'])
        protected["url"] = url
        protected64 = _b64(json.dumps(protected).encode("utf8"))
        signature = _openssl("dgst", ["-sha256", "-sign", keypath],
                             "{0}.{1}".format(protected64, payload64).encode("utf8"))
        return {
            "protected": protected64, "payload": payload64, "signature": _b64(signature)
        }

    def _send_signed_request(url, keypath, payload):
        """Sends signed requests to ACME server."""
        nonlocal nonce
        jose = _sign_request(url, keypath, payload)
        joseheaders = {
            'User-Agent': adtheaders.get('User-Agent'),
            'Content-Type': 'application/jose+json'
        }
        try:
            response = requests.post(url, json=jose, headers=joseheaders, timeout=timeout)
        except requests.exceptions.RequestException as error:
            response = error.response
        if response:
            nonce = response.headers['Replay-Nonce']
            try:
                return response, response.json()
            except ValueError:  # if body is empty or not JSON formatted
                return response, json.dumps({})
        else:
            raise RuntimeError("Unable to get response from ACME server.")

    # main code
    adtheaders = {'User-Agent': 'acme-dns-tiny/3.0'}
    nonce = None

    log.info("Fetch informations from the ACME directory.")
    acme_config = requests.get(acme_directory, headers=adtheaders, timeout=timeout).json()

    log.info("Get private signature from old account key.")
    private_acme_old_signature = _get_private_acme_signature(old_accountkeypath)

    log.info("Get private signature from new account key.")
    private_acme_new_signature = _get_private_acme_signature(new_accountkeypath)

    log.info("Ask to the ACME server the account identifier to complete the private signature.")
    http_response, result = _send_signed_request(acme_config["newAccount"], old_accountkeypath, {
        "onlyReturnExisting": True})
    if http_response.status_code == 200:
        private_acme_old_signature["kid"] = http_response.headers["Location"]
        private_acme_new_signature["kid"] = http_response.headers["Location"]
    else:
        raise ValueError("Error looking or account URL: {0} {1}"
                         .format(http_response.status_code, result))

    log.info("Rolling over account keys.")
    # The signature by the new key covers the account URL and the old key,
    # signifying a request by the new key holder to take over the account from
    # the old key holder.
    inner_payload = _sign_request(acme_config["keyChange"], new_accountkeypath, {
        "account": private_acme_old_signature["kid"],
        "oldKey": private_acme_old_signature["jwk"]}, is_inner=True)
    # The signature by the old key covers this request and its signature, and
    # indicates the old key holder's assent to the roll-over request.
    http_response, result = _send_signed_request(acme_config["keyChange"], old_accountkeypath,
                                                 inner_payload)

    if http_response.status_code != 200:
        raise ValueError("Error rolling over account key: {0} {1}"
                         .format(http_response.status_code, result))
    log.info("Keys rolled over.")


def main(argv):
    """Parse arguments and roll over the ACME account keys."""
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="Tiny ACME client to roll over an ACME account key with another one.",
        epilog="""This script *rolls over* ACME account keys.

It will need to have access to the ACME private account keys, so PLEASE READ THROUGH IT!
It's around 150 lines, so it won't take long.

Example: roll over account key from account.key to newaccount.key:
  python3 acme_account_rollover.py --current account.key --new newaccount.key --acme-directory \
https://acme-staging-v02.api.letsencrypt.org/directory""")
    parser.add_argument("--current", required=True,
                        help="path to the current private account key")
    parser.add_argument("--new", required=True,
                        help="path to the newer private account key to register")
    parser.add_argument("--acme-directory", required=True,
                        help="ACME directory URL of the ACME server where to remove the key")
    parser.add_argument("--quiet", action="store_const", const=logging.ERROR,
                        help="suppress output except for errors")
    parser.add_argument("--timeout", type=int, default=10,
                        help="""Number of seconds to wait before ACME requests time out.
                        Set it to 0 to wait indefinitely. Defaults to 10.""")
    args = parser.parse_args(argv)

    LOGGER.setLevel(args.quiet or logging.INFO)
    account_rollover(args.current, args.new, args.acme_directory, args.timeout or None, log=LOGGER)


if __name__ == "__main__":  # pragma: no cover
    main(sys.argv[1:])
