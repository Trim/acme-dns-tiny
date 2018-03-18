#!/usr/bin/env python3
import os, argparse, subprocess, json, sys, base64, binascii, time, hashlib, re, copy, textwrap, logging
import dns.resolver, dns.tsigkeyring, dns.update
from configparser import ConfigParser
import urllib.request
from urllib.error import HTTPError

LOGGER = logging.getLogger('acme_dns_tiny')
LOGGER.addHandler(logging.StreamHandler())
LOGGER.setLevel(logging.INFO)

def get_crt(config, csr_file, log=LOGGER):
    # helper function base64 encode as defined in acme spec
    def _b64(b):
        return base64.urlsafe_b64encode(b).decode("utf8").rstrip("=")

    # helper function to run openssl command
    def _openssl(command, options, communicate=None):
        openssl = subprocess.Popen(["openssl", command] + options,
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = openssl.communicate(communicate)
        if openssl.returncode != 0:
            raise IOError("OpenSSL Error: {0}".format(err))
        return out

    # helper function to send DNS dynamic update messages
    def _update_dns(rrset, action):
        algorithm = dns.name.from_text("{0}".format(config["TSIGKeyring"]["Algorithm"].lower()))
        dns_update = dns.update.Update(config["DNS"]["zone"], keyring=keyring, keyalgorithm=algorithm)
        if action == "add":
            dns_update.add(rrset.name, rrset)
        elif action == "delete":
            dns_update.delete(rrset.name, rrset)
        resp = dns.query.tcp(dns_update, config["DNS"]["Host"], port=config.getint("DNS", "Port"))
        dns_update = None
        return resp

    # helper function to send signed requests
    def _send_signed_request(url, payload):
        nonlocal jws_nonce
        payload64 = _b64(json.dumps(payload).encode("utf8"))
        protected = copy.deepcopy(jws_header)
        protected["nonce"] = jws_nonce or webclient.open(acme_config["newNonce"]).getheader("Replay-Nonce", None)
        protected["url"] = url
        if url == acme_config["newAccount"]:
            del protected["kid"]
        else:
            del protected["jwk"]
        protected64 = _b64(json.dumps(protected).encode("utf8"))
        signature = _openssl("dgst", ["-sha256", "-sign", config["acmednstiny"]["AccountKeyFile"]],
                             "{0}.{1}".format(protected64, payload64).encode("utf8"))
        data = json.dumps({
            "protected": protected64, "payload": payload64,"signature": _b64(signature)
        })
        try:
            resp = webclient.open(url, data.encode("utf8"))
        except HTTPError as httperror:
            resp = httperror
        finally:
            jws_nonce = resp.getheader("Replay-Nonce", None)
            return resp.getcode(), resp.read(), resp.getheaders()

    # main code
    webclient = urllib.request.build_opener()
    webclient.addheaders = [('User-Agent', 'acme-dns-tiny/2.0'), ('Accept-Language', config["acmednstiny"].get("Language", "en"))]

    log.info("Fetch informations from the ACME directory.")
    directory = webclient.open(config["acmednstiny"]["ACMEDirectory"])
    acme_config = json.loads(directory.read().decode("utf8"))
    terms_service = acme_config.get("meta", {}).get("termsOfService", "")

    log.info("Prepare DNS keyring and resolver.")
    keyring = dns.tsigkeyring.from_text({config["TSIGKeyring"]["KeyName"]: config["TSIGKeyring"]["KeyValue"]})
    resolver = dns.resolver.Resolver(configure=False)
    resolver.retry_servfail = True
    nameserver = []
    try:
        nameserver = [ipv4_rrset.to_text() for ipv4_rrset in dns.resolver.query(config["DNS"]["Host"], rdtype="A")]
        nameserver = nameserver + [ipv6_rrset.to_text() for ipv6_rrset in dns.resolver.query(config["DNS"]["Host"], rdtype="AAAA")]
    except dns.exception.DNSException as e:
        log.info("A and/or AAAA DNS resources not found for configured dns host: we will use either resource found if one exists or directly the DNS Host configuration.")
    if not nameserver:
        nameserver = [config["DNS"]["Host"]]
    resolver.nameservers = nameserver

    log.info("Read account key.")
    accountkey = _openssl("rsa", ["-in", config["acmednstiny"]["AccountKeyFile"], "-noout", "-text"])
    pub_hex, pub_exp = re.search(
        r"modulus:\r?\n\s+00:([a-f0-9\:\s]+?)\r?\npublicExponent: ([0-9]+)",
        accountkey.decode("utf8"), re.MULTILINE | re.DOTALL).groups()
    pub_exp = "{0:x}".format(int(pub_exp))
    pub_exp = "0{0}".format(pub_exp) if len(pub_exp) % 2 else pub_exp
    jws_header = {
        "alg": "RS256",
        "jwk": {
            "e": _b64(binascii.unhexlify(pub_exp.encode("utf-8"))),
            "kty": "RSA",
            "n": _b64(binascii.unhexlify(re.sub(r"(\s|:)", "", pub_hex).encode("utf-8"))),
        },
        "kid": None,
    }
    accountkey_json = json.dumps(jws_header["jwk"], sort_keys=True, separators=(",", ":"))
    thumbprint = _b64(hashlib.sha256(accountkey_json.encode("utf8")).digest())
    jws_nonce = None

    log.info("Read CSR to find domains to validate.")
    csr = _openssl("req", ["-in", csr_file, "-noout", "-text"]).decode("utf8")
    domains = set([])
    common_name = re.search(r"Subject:\s*?CN\s*?=\s*?([^\s,;/]+)", csr)
    if common_name is not None:
        domains.add(common_name.group(1))
    subject_alt_names = re.search(r"X509v3 Subject Alternative Name: \r?\n +([^\r\n]+)\r?\n", csr, re.MULTILINE | re.DOTALL)
    if subject_alt_names is not None:
        for san in subject_alt_names.group(1).split(", "):
            if san.startswith("DNS:"):
                domains.add(san[4:])
    if len(domains) == 0:
        raise ValueError("Didn't find any domain to validate in the provided CSR.")

    log.info("Register ACME Account.")
    account_request = {}
    if terms_service != "":
        account_request["termsOfServiceAgreed"] = True
        log.warning("Terms of service exists and will be automatically agreed, please read them: {0}".format(terms_service))
    account_request["contact"] = config["acmednstiny"].get("Contacts", "").split(';')
    if account_request["contact"] == "":
        del account_request["contact"]

    code, result, headers = _send_signed_request(acme_config["newAccount"], account_request)
    account_info = {}
    if code == 201:
        jws_header["kid"] = dict(headers).get("Location")
        log.debug("  - Registered a new account: '{0}'".format(jws_header["kid"]))
        account_info = json.loads(result.decode("utf8"))
    elif code == 200:
        jws_header["kid"] = dict(headers).get("Location")
        log.debug("  - Account is already registered: '{0}'".format(jws_header["kid"]))

        code, result, headers = _send_signed_request(jws_header["kid"], {})
        account_info = json.loads(result.decode("utf8"))
    else:
        raise ValueError("Error registering account: {0} {1}".format(code, result))

    log.info("Update contact information if needed.")
    if (set(account_request["contact"]) != set(account_info["contact"])):
        code, result, headers = _send_signed_request(jws_header["kid"], account_request)
        if code == 200:
            log.debug("  - Account updated with latest contact informations.")
        else:
            raise ValueError("Error registering updates for the account: {0} {1}".format(code, result))

    # new order
    log.info("Request to the ACME server an order to validate domains.")
    new_order = { "identifiers": [{"type": "dns", "value": domain} for domain in domains]}
    code, result, headers = _send_signed_request(acme_config["newOrder"], new_order)
    order = json.loads(result.decode("utf8"))
    if code == 201:
        order_location = dict(headers).get("Location")
        log.debug("  - Order received: {0}".format(order_location))
        if order["status"] != "pending":
            raise ValueError("Order status is not pending, we can't use it: {0}".format(order))
    elif (code == 403
        and order["type"] == "urn:ietf:params:acme:error:userActionRequired"):
        raise ValueError("Order creation failed ({0}). Read Terms of Service ({1}), then follow your CA instructions: {2}".format(order["detail"], dict(headers)["Link"], order["instance"]))
    else:
        raise ValueError("Error getting new Order: {0} {1}".format(code, result))

    # complete each authorization challenge
    for authz in order["authorizations"]:
        log.info("Process challenge for authorization: {0}".format(authz))

        # get new challenge
        resp = webclient.open(authz)
        authorization = json.loads(resp.read().decode("utf8"))
        if resp.getcode() != 200:
            raise ValueError("Error fetching challenges: {0} {1}".format(resp.getcode(), authorization))
        domain = authorization["identifier"]["value"]

        log.info("Install DNS TXT resource for domain: {0}".format(domain))
        challenge = [c for c in authorization["challenges"] if c["type"] == "dns-01"][0]
        token = re.sub(r"[^A-Za-z0-9_\-]", "_", challenge["token"])
        keyauthorization = "{0}.{1}".format(token, thumbprint)
        keydigest64 = _b64(hashlib.sha256(keyauthorization.encode("utf8")).digest())
        dnsrr_domain = "_acme-challenge.{0}.".format(domain)
        dnsrr_set = dns.rrset.from_text(dnsrr_domain, 300, "IN", "TXT",  '"{0}"'.format(keydigest64))
        try:
            _update_dns(dnsrr_set, "add")
        except dns.exception.DNSException as dnsexception:
            raise ValueError("Error updating DNS records: {0} : {1}".format(type(dnsexception).__name__, str(dnsexception)))

        log.info("Waiting for {0} seconds before starting self challenge check.".format(config["acmednstiny"].getint("CheckChallengeDelay")))
        time.sleep(config["acmednstiny"].getint("CheckChallengeDelay"))
        challenge_verified = False
        number_check_fail = 1
        while challenge_verified is False:
            try:
                log.debug('Self test (try: {0}): Check resource with value "{1}" exits on nameservers: {2}'.format(number_check_fail, keydigest64, resolver.nameservers))
                challenges = resolver.query(dnsrr_domain, rdtype="TXT")
                for response in challenges.rrset:
                    log.debug("  - Found value {0}".format(response.to_text()))
                    challenge_verified = challenge_verified or response.to_text() == '"{0}"'.format(keydigest64)
            except dns.exception.DNSException as dnsexception:
                log.debug("  - Will retry as a DNS error occurred while checking challenge: {0} : {1}".format(type(dnsexception).__name__, dnsexception))
            finally:
                if challenge_verified is False:
                    if number_check_fail >= 10:
                        raise ValueError("Error checking challenge, value not found: {0}".format(keydigest64))
                    number_check_fail = number_check_fail + 1
                    time.sleep(2)

        log.info("Waiting for {0} seconds before asking ACME server to validate challenge.".format(max(10, config["acmednstiny"].getint("CheckChallengeDelay"))))
        time.sleep(max(10, config["acmednstiny"].getint("CheckChallengeDelay")))
        code, result, headers = _send_signed_request(challenge["url"], {"keyAuthorization": keyauthorization})
        if code != 200:
            raise ValueError("Error triggering challenge: {0} {1}".format(code, result))
        try:
            while True:
                try:
                    resp = webclient.open(challenge["url"])
                    challenge_status = json.loads(resp.read().decode("utf8"))
                except IOError as e:
                    raise ValueError("Error during challenge validation: {0} {1}".format(
                        e.code, json.loads(e.read().decode("utf8"))))
                if challenge_status["status"] == "pending":
                    time.sleep(2)
                elif challenge_status["status"] == "valid":
                    log.info("ACME has verified challenge for domain: {0}".format(domain))
                    break
                else:
                    raise ValueError("Challenge for domain {0} did not pass: {1}".format(
                        domain, challenge_status))
        finally:
            _update_dns(dnsrr_set, "delete")

    log.info("Request to finalize the order (all chalenge have been completed)")
    resp = webclient.open(order_location)
    finalize = json.loads(resp.read().decode("utf8"))
    csr_der = _b64(_openssl("req", ["-in", csr_file, "-outform", "DER"]))
    code, result, headers = _send_signed_request(order["finalize"], {"csr": csr_der})
    if code != 200:
        raise ValueError("Error while sending the CSR: {0} {1}".format(code, result))

    while True:
        try:
            resp = webclient.open(order_location)
            finalize = json.loads(resp.read().decode("utf8"))
        except IOError as e:
            raise ValueError("Error finalizing order: {0} {1}".format(
                e.code, json.loads(e.read().decode("utf8"))))

        if finalize["status"] == "processing":
            time.sleep(resp.getheader("Retry-After", 2))
        elif finalize["status"] == "valid":
            log.info("Order finalized!")
            break
        else:
            raise ValueError("Finalizing order {0} got errors: {1}".format(
                domain, finalize))
    
    resp = webclient.open(finalize["certificate"])
    if resp.getcode() != 200:
        raise ValueError("Finalizing order {0} got errors: {1}".format(
            resp.getcode(), resp.read.decode("utf8")))
    certchain = resp.read().decode("utf8")
    
    log.info("Certificate signed and chain received: {0}".format(finalize["certificate"]))
    return certchain

def main(argv):
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="""
This script automates the process of getting a signed TLS certificate
chain from any CA using the ACME protocol and its DNS verification.
It will need to have access to your private ACME account key and dns server
so PLEASE READ THROUGH IT!
It's around 300 lines, so it won't take long.

===Example Usage===
python3 acme_dns_tiny.py ./example.ini ./yourdomain.csr > chain.crt
See example.ini file to configure correctly this script.
===================
"""
    )
    parser.add_argument("--quiet", action="store_const", const=logging.ERROR, help="suppress output except for errors")
    parser.add_argument("configfile", help="path to your configuration file")
    parser.add_argument("csrfile", help="path to your certificate request")
    args = parser.parse_args(argv)

    config = ConfigParser()
    config.read_dict({"acmednstiny": {"ACMEDirectory": "https://acme-staging-v02.api.letsencrypt.org/directory",
                                      "CheckChallengeDelay": 3},
                      "DNS": {"Port": "53"}})
    config.read(args.configfile)

    if (set(["accountkeyfile", "acmedirectory", "checkchallengedelay"]) - set(config.options("acmednstiny"))
        or set(["keyname", "keyvalue", "algorithm"]) - set(config.options("TSIGKeyring"))
        or set(["zone", "host", "port"]) - set(config.options("DNS"))):
        raise ValueError("Some required settings are missing.")

    LOGGER.setLevel(args.quiet or LOGGER.level)
    signed_crt = get_crt(config, args.csrfile, log=LOGGER)
    sys.stdout.write(signed_crt)

if __name__ == "__main__":  # pragma: no cover
    main(sys.argv[1:])
