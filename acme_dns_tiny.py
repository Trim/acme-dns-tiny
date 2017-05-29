#!/usr/bin/env python3
import os, argparse, subprocess, json, sys, base64, binascii, time, hashlib, re, copy, textwrap, logging
import dns.resolver, dns.tsigkeyring, dns.update
from configparser import ConfigParser
from urllib.request import urlopen
from urllib.error import HTTPError

LOGGER = logging.getLogger('acme_dns_tiny')
LOGGER.addHandler(logging.StreamHandler())
LOGGER.setLevel(logging.INFO)

def get_crt(config, log=LOGGER):
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
        protected["nonce"] = jws_nonce or urlopen(config["acmednstiny"]["ACMEDirectory"]).getheader("Replay-Nonce", None)
        protected64 = _b64(json.dumps(protected).encode("utf8"))
        signature = _openssl("dgst", ["-sha256", "-sign", config["acmednstiny"]["AccountKeyFile"]],
                             "{0}.{1}".format(protected64, payload64).encode("utf8"))
        data = json.dumps({
            "header": jws_header, "protected": protected64,
            "payload": payload64, "signature": _b64(signature),
        })
        try:
            resp = urlopen(url, data.encode("utf8"))
        except HTTPError as httperror:
            resp = httperror
        finally:
            jws_nonce = resp.getheader("Replay-Nonce", None)
            return resp.getcode(), resp.read(), resp.getheaders()

    # helper function to get url from Link HTTP headers
    def _get_url_link(headers, rel):
        log.info("Looking for Link with rel='{0}' in headers".format(rel))
        linkheaders = [link.strip() for link in dict(headers)["Link"].split(',')]
        url = [re.match(r'<(?P<url>.*)>.*;rel=(' + re.escape(rel) + r'|("([a-z][a-z0-9\.\-]*\s+)*' + re.escape(rel) + r'[\s"]))', link).groupdict()
                        for link in linkheaders][0]["url"]
        return url

    # main code
    log.info("Read ACME directory.")
    directory = urlopen(config["acmednstiny"]["ACMEDirectory"])
    acme_config = json.loads(directory.read().decode("utf8"))
    current_terms = acme_config.get("meta", {}).get("terms-of-service")

    log.info("Prepare DNS keyring and resolver.")
    keyring = dns.tsigkeyring.from_text({config["TSIGKeyring"]["KeyName"]: config["TSIGKeyring"]["KeyValue"]})
    resolver = dns.resolver.Resolver(configure=False)
    resolver.retry_servfail = True
    nameserver = []
    try:
        nameserver = [ipv4_rrset.to_text() for ipv4_rrset in dns.resolver.query(config["DNS"]["Host"], rdtype="A")]
        nameserver = nameserver + [ipv6_rrset.to_text() for ipv6_rrset in dns.resolver.query(config["DNS"]["Host"], rdtype="AAAA")]
    except dns.exception.DNSException as e:
        log.info("A and/or AAAA DNS resources not found for configured dns host: we will use either resource found if exists or directly the DNS Host configuration.")
    if not nameserver:
        nameserver = [config["DNS"]["Host"]]
    resolver.nameservers = nameserver

    log.info("Parsing account key looking for public key.")
    if "rsa" in config["acmednstiny"]["AccountKeyType"].lower():
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
        }
    else if "ec" in config["acmednstiny"]["AccountKeyType"].lower():
        accountkey = _openssl("ec", ["-in", config["acmednstiny"]["AccountKeyFile"], "-noout", "-text"])
        pub_hex, pub_exp = re.search(
            r"pub:\s*\r?\n\s+04:([a-f0-9\:\s]+?)\nASN1 OID: prime256v1\r?\n",
            accountkey.decode("utf8"), re.MULTILINE | re.DOTALL).groups()
        pub_exp = binascii.unhexlify(re.sub(r"(\s|:)", "", pub_hex.group(1)))
        if len(pub_hex) != 64:
            raise ValueError("Key error: public key has incorrect length")
        jws_header = {
            "alg": "ES256",
            "jwk": {
                "kty": "EC",
                "x": _b64(pub_hex[:32]),
                "y": _b64(pub_hex[32:]),
            },
        }
    else:
        raise ValueError("Error reading account key file {0}, uknown key type {1}".format(config["acmednstiny"]["AccountKeyFile"], config["acmednstiny"]["AccountKeyType"]))
    accountkey_json = json.dumps(jws_header["jwk"], sort_keys=True, separators=(",", ":"))
    thumbprint = _b64(hashlib.sha256(accountkey_json.encode("utf8")).digest())
    jws_nonce = None

    log.info("Parsing CSR looking for domains.")
    csr = _openssl("req", ["-in", config["acmednstiny"]["CSRFile"], "-noout", "-text"]).decode("utf8")
    domains = set([])
    common_name = re.search(r"Subject:.*? CN=([^\s,;/]+)", csr)
    if common_name is not None:
        domains.add(common_name.group(1))
    subject_alt_names = re.search(r"X509v3 Subject Alternative Name: \r?\n +([^\r\n]+)\r?\n", csr, re.MULTILINE | re.DOTALL)
    if subject_alt_names is not None:
        for san in subject_alt_names.group(1).split(", "):
            if san.startswith("DNS:"):
                domains.add(san[4:])

    log.info("Registering ACME Account.")
    reg_info = {"resource": "new-reg"}
    if current_terms is not None:
        reg_info["agreement"] = current_terms
    reg_info["contact"] = []
    reg_mailto = "mailto:{0}".format(config["acmednstiny"].get("MailContact"))
    reg_phone = "tel:{0}".format(config["acmednstiny"].get("PhoneContact"))
    if config["acmednstiny"].get("MailContact") is not None:
        reg_info["contact"].append(reg_mailto)
    if config["acmednstiny"].get("PhoneContact") is not None:
        reg_info["contact"].append(reg_phone)
    if len(reg_info["contact"]) == 0:
        del reg_info["contact"]

    code, result, headers = _send_signed_request(acme_config["new-reg"], reg_info)
    if code == 201:
        account_url = dict(headers).get("Location")
        log.info("Registered! (account: '{0}')".format(account_url))
        reg_received_contact = reg_info.get("contact")
    elif code == 409:
        account_url = dict(headers).get("Location")
        log.info("Already registered! (account: '{0}')".format(account_url))
        # Client should send empty payload to query account information
        code, result, headers = _send_signed_request(account_url, {"resource":"reg"})
        account_info = json.loads(result.decode("utf8"))
        reg_info["agreement"] = account_info.get("agreement")
        reg_received_contact = account_info.get("contact")
    else:
        raise ValueError("Error registering: {0} {1}".format(code, result))

    log.info("Update contact information and terms of service agreement if needed.")
    if current_terms is None:
        current_terms = _get_url_link(headers, 'terms-of-service')
    if (reg_info.get("agreement") != current_terms
        or reg_mailto not in reg_received_contact
        or reg_phone not in reg_received_contact):
        reg_info["resource"] = "reg"
        reg_info["agreement"] = current_terms
        code, result, headers = _send_signed_request(account_url, reg_info)
        if code == 202:
            log.info("Account updated (terms of service agreed: '{0}')".format(reg_info.get("agreement")))
        else:
            raise ValueError("Error register update: {0} {1}".format(code, result))

    # verify each domain
    for domain in domains:
        log.info("Verifying domain: {0}".format(domain))

        # get new challenge
        code, result, headers = _send_signed_request(acme_config["new-authz"], {
            "resource": "new-authz",
            "identifier": {"type": "dns", "value": domain},
        })
        if code != 201:
            raise ValueError("Error requesting challenges: {0} {1}".format(code, result))

        log.info("Create and install DNS TXT challenge resource.")
        challenge = [c for c in json.loads(result.decode("utf8"))["challenges"] if c["type"] == "dns-01"][0]
        token = re.sub(r"[^A-Za-z0-9_\-]", "_", challenge["token"])
        keyauthorization = "{0}.{1}".format(token, thumbprint)
        keydigest64 = _b64(hashlib.sha256(keyauthorization.encode("utf8")).digest())
        dnsrr_domain = "_acme-challenge.{0}.".format(domain)
        dnsrr_set = dns.rrset.from_text(dnsrr_domain, 300, "IN", "TXT",  '"{0}"'.format(keydigest64))
        try:
            _update_dns(dnsrr_set, "add")
        except dns.exception.DNSException as dnsexception:
            raise ValueError("Error updating DNS records: {0} : {1}".format(type(dnsexception).__name__, str(dnsexception)))

        log.info("Wait {0} then start self challenge checks.".format(config["acmednstiny"].getint("CheckChallengeDelay")))
        time.sleep(config["acmednstiny"].getint("CheckChallengeDelay"))
        challenge_verified = False
        number_check_fail = 1
        while challenge_verified is False:
            try:
                log.info('Try {0}: Check ressource with value "{1}" exits on nameservers: {2}'.format(number_check_fail, keydigest64, resolver.nameservers))
                challenges = resolver.query(dnsrr_domain, rdtype="TXT")
                for response in challenges.rrset:
                    log.info(".. Found value {0}".format(response.to_text()))
                    challenge_verified = challenge_verified or response.to_text() == '"{0}"'.format(keydigest64)
            except dns.exception.DNSException as dnsexception:
                log.info("Info: retry, because a DNS error occurred while checking challenge: {0} : {1}".format(type(dnsexception).__name__, dnsexception))
            finally:
                if number_check_fail >= 10:
                    raise ValueError("Error checking challenge, value not found: {0}".format(keydigest64))

                if challenge_verified is False:
                    number_check_fail = number_check_fail + 1
                    time.sleep(2)

        log.info("Ask ACME server to perform checks.")
        code, result, headers = _send_signed_request(challenge["uri"], {
            "resource": "challenge",
            "keyAuthorization": keyauthorization,
        })
        if code != 202:
            raise ValueError("Error triggering challenge: {0} {1}".format(code, result))

        log.info("Waiting challenge to be verified.")
        try:
            while True:
                try:
                    resp = urlopen(challenge["uri"])
                    challenge_status = json.loads(resp.read().decode("utf8"))
                except IOError as e:
                    raise ValueError("Error checking challenge: {0} {1}".format(
                        e.code, json.loads(e.read().decode("utf8"))))
                if challenge_status["status"] == "pending":
                    time.sleep(2)
                elif challenge_status["status"] == "valid":
                    log.info("Domain {0} verified!".format(domain))
                    break
                else:
                    raise ValueError("{0} challenge did not pass: {1}".format(
                        domain, challenge_status))
        finally:
            _update_dns(dnsrr_set, "delete")

    log.info("Ask to sign certificate.")
    csr_der = _openssl("req", ["-in", config["acmednstiny"]["CSRFile"], "-outform", "DER"])
    code, result, headers = _send_signed_request(acme_config["new-cert"], {
        "resource": "new-cert",
        "csr": _b64(csr_der),
    })
    if code != 201:
        raise ValueError("Error signing certificate: {0} {1}".format(code, result))
    certificate = os.linesep.join(textwrap.wrap(base64.b64encode(result).decode("utf8"), 64))

    # get the parent certificate which had created this one
    certificate_parent_url = _get_url_link(headers, 'up')
    resp = urlopen(certificate_parent_url)
    if resp.getcode() not in [200, 201]:
        raise ValueError("Error getting certificate chain from {0}: {1} {2}".format(
            certificate_parent_url, code, resp.read()))
    intermediary_certificate = os.linesep.join(textwrap.wrap(base64.b64encode(resp.read()).decode("utf8"), 64))
    
    chainlist = ["-----BEGIN CERTIFICATE-----{0}{1}{0}-----END CERTIFICATE-----{0}".format(
        os.linesep, cert) for cert in [certificate, intermediary_certificate]]
    
    log.info("Certificate signed and received.")
    return "".join(chainlist)

def main(argv):
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="""
This script automates the process of getting a signed TLS certificate
chain from Let's Encrypt using the ACME protocol and its DNS verification.
It will need to have access to your private account key and dns server
so PLEASE READ THROUGH IT!
It's around 300 lines, so it won't take long.

===Example Usage===
python3 acme_dns_tiny.py ./example.ini > chain.crt
See example.ini file to configure correctly this script.
===================
"""
    )
    parser.add_argument("--quiet", action="store_const", const=logging.ERROR, help="suppress output except for errors")
    parser.add_argument("configfile", help="path to your configuration file")
    args = parser.parse_args(argv)

    config = ConfigParser()
    config.read_dict({"acmednstiny": {"ACMEDirectory": "https://acme-staging.api.letsencrypt.org/directory",
                                      "CheckChallengeDelay": 2,
                                      "AccountKeyType": "rsa"},
                      "DNS": {"Port": "53"}})
    config.read(args.configfile)

    if (set(["accountkeyfile", "csrfile", "acmedirectory", "checkchallengedelay"]) - set(config.options("acmednstiny"))
        or set(["keyname", "keyvalue", "algorithm"]) - set(config.options("TSIGKeyring"))
        or set(["zone", "host", "port"]) - set(config.options("DNS"))):
        raise ValueError("Some required settings are missing.")

    LOGGER.setLevel(args.quiet or LOGGER.level)
    signed_crt = get_crt(config, log=LOGGER)
    sys.stdout.write(signed_crt)

if __name__ == "__main__":  # pragma: no cover
    main(sys.argv[1:])
