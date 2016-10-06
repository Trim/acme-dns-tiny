#!/usr/bin/env python3
import argparse, subprocess, json, sys, base64, binascii, time, hashlib, re, copy, textwrap, logging
import dns.resolver, dns.tsigkeyring, dns.update
from configparser import ConfigParser
from urllib.request import urlopen

LOGGER = logging.getLogger('acme_dns_tiny_logger')
LOGGER.addHandler(logging.StreamHandler())
LOGGER.setLevel(logging.INFO)

def get_crt(config, log=LOGGER):
    # helper function base64 encode for jose spec
    def _b64(b):
        return base64.urlsafe_b64encode(b).decode("utf8").replace("=", "")

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
        payload64 = _b64(json.dumps(payload).encode("utf8"))
        protected = copy.deepcopy(jws_header)
        protected["nonce"] = urlopen(config["acmednstiny"]["ACMEDirectory"]).headers["Replay-Nonce"]
        protected["url"] = url
        protected64 = _b64(json.dumps(protected).encode("utf8"))
        signature = _openssl("dgst", ["-sha256", "-sign", config["acmednstiny"]["AccountKeyFile"]],
                             "{0}.{1}".format(protected64, payload64).encode("utf8"))
        data = json.dumps({
            "header": jws_header, "protected": protected64,
            "payload": payload64, "signature": _b64(signature),
        })
        try:
            resp = urlopen(url, data.encode("utf8"))
            return resp.getcode(), resp.read(), resp.getheaders()
        except IOError as e:
            return getattr(e, "code", None), getattr(e, "read", e.__str__)(), None

    # helper function to get url from Link HTTP headers
    def _get_url_link(headers, rel):
        log.info("Looking for {0} in headers: {1}".format(rel, headers))
        linkheaders = [link.strip() for link in dict(headers)["Link"].split(',')]
        url = [re.match(r'<(?P<url>.*)>.*;rel=(' + re.escape(rel) + r'|("([a-z][a-z0-9\.\-]*\s+)*' + re.escape(rel) + r'[\s"]))', link).groupdict()
                        for link in linkheaders][0]["url"]
        return url

    # main code

    log.info("Read ACME directory.")
    directory = urlopen(config["acmednstiny"]["ACMEDirectory"])
    acme_config = json.loads(directory.read().decode("utf8"))
    directory_terms_url = acme_config.get("meta", {}).get("terms-of-service")

    log.info("Prepare DNS keyring and resolver.")
    keyring = dns.tsigkeyring.from_text({config["TSIGKeyring"]["KeyName"]: config["TSIGKeyring"]["KeyValue"]})
    nameserver = []
    try:
        nameserver = [ipv4_rrset.to_text() for ipv4_rrset in dns.resolver.query(config["DNS"]["Host"], rdtype="A")]
    except dns.exception.DNSException as e:
        log.info("DNS IPv4 record not found for configured dns host.")
    finally:
        try:
            nameserver = nameserver + [ipv6_rrset.to_text() for ipv6_rrset in dns.resolver.query(config["DNS"]["Host"], rdtype="AAAA")]
        except dns.exception.DNSException as e:
            log.info("DNS IPv4 and IPv6 records not found for configured dns host. Try to keep original name.")
        finally:
            if not nameserver:
                nameserver = [config["DNS"]["Host"]]
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = nameserver
    resolver.retry_servfail = True

    log.info("Parsing account key looking for public key.")
    accountkey = _openssl("rsa", ["-in", config["acmednstiny"]["AccountKeyFile"], "-noout", "-text"])
    pub_hex, pub_exp = re.search(
        r"modulus:\n\s+00:([a-f0-9\:\s]+?)\npublicExponent: ([0-9]+)",
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
    accountkey_json = json.dumps(jws_header["jwk"], sort_keys=True, separators=(",", ":"))
    thumbprint = _b64(hashlib.sha256(accountkey_json.encode("utf8")).digest())

    log.info("Parsing CSR looking for domains.")
    csr = _openssl("req", ["-in", config["acmednstiny"]["CSRFile"], "-noout", "-text"]).decode("utf8")
    domains = set([])
    common_name = re.search(r"Subject:.*? CN=([^\s,;/]+)", csr)
    if common_name is not None:
        domains.add(common_name.group(1))
    subject_alt_names = re.search(r"X509v3 Subject Alternative Name: \n +([^\n]+)\n", csr, re.MULTILINE | re.DOTALL)
    if subject_alt_names is not None:
        for san in subject_alt_names.group(1).split(", "):
            if san.startswith("DNS:"):
                domains.add(san[4:])

    log.info("Registering ACME Account.")
    if directory_terms_url is not None:
        reg_info["agreement"] = directory_terms_url
    reg_info["contact"] = []
    if b'MailContact' in config["acmednstiny"]:
        reg_info["contact"].append("mailto:{0}".format(config["acmednstiny"]["MailContact"]))
    if b'PhoneContact' in config["acmednstiny"]:
        reg_info["contact"].append("tel:{0}".format(config["acmednstiny"]["PhoneContact"]))
    if len(reg_info["contact"]) == 0:
        del reg_info["contact"]
    code, result, headers = _send_signed_request(acme_config["new-reg"], reg_info)
    if code == 201:
        log.info("Registered! (account: '{0}')".format(dict(headers).get("Location")))
        reg_received_terms = _get_url_link(headers, 'terms-of-service')
    elif code == 409:
        log.info("Already registered (headers: {0}, content: {1})".format(dict(headers), result))
        account_url = dict(headers).get("Location")
        if account_url is not None:
            log.info("Get account informations (account: '{0}')".format(registration_url))
            # Client should send empty payload to query account information
            code, result, headers = _send_signed_request(account_url, {})
            account_info = json.loads(result.read().decode("utf8"))
            reg_received_terms = account_info.get("agreement")
    else:
        raise ValueError("Error registering: {0} {1} {2}".format(code, headers, result))

    log.info("Terms of service agreement if needed.")
    if reg_info.get("agreement") != reg_received_terms:
        reg_info["agreement"] = reg_received_terms
        code, result, headers = _send_signed_request(acme_config["new-reg"], reg_info)
        if code == 201:
            log.info("Terms of service agreed: {0}".format(reg_info.get("agreement")))
        else:
            raise ValueError("Error registering: {0} {1} {2}".format(code, headers, result))

    for domain in domains:
        log.info("Verifying domain: {0}".format(domain))

        # get new challenge
        code, result, headers = _send_signed_request(acme_config["new-authz"], {
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
                log.info('Try {0}: Check ressource with value "{1}" exits on nameservers: {2}'.format(number_check_fail+1, keydigest64, resolver.nameservers))
                challenges = resolver.query(dnsrr_domain, rdtype="TXT")
                for response in challenges.rrset:
                    log.info(".. Found value {0}".format(response.to_text()))
                    challenge_verified = challenge_verified or response.to_text() == '"{0}"'.format(keydigest64)
            except dns.exception.DNSException as dnsexception:
                log.info("Info: retry, because a DNS error occurred while checking challenge: {0} : {1}".format(type(dnsexception).__name__, dnsexception))
            finally:
                if number_check_fail > 10:
                    raise ValueError("Error checking challenge, value not found: {0}".format(keydigest64))

                if challenge_verified is False:
                    number_check_fail = number_check_fail + 1
                    time.sleep(2)
        log.info("Ask ACME server to perform checks.")
        code, result, headers = _send_signed_request(challenge["uri"], {
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
        "csr": _b64(csr_der),
    })
    if code != 201:
        raise ValueError("Error signing certificate: {0} {1}".format(code, result))
    certificate = "\n".join(textwrap.wrap(base64.b64encode(result).decode("utf8"), 64))

    # get the parent certificate which had created this one
    resp = urlopen(_get_url_link(headers, 'up'))
    code = resp.getcode()
    result = resp.read()
    if code not in [200, 201]:
        raise ValueError("Error getting certificate chain from {0}: {1} {2}".format(
            certificate_parent_url, code, result))
    certificate_parent = "\n".join(textwrap.wrap(base64.b64encode(result).decode("utf8"), 64))

    log.info("Certificate signed and received.")
    return """-----BEGIN CERTIFICATE-----\n{0}\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\n{1}\n-----END CERTIFICATE-----\n""".format(
        certificate, certificate_parent)

def main(argv):
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=textwrap.dedent("""\
            This script automates the process of getting a signed TLS certificate
            chain from Let's Encrypt using the ACME protocol and its DNS verification.
            It will need to have access to your private account key and dns server
            so PLEASE READ THROUGH IT!
            It's only ~250 lines, so it won't take long.

            ===Example Usage===
            python3 acme_dns_tiny.py ./example.ini > chain.crt
            See example.ini file to configure correctly this script.
            ===================
            """)
    )
    parser.add_argument("--quiet", action="store_const", const=logging.ERROR, help="suppress output except for errors")
    parser.add_argument("configfile", help="path to your configuration file")
    args = parser.parse_args(argv)

    config = ConfigParser()
    config.read_dict({"acmednstiny": {"ACMEDirectory": "https://acme-staging.api.letsencrypt.org/directory",
                                      "CheckChallengeDelay": 2},
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
