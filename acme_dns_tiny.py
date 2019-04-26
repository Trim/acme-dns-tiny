#!/usr/bin/env python3
import argparse, subprocess, requests, json, sys, base64, binascii, time, hashlib, re, copy, logging, configparser
import dns.resolver, dns.tsigkeyring, dns.update

LOGGER = logging.getLogger('acme_dns_tiny')
LOGGER.addHandler(logging.StreamHandler())

def get_crt(config, log=LOGGER):
    def _b64(b):
        """"Encodes string as base64 as specified in ACME RFC """
        return base64.urlsafe_b64encode(b).decode("utf8").rstrip("=")

    def _openssl(command, options, communicate=None):
        """Run openssl command line and raise IOError on non-zero return."""
        openssl = subprocess.Popen(["openssl", command] + options,
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = openssl.communicate(communicate)
        if openssl.returncode != 0:
            raise IOError("OpenSSL Error: {0}".format(err))
        return out

    def _update_dns(rrset, action):
        """Updates DNS resource by adding or deleting resource."""
        algorithm = dns.name.from_text("{0}".format(config["TSIGKeyring"]["Algorithm"].lower()))
        dns_update = dns.update.Update(config["DNS"]["zone"], keyring=keyring, keyalgorithm=algorithm)
        if action == "add":
            dns_update.add(rrset.name, rrset)
        elif action == "delete":
            dns_update.delete(rrset.name, rrset)
        response = dns.query.tcp(dns_update, config["DNS"]["Host"], port=config.getint("DNS", "Port"))
        dns_update = None
        return response

    def _send_signed_request(url, payload):
        """Sends signed requests to ACME server."""
        nonlocal jws_nonce
        if payload == "": # on POST-as-GET, final payload has to be just empty string
            payload64 = ""
        else:
            payload64 = _b64(json.dumps(payload).encode("utf8"))
        protected = copy.deepcopy(jws_header)
        protected["nonce"] = jws_nonce or requests.get(acme_config["newNonce"]).headers['Replay-Nonce']
        protected["url"] = url
        if url == acme_config["newAccount"]:
            del protected["kid"]
        else:
            del protected["jwk"]
        protected64 = _b64(json.dumps(protected).encode("utf8"))
        signature = _openssl("dgst", ["-sha256", "-sign", config["acmednstiny"]["AccountKeyFile"]],
                             "{0}.{1}".format(protected64, payload64).encode("utf8"))
        jose = {
            "protected": protected64, "payload": payload64,"signature": _b64(signature)
        }
        try:
            response = requests.post(url, json=jose, headers=joseheaders)
        except requests.exceptions.RequestException as error:
            response = error.response
        finally:
            jws_nonce = response.headers['Replay-Nonce']
            try:
                return response, response.json()
            except ValueError as error:
                return response, json.dumps({})

    # main code
    adtheaders =  {'User-Agent': 'acme-dns-tiny/2.1',
        'Accept-Language': config["acmednstiny"].get("Language", "en")
    }
    joseheaders=copy.deepcopy(adtheaders)
    joseheaders['Content-Type']='application/jose+json'

    log.info("Fetch informations from the ACME directory.")
    directory = requests.get(config["acmednstiny"]["ACMEDirectory"], headers=adtheaders)
    acme_config = directory.json()
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
    jwk_thumbprint = _b64(hashlib.sha256(accountkey_json.encode("utf8")).digest())
    jws_nonce = None

    log.info("Read CSR to find domains to validate.")
    csr = _openssl("req", ["-in", config["acmednstiny"]["CSRFile"], "-noout", "-text"]).decode("utf8")
    domains = set()
    common_name = re.search(r"Subject:.*?\s+?CN\s*?=\s*?([^\s,;/]+)", csr)
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

    http_response, account_info = _send_signed_request(acme_config["newAccount"], account_request)
    if http_response.status_code == 201:
        jws_header["kid"] = http_response.headers['Location']
        log.info("  - Registered a new account: '{0}'".format(jws_header["kid"]))
    elif http_response.status_code == 200:
        jws_header["kid"] = http_response.headers['Location']
        log.debug("  - Account is already registered: '{0}'".format(jws_header["kid"]))

        http_response, account_info = _send_signed_request(jws_header["kid"], {})
    else:
        raise ValueError("Error registering account: {0} {1}".format(http_response.status_code, account_info))

    log.info("Update contact information if needed.")
    if (set(account_request["contact"]) != set(account_info["contact"])):
        http_response, result = _send_signed_request(jws_header["kid"], account_request)
        if http_response.status_code == 200:
            log.debug("  - Account updated with latest contact informations.")
        else:
            raise ValueError("Error registering updates for the account: {0} {1}".format(http_response.status_code, result))

    # new order
    log.info("Request to the ACME server an order to validate domains.")
    new_order = { "identifiers": [{"type": "dns", "value": domain} for domain in domains]}
    http_response, order = _send_signed_request(acme_config["newOrder"], new_order)
    if http_response.status_code == 201:
        order_location = http_response.headers['Location']
        log.debug("  - Order received: {0}".format(order_location))
        if order["status"] != "pending" and order["status"] != "ready":
            raise ValueError("Order status is neither pending neither ready, we can't use it: {0}".format(order))
    elif (http_response.status_code == 403
        and order["type"] == "urn:ietf:params:acme:error:userActionRequired"):
        raise ValueError("Order creation failed ({0}). Read Terms of Service ({1}), then follow your CA instructions: {2}".format(order["detail"], http_response.headers['Link'], order["instance"]))
    else:
        raise ValueError("Error getting new Order: {0} {1}".format(http_response.status_code, result))

    # complete each authorization challenge
    for authz in order["authorizations"]:
        if order["status"] == "ready":
            log.info("No challenge to process: order is already ready.")
            break;

        log.info("Process challenge for authorization: {0}".format(authz))
        # get new challenge
        http_response, authorization = _send_signed_request(authz, "")
        if http_response.status_code != 200:
            raise ValueError("Error fetching challenges: {0} {1}".format(http_response.status_code, authorization))
        domain = authorization["identifier"]["value"]

        log.info("Install DNS TXT resource for domain: {0}".format(domain))
        challenge = [c for c in authorization["challenges"] if c["type"] == "dns-01"][0]
        token = re.sub(r"[^A-Za-z0-9_\-]", "_", challenge["token"])
        keyauthorization = "{0}.{1}".format(token, jwk_thumbprint)
        keydigest64 = _b64(hashlib.sha256(keyauthorization.encode("utf8")).digest())
        dnsrr_domain = "_acme-challenge.{0}.".format(domain)
        try: # a CNAME resource can be used for advanced TSIG configuration
            # Note: the CNAME target has to be of "non-CNAME" type to be able to add TXT records aside it
            dnsrr_domain = [response.to_text() for response in resolver.query(dnsrr_domain, rdtype="CNAME")][0]
            log.info("  - A CNAME resource has been found for this domain, will install TXT on {0}".format(dnsrr_domain))
        except dns.exception.DNSException as dnsexception:
            log.debug("  - Not any CNAME resource has been found for this domain ({1}), will install TXT directly on {0}".format(dnsrr_domain, type(dnsexception).__name__))
        dnsrr_set = dns.rrset.from_text(dnsrr_domain, config["DNS"].getint("TTL"), "IN", "TXT",  '"{0}"'.format(keydigest64))
        try:
            _update_dns(dnsrr_set, "add")
        except dns.exception.DNSException as dnsexception:
            raise ValueError("Error updating DNS records: {0} : {1}".format(type(dnsexception).__name__, str(dnsexception)))

        log.info("Waiting for 1 TTL ({0} seconds) before starting self challenge check.".format(config["DNS"].getint("TTL")))
        time.sleep(config["DNS"].getint("TTL"))
        challenge_verified = False
        number_check_fail = 1
        while challenge_verified is False:
            try:
                log.debug('Self test (try: {0}): Check resource with value "{1}" exits on nameservers: {2}'.format(number_check_fail, keydigest64, resolver.nameservers))
                for response in resolver.query(dnsrr_domain, rdtype="TXT").rrset:
                    log.debug("  - Found value {0}".format(response.to_text()))
                    challenge_verified = challenge_verified or response.to_text() == '"{0}"'.format(keydigest64)
            except dns.exception.DNSException as dnsexception:
                log.debug("  - Will retry as a DNS error occurred while checking challenge: {0} : {1}".format(type(dnsexception).__name__, dnsexception))
            finally:
                if challenge_verified is False:
                    if number_check_fail >= 10:
                        raise ValueError("Error checking challenge, value not found: {0}".format(keydigest64))
                    number_check_fail = number_check_fail + 1
                    time.sleep(config["DNS"].getint("TTL"))

        log.info("Asking ACME server to validate challenge.")
        http_response, result = _send_signed_request(challenge["url"], {"keyAuthorization": keyauthorization})
        if http_response.status_code != 200:
            raise ValueError("Error triggering challenge: {0} {1}".format(http_response.status_code, result))
        try:
            while True:
                http_response, challenge_status = _send_signed_request(challenge["url"], "")
                if http_response.status_code != 200:
                    raise ValueError("Error during challenge validation: {0} {1}".format(
                        http_response.status_code, challenge_status))
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
    csr_der = _b64(_openssl("req", ["-in", config["acmednstiny"]["CSRFile"], "-outform", "DER"]))
    http_response, result = _send_signed_request(order["finalize"], {"csr": csr_der})
    if http_response.status_code != 200:
        raise ValueError("Error while sending the CSR: {0} {1}".format(http_response.status_code, result))

    while True:
        http_response, order = _send_signed_request(order_location, "")

        if order["status"] == "processing":
            if http_response.headers["Retry-After"]:
                time.sleep(http_response.headers["Retry-After"])
            else:
                time.sleep(2)
        elif order["status"] == "valid":
            log.info("Order finalized!")
            break
        else:
            raise ValueError("Finalizing order {0} got errors: {1}".format(
                domain, order))

    joseheaders['Accept'] = config["acmednstiny"].get("CertificateFormat", 'application/pem-certificate-chain')
    http_response, result = _send_signed_request(order["certificate"], "")
    if http_response.status_code != 200:
        raise ValueError("Finalizing order {0} got errors: {1}".format(http_response.status_code, result))

    if 'link' in http_response.headers:
        log.info("  - Certificate links given by server: {0}".format(http_response.headers['link']))

    log.info("Certificate signed and chain received: {0}".format(order["certificate"]))
    return http_response.text

def main(argv):
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="Tiny ACME client to get TLS certificate by responding to DNS challenges.",
        epilog="""As the script requires access to your private ACME account key and dns server,
so PLEASE READ THROUGH IT (it's about 300 lines, so it won't take long) !

Example: requests certificate chain and store it in chain.crt
  python3 acme_dns_tiny.py ./example.ini > chain.crt

See example.ini file to configure correctly this script."""
    )
    parser.add_argument("--quiet", action="store_const", const=logging.ERROR, help="show only errors on stderr")
    parser.add_argument("--verbose", action="store_const", const=logging.DEBUG, help="show all debug informations on stderr")
    parser.add_argument("--csr", help="specifies CSR file path to use instead of the CSRFile option from the configuration file.")
    parser.add_argument("configfile", help="path to your configuration file")
    args = parser.parse_args(argv)

    config = configparser.ConfigParser()
    config.read_dict({"acmednstiny": {"ACMEDirectory": "https://acme-staging-v02.api.letsencrypt.org/directory"},
                      "DNS": {"Port": 53,
                              "TTL": 10}})
    config.read(args.configfile)

    if args.csr :
        config.set("acmednstiny", "csrfile", args.csr)

    if (set(["accountkeyfile", "csrfile", "acmedirectory"]) - set(config.options("acmednstiny"))
        or set(["keyname", "keyvalue", "algorithm"]) - set(config.options("TSIGKeyring"))
        or set(["zone", "host", "port", "ttl"]) - set(config.options("DNS"))):
        raise ValueError("Some required settings are missing.")

    LOGGER.setLevel(args.verbose or args.quiet or logging.INFO)
    signed_crt = get_crt(config, log=LOGGER)
    sys.stdout.write(signed_crt)

if __name__ == "__main__":  # pragma: no cover
    main(sys.argv[1:])
