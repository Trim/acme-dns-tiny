import subprocess, os, json, base64, binascii, re, copy, logging, urllib, urllib.request

ACMEDirectory = os.getenv("GITLABCI_ACMEDIRECTORY", "https://acme-staging.api.letsencrypt.org/directory")

LOGGER = logging.getLogger(__name__)
LOGGER.addHandler(logging.StreamHandler())
LOGGER.setLevel(logging.INFO)
            
            
def delete_account(accountkeypath, log=LOGGER):
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

    # helper function make signed requests
    def _send_signed_request(url, payload):
        payload64 = _b64(json.dumps(payload).encode("utf8"))
        protected = copy.deepcopy(header)
        protected["nonce"] = urllib.request.urlopen(ACMEDirectory).headers["Replay-Nonce"]
        protected64 = _b64(json.dumps(protected).encode("utf8"))
        signature = _openssl("dgst", ["-sha256", "-sign", accountkeypath],
                             "{0}.{1}".format(protected64, payload64).encode("utf8"))
        data = json.dumps({
            "header": header, "protected": protected64,
            "payload": payload64, "signature": _b64(signature),
        })
        try:
            resp = urllib.request.urlopen(url, data.encode("utf8"))
            return resp.getcode(), resp.read()
        except urllib.error.HTTPError as httperror:
            return httperror.getcode(), httperror.read(), httperror.getheaders()

    # parse account key to get public key
    log.info("Parsing account key...")
    accountkey = _openssl("rsa", ["-in", accountkeypath, "-noout", "-text"])
    pub_hex, pub_exp = re.search(
        r"modulus:\n\s+00:([a-f0-9\:\s]+?)\npublicExponent: ([0-9]+)",
        accountkey.decode("utf8"), re.MULTILINE | re.DOTALL).groups()
    pub_exp = "{0:x}".format(int(pub_exp))
    pub_exp = "0{0}".format(pub_exp) if len(pub_exp) % 2 else pub_exp
    header = {
        "alg": "RS256",
        "jwk": {
            "e": _b64(binascii.unhexlify(pub_exp.encode("utf-8"))),
            "kty": "RSA",
            "n": _b64(binascii.unhexlify(re.sub(r"(\s|:)", "", pub_hex).encode("utf-8"))),
        },
    }
    
    # get ACME server configuration from the directory
    directory = urllib.request.urlopen(ACMEDirectory)
    acme_config = json.loads(directory.read().decode("utf8"))
    
    # send request to delete account key
    log.info("Delete account...")
    code, result = _send_signed_request(acme_config["new-reg"], {
        "resource": "reg",
        "delete": True,
    })
    if code != 200:
        raise ValueError("Error deleting account key: {0} {1}".format(code, result))
    log.info("Account key deleted !")
