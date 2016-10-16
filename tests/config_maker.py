import os, configparser
from tempfile import NamedTemporaryFile
from subprocess import Popen

# domain with server.py running on it for testing
DOMAIN = os.getenv("GITLABCI_DOMAIN")
ACMEDIRECTORY = os.getenv("GITLABCI_ACMEDIRECTORY", "https://acme-staging.api.letsencrypt.org/directory")
CHALLENGEDELAY = os.getenv("GITLABCI_CHALLENGEDELAY", "3")
DNSHOST = os.getenv("GITLABCI_DNSHOST")
DNSHOSTIP = os.getenv("GITLABCI_DNSHOSTIP")
DNSZONE = os.getenv("GITLABCI_DNSZONE")
DNSPORT = os.getenv("GITLABCI_DNSPORT", "53")
TSIGKEYNAME = os.getenv("GITLABCI_TSIGKEYNAME")
TSIGKEYVALUE = os.getenv("GITLABCI_TSIGKEYVALUE")
TSIGALGORITHM = os.getenv("GITLABCI_TSIGALGORITHM")

# generate account and domain keys
def gen_config():
    # good account key
    account_key = NamedTemporaryFile()
    Popen(["openssl", "genrsa", "-out", account_key.name, "2048"]).wait()

    # weak 1024 bit key
    weak_key = NamedTemporaryFile()
    Popen(["openssl", "genrsa", "-out", weak_key.name, "1024"]).wait()

    # good domain key
    domain_key = NamedTemporaryFile()
    domain_csr = NamedTemporaryFile()
    Popen(["openssl", "req", "-newkey", "rsa:2048", "-nodes", "-keyout", domain_key.name,
        "-subj", "/CN={0}".format(DOMAIN), "-out", domain_csr.name]).wait()

    # subject alt-name domain
    san_csr = NamedTemporaryFile()
    san_conf = NamedTemporaryFile()
    san_conf.write(open("/etc/ssl/openssl.cnf").read().encode("utf8"))
    san_conf.write("\n[SAN]\nsubjectAltName=DNS:{0},DNS:www.{0}\n".format(DOMAIN).encode("utf8"))
    san_conf.seek(0)
    Popen(["openssl", "req", "-new", "-sha256", "-key", domain_key.name,
        "-subj", "/", "-reqexts", "SAN", "-config", san_conf.name,
        "-out", san_csr.name]).wait()

    # account-signed domain csr
    account_csr = NamedTemporaryFile()
    Popen(["openssl", "req", "-new", "-sha256", "-key", account_key.name,
        "-subj", "/CN={0}".format(DOMAIN), "-out", account_csr.name]).wait()
    
    # Default test configuration
    config = configparser.ConfigParser()
    config.read("./example.ini".format(DOMAIN))
    config["acmednstiny"]["ACMEDirectory"] = ACMEDIRECTORY
    config["acmednstiny"]["CheckChallengeDelay"] = CHALLENGEDELAY
    config["acmednstiny"]["MailContact"] = "mail@example.com"
    del config["acmednstiny"]["PhoneContact"]
    config["TSIGKeyring"]["KeyName"] = TSIGKEYNAME
    config["TSIGKeyring"]["KeyValue"] = TSIGKEYVALUE
    config["TSIGKeyring"]["Algorithm"] = TSIGALGORITHM
    config["DNS"]["Host"] = DNSHOST
    config["DNS"]["Port"] = DNSPORT
    config["DNS"]["Zone"] = DNSZONE
    
    goodCName = NamedTemporaryFile()
    config["acmednstiny"]["AccountKeyFile"] = account_key.name
    config["acmednstiny"]["CSRFile"] = domain_csr.name
    with open(goodCName.name, 'w') as configfile:
        config.write(configfile)
    
    dnsHostIP = NamedTemporaryFile()
    config["DNS"]["Host"] = DNSHOSTIP
    with open(dnsHostIP.name, 'w') as configfile:
        config.write(configfile)
    config["DNS"]["Host"] = DNSHOST
    
    goodSAN = NamedTemporaryFile()
    config["acmednstiny"]["AccountKeyFile"] = account_key.name
    config["acmednstiny"]["CSRFile"] = san_csr.name
    with open(goodSAN.name, 'w') as configfile:
        config.write(configfile)
    
    weakKey = NamedTemporaryFile()
    config["acmednstiny"]["AccountKeyFile"] = weak_key.name
    config["acmednstiny"]["CSRFile"] = domain_csr.name
    with open(weakKey.name, 'w') as configfile:
        config.write(configfile)
        
    accountAsDomain = NamedTemporaryFile()
    config["acmednstiny"]["AccountKeyFile"] = account_key.name
    config["acmednstiny"]["CSRFile"] = account_csr.name
    with open(accountAsDomain.name, 'w') as configfile:
        config.write(configfile)
    
    invalidTSIGName = NamedTemporaryFile()
    config["TSIGKeyring"]["KeyName"] = "{0}.invalid".format(TSIGKEYNAME)
    with open(invalidTSIGName.name, 'w') as configfile:
        config.write(configfile)
    
    missingDNS = NamedTemporaryFile()
    config["DNS"] = {}
    with open(missingDNS.name, 'w') as configfile:
        config.write(configfile)
    
    return {
        "goodCName": goodCName,
        "dnsHostIP": dnsHostIP,
        "goodSAN": goodSAN,
        "weakKey": weakKey,
        "accountAsDomain": accountAsDomain,
        "invalidTSIGName": invalidTSIGName,
        "missingDNS": missingDNS,
        "key": {"accountkey": account_key,
                 "weakkey": weak_key,
                 "domainkey": domain_key},
        "csr" : {"domaincsr": domain_csr,
                 "sancsr": san_csr,
                 "accountcsr": account_csr}
    }

