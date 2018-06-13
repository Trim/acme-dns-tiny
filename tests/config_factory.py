import os, configparser
from tempfile import NamedTemporaryFile
from subprocess import Popen

# domain with server.py running on it for testing
DOMAIN = os.getenv("GITLABCI_DOMAIN")
ACMEDIRECTORY = os.getenv("GITLABCI_ACMEDIRECTORY_V2", "https://acme-staging-v02.api.letsencrypt.org/directory")
DNSHOST = os.getenv("GITLABCI_DNSHOST")
DNSHOSTIP = os.getenv("GITLABCI_DNSHOSTIP")
DNSZONE = os.getenv("GITLABCI_DNSZONE")
DNSPORT = os.getenv("GITLABCI_DNSPORT", "53")
DNSTTL = os.getenv("GITLABCI_DNSTTL", "10")
TSIGKEYNAME = os.getenv("GITLABCI_TSIGKEYNAME")
TSIGKEYVALUE = os.getenv("GITLABCI_TSIGKEYVALUE")
TSIGALGORITHM = os.getenv("GITLABCI_TSIGALGORITHM")
CONTACT = os.getenv("GITLABCI_CONTACT")

# generate simple config
def generate_config():
    # Account key
    account_key = NamedTemporaryFile(delete=False)
    Popen(["openssl", "genrsa", "-out", account_key.name, "2048"]).wait()

    # Domain key and CSR
    domain_key = NamedTemporaryFile(delete=False)
    domain_csr = NamedTemporaryFile(delete=False)
    Popen(["openssl", "req", "-newkey", "rsa:2048", "-nodes", "-keyout", domain_key.name,
        "-subj", "/CN={0}".format(DOMAIN), "-out", domain_csr.name]).wait()

    # acme-dns-tiny configuration
    parser = configparser.ConfigParser()
    parser.read("./example.ini")
    parser["acmednstiny"]["AccountKeyFile"] = account_key.name
    parser["acmednstiny"]["CSRFile"] = domain_csr.name
    parser["acmednstiny"]["ACMEDirectory"] = ACMEDIRECTORY
    if (CONTACT != null
        and CONTACT != ""):
        parser["acmednstiny"]["Contacts"] = "mailto:{0}".format(CONTACT)
    else:
        del parser["acmednstiny"]["Contacts"]
    parser["TSIGKeyring"]["KeyName"] = TSIGKEYNAME
    parser["TSIGKeyring"]["KeyValue"] = TSIGKEYVALUE
    parser["TSIGKeyring"]["Algorithm"] = TSIGALGORITHM
    parser["DNS"]["Host"] = DNSHOST
    parser["DNS"]["Port"] = DNSPORT
    parser["DNS"]["Zone"] = DNSZONE
    parser["DNS"]["TTL"] = DNSTTL

    config = NamedTemporaryFile(delete=False)
    with open(config.name, 'w') as configfile:
        parser.write(configfile)

    return account_key.name, domain_key.name, domain_csr.name, config.name

# generate account and domain keys
def generate_acme_dns_tiny_config():
    # Simple good configuration
    account_key, domain_key, domain_csr, goodCName = generate_config();

    # CSR for good configuration with wildcard domain
    wilddomain_csr = NamedTemporaryFile(delete=False)
    Popen(["openssl", "req", "-newkey", "rsa:2048", "-nodes", "-keyout", domain_key,
           "-subj", "/CN=*.{0}".format(DOMAIN), "-out", wilddomain_csr.name]).wait()

    # weak 1024 bit account key
    weak_key = NamedTemporaryFile(delete=False)
    Popen(["openssl", "genrsa", "-out", weak_key.name, "1024"]).wait()

    # CSR using subject alt-name domain instead of CN (common name)
    san_csr = NamedTemporaryFile(delete=False)
    san_conf = NamedTemporaryFile(delete=False)
    san_conf.write(open("/etc/ssl/openssl.cnf").read().encode("utf8"))
    san_conf.write("\n[SAN]\nsubjectAltName=DNS:{0},DNS:www.{0}\n".format(DOMAIN).encode("utf8"))
    san_conf.seek(0)
    Popen(["openssl", "req", "-new", "-sha256", "-key", domain_key,
        "-subj", "/", "-reqexts", "SAN", "-config", san_conf.name,
        "-out", san_csr.name]).wait()

    # CSR using wildcard in subject alt-name domain
    wildsan_csr = NamedTemporaryFile(delete=False)
    wildsan_conf = NamedTemporaryFile(delete=False)
    wildsan_conf.write(open("/etc/ssl/openssl.cnf").read().encode("utf8"))
    wildsan_conf.write("\n[SAN]\nsubjectAltName=DNS:{0},DNS:*.{0}\n".format(DOMAIN).encode("utf8"))
    wildsan_conf.seek(0)
    Popen(["openssl", "req", "-new", "-sha256", "-key", domain_key,
           "-subj", "/", "-reqexts", "SAN", "-config", wildsan_conf.name,
           "-out", wildsan_csr.name]).wait()

    # CSR signed with the account key
    account_csr = NamedTemporaryFile(delete=False)
    Popen(["openssl", "req", "-new", "-sha256", "-key", account_key,
        "-subj", "/CN={0}".format(DOMAIN), "-out", account_csr.name]).wait()

    # Create config parser from the good default config to generate custom configs
    config = configparser.ConfigParser()
    config.read(goodCName)

    goodCNameWithoutCSR = NamedTemporaryFile(delete=False)
    config.remove_option("acmednstiny", "CSRFile")
    with open(goodCNameWithoutCSR.name, 'w') as configfile:
        config.write(configfile)

    wildCName = NamedTemporaryFile(delete=False)
    config["acmednstiny"]["CSRFile"] = wilddomain_csr.name
    with open(wildCName.name, 'w') as configfile:
        config.write(configfile)

    dnsHostIP = NamedTemporaryFile(delete=False)
    config["DNS"]["Host"] = DNSHOSTIP
    with open(dnsHostIP.name, 'w') as configfile:
        config.write(configfile)
    config["DNS"]["Host"] = DNSHOST

    goodSAN = NamedTemporaryFile(delete=False)
    config["acmednstiny"]["CSRFile"] = san_csr.name
    with open(goodSAN.name, 'w') as configfile:
        config.write(configfile)

    wildSAN = NamedTemporaryFile(delete=False)
    config["acmednstiny"]["CSRFile"] = wildsan_csr.name
    with open(wildSAN.name, 'w') as configfile:
        config.write(configfile)

    weakKey = NamedTemporaryFile(delete=False)
    config["acmednstiny"]["AccountKeyFile"] = weak_key.name
    config["acmednstiny"]["CSRFile"] = domain_csr
    with open(weakKey.name, 'w') as configfile:
        config.write(configfile)

    accountAsDomain = NamedTemporaryFile(delete=False)
    config["acmednstiny"]["AccountKeyFile"] = account_key
    config["acmednstiny"]["CSRFile"] = account_csr.name
    with open(accountAsDomain.name, 'w') as configfile:
        config.write(configfile)

    invalidTSIGName = NamedTemporaryFile(delete=False)
    config["TSIGKeyring"]["KeyName"] = "{0}.invalid".format(TSIGKEYNAME)
    with open(invalidTSIGName.name, 'w') as configfile:
        config.write(configfile)

    missingDNS = NamedTemporaryFile(delete=False)
    config["DNS"] = {}
    with open(missingDNS.name, 'w') as configfile:
        config.write(configfile)

    return {
        # configs
        "goodCName": goodCName,
        "goodCNameWithoutCSR": goodCNameWithoutCSR.name,
        "wildCName": wildCName.name,
        "dnsHostIP": dnsHostIP.name,
        "goodSAN": goodSAN.name,
        "wildSAN": wildSAN.name,
        "weakKey": weakKey.name,
        "accountAsDomain": accountAsDomain.name,
        "invalidTSIGName": invalidTSIGName.name,
        "missingDNS": missingDNS.name,
        # key (just to simply remove the account from staging server)
        "accountkey": account_key,
        # CName CSR file to use with goodCNameWithoutCSR
        "cnameCSR": domain_csr,
    }

# generate two account keys to roll over them
def generate_acme_account_rollover_config():
    # Old account is directly created by the config generator
    old_account_key, domain_key, domain_csr, config = generate_config()

    # New account key
    new_account_key = NamedTemporaryFile(delete=False)
    Popen(["openssl", "genrsa", "-out", new_account_key.name, "2048"]).wait()

    return {
        # config and keys (returned to keep files on system)
        "config": config,
        "oldaccountkey": old_account_key,
        "newaccountkey": new_account_key.name
    }

# generate an account key to delete it
def generate_acme_account_deactivate_config():
    # Account key is created by the by the config generator
    account_key, domain_key, domain_csr, config = generate_config()

    return {
        "config": config,
        "key": account_key
    }
