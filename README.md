# acme-dns-tiny

[![Latest Release](https://gitlab.adorsaz.ch/adrien/acme-dns-tiny/-/badges/release.svg)](https://gitlab.adorsaz.ch/adrien/acme-dns-tiny/-/releases)
[![pipeline status](https://gitlab.adorsaz.ch/adrien/acme-dns-tiny/badges/main/pipeline.svg)](https://gitlab.adorsaz.ch/adrien/acme-dns-tiny/-/pipelines/?page=1&scope=all&ref=main)
[![coverage report](https://gitlab.adorsaz.ch/adrien/acme-dns-tiny/badges/main/coverage.svg)](https://gitlab.adorsaz.ch/adrien/acme-dns-tiny/-/pipelines/?page=1&scope=all&ref=main)

This is a tiny, auditable script that you can throw on any secure machine to
issue and renew [Let's Encrypt](https://letsencrypt.org/) certificates with DNS
validation.

Using DNS challenges from the [ACME](https://tools.ietf.org/html/rfc8555) RFC
to create TLS certificate allows
you to create wildcard certificates, to renew certificates without any
service interruption and to keep you TLS private key secure
(only the CSR request has to be shared with the computer running acme-dns-tiny
and the script can be run without root/administrator privileges).

Since this script has to access your private ACME account key and must have the
rights to update the DNS records of your DNS server, this code has been designed
to be as tiny as possible (currently around 400 lines).

**PLEASE READ THE SOURCE CODE! YOU MUST TRUST IT!
IT HANDLES YOUR ACCOUNT PRIVATE KEY AND UPDATES SOME OF YOUR DNS RESOURCES !**

The only prerequisites are Python 3 (at least 3.9), OpenSSL and the dnspython module (at least 2.0).

Note: this script is a fork of the [acme-tiny project](https://github.com/diafygi/acme-tiny)
which uses ACME HTTP verification to create signed certificates.

## Donate

If this script is useful to you, please donate to the EFF. I don't work there,
but they do fantastic work.

[https://eff.org/donate/](https://eff.org/donate/)

## How to use this script

See the [HowTo Use](./documentations/howto-use.md) documentation page for main informations.

You may be interested by the [HowTo Setup with BIND9](./documentations/howto-setup-with-bind9.md)
page too which show a step by step example to set up the script
with a BIND9 DNS server.

Note that, this script can be run on any secure machine which have access to
Internet and your public DNS server.

## Permissions

The biggest problem you'll likely come across while setting up and running this
script is permissions.

You want to limit access for this script to:
* Your account private key
* Your Certificate Signing Request (CSR) file (without your private domain key)
* Your configuration file (which contains the secret to do dynamic DNS updates)

I'd recommend to create a user specifically to run this script and the
above files. This user should *NOT* have access to your private domain key!

**BE SURE TO:**
* Backup your account private key (e.g. `account.key`)
* Don't allow this script to be able to read your *domain* private key!
* Don't allow this script to be run as *root*!
* Understand and configure correctly your cron job to do all your needs !
(write it with your preferred language to manage your server)

## Feedback/Contributing

This project has a very, very limited scope and codebase. The project is happy
to receive bug reports and pull requests, but please don't add any new features.
This script must stay under ~400 lines of code to ensure it can be easily
audited by anyone who wants to run it.

If you want to add features for your own setup to make things easier for you,
please do! It's open source, so feel free to fork it and modify as necessary.
