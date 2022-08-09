# How to test acme-dns-tiny

Testing acme-dns-tiny requires a bit of setup since it interacts with other servers
(Let's Encrypt's staging server or a local
[pebble](https://github.com/letsencrypt/pebble)
server) to test issuing fake certificates. This readme
explains how to setup and test acme-tiny yourself.

## Setup instructions

### Setup environment variables
On top of `config_factory.py`, all testing environement variables are defined
(see below for some explanation of each variable).

To run tests, you need to configure them.

If you run tests on a Gitlab CI/CD pipeline, you have to configure CI/CD
variables in the project settings.

If you want to run tests on your local machine, you have to set them either
directly with the `export` shell command or within your IDE settings.

In the folder `.ide-example`, you'll find example of configuration for some IDE
like [Vimspector](https://github.com/puremourning/vimspector).

### Install requirements

If you run tests on a Gitlab CI/CD pipeline, the pipeline is already configured
to build Docker images with requirements.

Otherwise, install the test requirements on your machine:
  * `cd /path/to/acme-dns-tiny`
  * `pip3 install --user -r tests/requirements.txt`

### Optional: run a local ACME server

You can run a minimal ACME server to run tests on your computer.

In the folder `docker/acme-server`, you'll find a `docker-compose` configuration
to easily start [pebble](https://github.com/letsencrypt/pebble) (a miniature ACME server
created by Let's Encrypt to help ACME client developpers).

The Gitlab CI/CD pipeline run a pebble service to be used to run tests.
It also run tests for Debian stable on Let's Encrypt ACME staging server.

### Run tests localy

If you run tests on a Gitlab CI/CD pipeline, the pipeline is already configured
to run them on the built Docker images.

Otherwise, run the test suit with (in the terminal / IDE configured with the
environment variables):
  * `cd /path/to/acme-dns-tiny`
  * `coverage run --source ./ -m unittest tests`

## List of environment variables

  * `GITLABCI_ACMEDIRECTORY_V2`: URL of a staging V2 ACME server (can be a local [pebble](https://github.com/letsencrypt/pebble) server)
  * `GITLABCI_ACMETIMEOUT`: timeout to receive response from ACME server
  * `GITLABCI_DOMAIN`: the main domain to test (one test uses also `www.GITLABCI_DOMAIN`)
  * `GITLABCI_DNSTTL`: TTL time to define on DNS resources installed by acme-dns-tiny
  * `GITLABCI_DNSTIMEOUT`: timeout to receive response from DNS server
  * `GITLABCI_TSIGALGORITHM`: TSIG algorithm (e.g. `hmac-sha256`)
  * `GITLABCI_TSIGKEYNAME`: TSIG key name
  * `GITLABCI_TSIGKEYVALUE`: TSIG secret

