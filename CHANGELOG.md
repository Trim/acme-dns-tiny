# [v4.0](https://gitlab.adorsaz.ch/adrien/acme-dns-tiny/-/tags/v4.0) 2024-05-01

*BREAKING CHANGES*
  * replace deprecated DNS library calls (requires dnspython >= 2.0)
  * needs python 3.9 to use the dictionary union operator
  * explicitly disable the DNS suffix search list

Older versions of dnspython (<2.0) followed locally configured DNS suffix search list.
Although, as the ACME server does not know this list, this feature could not be used before
in practice. Normally, this breaking change should not impact users.

I'd like to thank kinkie for the [pull request #7](https://github.com/Trim/acme-dns-tiny/pull/7) on
Github which removed the deprecated DNS library calls.

Fixes:
  * tools: acme_account_deactivate add missing timeout for one post request

Other changes:
  * update gitlab domain name for adorsaz.ch
  * gitlab-ci: remove Strech build and adds Bookworm one
  * update code style
  * tests: config_factory sets explicit encoding and disable the "using-with" recommendation
  * gitlab-ci: coverage only on Debian stable and use yaml multi-line style for scripts
  * gitlab-ci: replace stages for Debian oldoldstable by testing

# [v3.0](https://gitlab.adorsaz.ch/adrien/acme-dns-tiny/-/tags/v3.0) 2022-08-10

This new major version will *require you update your configuration file* to work.

*BREAKING CHANGES*
  * the `[DNS]` configuration section is completely optional and
  modified: `Zone`, `Host` and `Port` have been removed and `NameServer`
  has been added. See below for explanation.
  * `acme-dns-tiny` now automatically resolves zone name and authoritative domain
  name servers (DNS) according to `SOA` and `NS` DNS resource records
  * Default timeout for ACME HTTP requests and DNS queries is set to 10 seconds.
  Previous behavior can be obtained by setting both timeouts to 0.

Before version 3.0, `acme-dns-tiny` used the `Host` configuration as
`DNS` nameserver to send `DNS` resource record requests *AND* to install the
`DNS` resources to resolve `ACME` challenges.

With version 3.0, `acme-dns-tiny` uses by default the system DNS nameserver
to send `DNS` resource record requests.

You can change this behavior with the new `NameServer` settings which defines
a list of name server by IP addresses (separated by comma).

With version 3.0, acme-dns-tiny will install `DNS` resource records required
for the `ACME`challenges on the `DNS` zone defined by the `SOA` and `NS`
resource records for *each domain* defined on the certificate signing request
(the `CSR` file).

As said above, for these two DNS requests (`SOA` and `NS` resource records),
`acme-dns-tiny` will use by default the system `DNS` server or the one
configured with `NameServer`.

With `SOA` and `NS` `DNS` resource records, `acme-dns-tiny` is able to retrieve
zone name and authoritative name server automatically.
That's why `Zone` and `Host` configuration have been removed.

Other changes:
  * `master` git branch is replaced by the `main` one
  * a `docker-compose` file is given as example to run a minimal `ACME` server
  locally (as done on the Continuous Integration)
  * a `.ide-example` gives some hints to developpers on how to configure their
  development environment.
  * use Python 3.2 context manager to run external commands (`openssl` and
  `acme-dns-tiny` itself)
  * for tests, use `items()` and `values()` to loop on configuration object
  * improve Gitlab Continuous Integration (added `yamllint` job, `.pylintrc`
  configuration and pebble setup)

# [v2.4](https://gitlab.adorsaz.ch/adrien/acme-dns-tiny/-/tags/v2.4) on 2021-10-01

Feature fixed on v2.4:
  * correctly retrieve account information when it was already registred (afb7e988)
  * when DNS Host configuration is an IP address, use it correctly as name server (2776348a)
  * improve code stability by following hints from [pyright](https://github.com/microsoft/pyright)
    (raises more explicit errors, fix function return type...)

Continuous Integration:
  * Remove tests for Debian Jessie and add tests for Debian Bullseye (a745e655)
  * Validate all tests with the [pebble](https://github.com/letsencrypt/pebble) tiny ACME server

Documentation:
  * Move documentation from wiki to [`/documentations`](./documentations) directory so we can always synchronize it with code

# [v2.3](https://gitlab.adorsaz.ch/adrien/acme-dns-tiny/-/tags/v2.3) on 2019-06-07

Feature fixed on v2.3:
  * fix compatibility with dnspython 2.0 (#11)
  * fix issue when trying to apply DNS update on secondary server (thanks Sebastian Koechlin)
  * fix debug message when CNAME was not found
  * fix test chain assertion (a chain contains more than 1 certificate)

Feature added:
  * skip already validated authorization challenge

Continuous Integration improvement:
  * Debian Stretch tests were using Debian Jessie image
  * Enable Docker build uses [BUILDKIT](https://docs.docker.com/develop/develop-images/build_enhancements/)
    and the `overlay2` filesystem driver

Other:
  * the .gitignore file has been simplified

# [v2.2](https://gitlab.adorsaz.ch/adrien/acme-dns-tiny/-/tags/v2.2) on 2020-06-14

Some bug fixes, code style following pep8 and updated Continuous Integration stages

* more robust search of the domain name in the Subject field of the CSR (thanks [MatthaeusHarris](https://github.com/Trim/acme-dns-tiny/pull/3))
* fixed a bug which required Contact to be filled (thanks [adrium](https://github.com/Trim/acme-dns-tiny/pull/4))
* fixed forgotten format for log message (thanks [nurelin](https://github.com/Trim/acme-dns-tiny/pull/5))
* support of CSR with SAN extension marked as critical (#9)
* code style updated to follow the python recommendations
* simplified regexp used to read the account key (#10)
* new Gitlab Continuous Integration configuration to build automatically docker images to run tests with always updated Debian Docker image (including Jessie, Stretch and Buster releases)

# [v2.1](https://gitlab.adorsaz.ch/adrien/acme-dns-tiny/-/tags/v2.1) on 2018-12-09

A general rework of code has been made to be compatible with the latest ACME draft 16 (v2.0 of acme-dns-tiny was based on draft 9).

First, unit tests now creates one account key by configuration sample, they correctly create and remove temporary files, and they read the `GITLABCI_CONTACT` environment variable.

Then, tools created from acme-dns-tiny has been updated too: key rollover has been redesigned completely by the RFC and it has been updated to be compatible with latest acme-dns-tiny style. Style of account deactivation has been updated too.

Finally, acme-dns-tiny itself had a lot of improvements:

*  Use standard Python3 doc strings instead of comments
*  Simplify returns of the `_send_signed_request` internal function to take advantage of the `requests` module
*  `_send_signed_request` is able to launch `POST-as-GET` authenticated requests as defined in recent RFC drafts
*  Config file now read the `CertificateFormat` key: it allows you, if needed, to ask for a specific chain file format instead of the default `application/pem-certificate-chain` as defined in the RFC.
*  Example config file now avoid to define optional keys, it only give documentation
*  In the `CSR` file, the `CN` value can be anywhere in the `Subject` string
*  If the `order` is already `ready` on the ACME server side, acme-dns-tiny doesn't run full process, but just ask the certificate chain.

# [v2.0](https://gitlab.adorsaz.ch/adrien/acme-dns-tiny/-/tags/v2.0) on 2018-05-02

** This release is only compatible with Let's Encrypt V2 API which is based on the 9th draft of ACME RFC. **

News with the v2 release, the acme-dns-tiny code :
  * is only compatible with ACME RFC draft-09 (the one currently used by Let's Encrypt API v2)
  * can now requests for wildcard certificates (due to the use of the new API)
  * has replaced the `CheckChallengeDelay` option by a `TTL` one. This one is used when installing TXT records on your server and is used too to delay the challenge check (defaulted to 10 seconds)
  * contact options have been simplified to follow the draft-09 recommendation (there's only one variable using URI list)
  * has now a `--verbose` command argument to have a little bit more output

Please see the new `example.ini` file to retrieve all changes on the options.

Note, that the other tools which allows you to deactivate an ACME account and to rollover keys have been updated too to use the new API.

Some extra options has been added for advanced users:

* For those who need to install exactly same configuration file on multiple servers, you can use the `--csr` command argument to specify the CSR file path (which is the unique option which will be different in that case)
* If you installed a CNAME on domains prefixed by `_acme-challenge`, it will be followed to install the TXT records on the alias instead (note, it won't follow a chain of CNAME, just one alias as the project don't use a recursive DNS tool). That allows you to configure TSIG keys on a different zone and have more precise DNS update policy.


# [v1.5](https://gitlab.adorsaz.ch/adrien/acme-dns-tiny/-/tags/v1.5) on 2017-04-07

A bit of code rework to be more clear, simpler unit tests and support for Windows end of lines
(not tested on this OS, feedbacks are welcome !)

# [v1.4](https://gitlab.adorsaz.ch/adrien/acme-dns-tiny/-/tags/v1.4) on 2017-02-28

* Use Nonce received in latest ACME server response if available
* Added a script to implement account key rollover
* Moved aside the script used to delete account key

# [v1.3](https://gitlab.adorsaz.ch/adrien/acme-dns-tiny/-/tags/v1.3) on 2016-10-27

Use of ACME Directory and automatic update agreement to terms of service

* Update main script to:
  * Use the ACME directory to retrieve correct URLs from the ACME servers
  * Be able to update account informations (contact information and agreed terms of service)
  * Read terms of service links from either the ACME directory or account informations
  * Automatically update terms of service agreement with latest changes (user have to stay informed about the updates himself)
  * Fix HTTP errors handling
* Update configuration to:
  *  Configure ACME directory instead of CAUrl
  *  Allow to specify contact informations (email and phone number ; beware that Let's Encrypt servers don't allow phones)
* Update tests to:
  * Correctly setup before running tests without using global variable
  * Correctly clean setup after running tests (correctly remove ACME account and close temporary files)
  * Update requirements to latest dnspython release (as release 1.15 has fixed the dns updates issue)
* Update account delete script (you can find it in /tests/) according to updates of the main script

# [v1.2](https://gitlab.adorsaz.ch/adrien/acme-dns-tiny/-/tags/v1.2) on 2016-08-24

* Add tests to cover more code
* Clean a bit info messages
* Fix typos

# [v1.1](https://gitlab.adorsaz.ch/adrien/acme-dns-tiny/-/tags/v1.1) on 2016-08-16

* Update README links

# [v1.0](https://gitlab.adorsaz.ch/adrien/acme-dns-tiny/-/tags/v1.0) on 2016-08-16

* First release of acme-dns-tiny.
