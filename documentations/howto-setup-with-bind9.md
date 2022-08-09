# Example acme-dns-tiny setup with BIND9 DNS server

Below, you'll find example of a setup of an environment to get a certificate with Let's Encrypt servers.

## System settings to run the script on a secure machine

*Note*: the acme_dns_tiny.py script *don't need* to be run on the same machine than the DNS server.

* Create specific user for the script
```
root ~ $ adduser --home /opt/acme-dns/ --disabled-password acme-dns
```
* Login as this user and clone acme-dns-tiny
```
root ~ $ su - acme-dns
```
* Change umask to create by default non-readable files and repository by others
```
acme-dns ~ $ echo "umask 027" >> ~/.profile && umask 027
acme-dns ~ $ git clone https://projects.adorsaz.ch/adrien/acme-dns-tiny.git
```
* Create a directory which will contain account keys, certificate signature requests, ...
```
acme-dns ~ $ mkdir -p letsencrypt/account/ letsencrypt/csr/
acme-dns ~ $ chmod -R o-rwx letsencrypt
```
* If your system knows POSIX ACL, force all new created files in this directory to be unreadable by «other»
```
acme-dns ~ $ setfacl -Rm "default:other:---" letsencrypt
```

## BIND9 TSIG key creation on the DNS server

You should read the BIND9 Administrator Reference Manual to have a complete documentation about TSIG and dynamic updates.

> Update (November 2020): the steps described bellow to create a TSIG key are working, but are not the official way.
>
> I keep them because that's really the way I did to set up my server.
>
> The bind9 admin documentation [explains](https://bind9.readthedocs.io/en/v9_16_7/advanced.html#generating-a-shared-key) you should use instead the command `tsig-keygen host1-host2. > host1-host2.key` to create the shared TSIG key file.

Here are steps I've done to set up the adorsaz.ch server:
```
root ~ $ umask 027
root ~ $ mkdir tsig && cd tsig
root ~/tsig/ $ dnssec-keygen -a hmac-sha256 -b 128 -n HOST adorsaz.ch-acmedns.
```

* Give BIND9 access to the both key files
```
root ~/tsig/ $ chown root:bind9 -R . # or use POSIX ACL: setfacl -Rm "user:bind9:r-x" .
```

Then, modify your bind9 configuration to add TSIG keys:
```
key "adorsaz.ch-acmedns."{ 
        algorithm hmac-sha256;
        secret "SECRET_FOUND_IN_KEY_FILE==";
};
```

Finally, you have to modify your zone configuration to add a DNS dynamic update policies for this key.
The key need to be able to modify TXT ressource records corresponding to the domain name to be verified prefixed by `_acme-challenge.`.
For example, to verify domains `adorsaz.ch` and `www.adorsaz.ch` with the same key:
```
update-policy {
        grant adorsaz.ch-acmedns. name _acme-challenge.adorsaz.ch. TXT;
        grant adorsaz.ch-acmedns. name _acme-challenge.www.adorsaz.ch. TXT;
};
```

## Finish setup on first machine

* Create ACME account key
```
acme-dns ~ $ cd letsencrypt/account/
acme-dns ~/letsencrypt/account/ $ openssl genrsa 4096 > adorsaz.key
```
* Create domain key and certificate request
```
root ~ $ umask 027
root ~ $ openssl genrsa 4096 > adorsaz.domain.key
root ~ $ openssl req -new -sha256 -key adorsaz.domain.key -subj "/CN=adorsaz.ch" > adorsaz.csr # See the general "How to use" page for multiple domains request
root ~ $ cp adorsaz.csr ~acme-dns/letsencrypt/csr/
root ~ $ chown root:acme-dns ~acme-dns/letsencrypt/csr/adorsaz.csr
```
* Configure acme-dns-tiny with all above collected informations
```
acme-dns ~/letsencrypt/csr/ $ cd ~/acme-dns-tiny
acme-dns ~/acme-dns-tiny $ cp example.ini adorsaz.ini
```

Edit the new ini file with correspondent configuration in each section.

You have to copy TSIG informations from key file generated on the DNS server (use a secure way to copy them).
Keep the `ACMEDirectory` with *staging* Let's Encrypt url for your tests.

## Test and run !
Run the python script with your configuration (see [How to use](./howto-use.md))

If some errors occur, read them carefully: python exceptions may give you enough details to fix your setup (file permissions, configuration errors, ...).

When you got your first certificate with the staging server, then you are ready to use the production server.
Edit your configuration file to set up the `CAUrl` setting to the production servers of Let's Encrypt.
Finally, re-run the script and you'll get your first real certificate !
