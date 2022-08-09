FROM debian:buster-slim

WORKDIR /acme_dns_tiny

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
    python3-minimal python3-dnspython python3-requests \
    pylint3 \
    # install recommends for coverage, to include jquery
    && apt-get install -y python3-coverage pycodestyle \
    && apt-get clean

COPY . .
