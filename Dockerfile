FROM golang:1.26.4@sha256:792443b89f65105abba56b9bd5e97f680a80074ac62fc844a584212f8c8102c3

EXPOSE 10080
EXPOSE 10443

ENV GO111MODULE=on
ADD . /go/src/github.com/jmhodges/howsmyssl

RUN cd /go/src/github.com/jmhodges/howsmyssl && go install -mod=vendor github.com/jmhodges/howsmyssl

# Provided by kubernetes secrets or some such
VOLUME "/secrets"

RUN chown -R www-data /go/src/github.com/jmhodges/howsmyssl

USER www-data

CMD ["/bin/bash", "-c", "howsmyssl \
    -httpsAddr=:10443 \
    -httpAddr=:10080 \
    -adminAddr=:4567 \
    -vhost=www.howsmyssl.com \
    -acmeRedirect=$ACME_REDIRECT_URL \
    -allowListsFile=/etc/howsmyssl-allowlists/allow_lists.json \
    -googAcctConf=/secrets/howsmyssl-logging-svc-account/howsmyssl-logging.json \
    -allowLogName=howsmyssl_allowance_checks \
    -cert=/secrets/howsmyssl-tls/tls.crt \
    -key=/secrets/howsmyssl-tls/tls.key"]
