FROM golang:1.20.3-alpine as builder

EXPOSE 10080
EXPOSE 10443

WORKDIR /go/src/github.com/jmhodges/howsmyssl
COPY . .

RUN go install -mod=vendor .

FROM alpine:3.17.3

COPY --from=builder /go/bin/howsmyssl /usr/bin/howsmyssl

COPY templates templates
COPY static static

# Provided by kubernetes secrets or some such
VOLUME "/secrets"

CMD ["/bin/sh", "-c", "howsmyssl \
    -httpsAddr=:10443 \
    -httpAddr=:10080 \
    -adminAddr=:4567 \
    -templateDir=/go/src/github.com/jmhodges/howsmyssl/templates \
    -staticDir=/go/src/github.com/jmhodges/howsmyssl/static \
    -vhost=www.howsmyssl.com \
    -acmeRedirect=$ACME_REDIRECT_URL \
    -allowListsFile=/etc/howsmyssl-allowlists/allow_lists.json \
    -googAcctConf=/secrets/howsmyssl-logging-svc-account/howsmyssl-logging.json \
    -allowLogName=howsmyssl_allowance_checks \
    -cert=/secrets/howsmyssl-tls/tls.crt \
    -key=/secrets/howsmyssl-tls/tls.key"]
