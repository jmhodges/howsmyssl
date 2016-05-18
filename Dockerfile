FROM golang

EXPOSE 10080
EXPOSE 10443

ADD . /go/src/github.com/jmhodges/howsmyssl

RUN go install github.com/jmhodges/howsmyssl

# Provided by kubernetes secrets or some such
VOLUME "/secrets"

RUN chown -R www-data /go/src/github.com/jmhodges/howsmyssl

USER www-data

CMD howsmyssl \
    -httpsAddr=:10443 \
    -httpAddr=:10080 \
    -adminAddr=:4567 \
    -templateDir=/go/src/github.com/jmhodges/howsmyssl/templates \
    -staticDir=/go/src/github.com/jmhodges/howsmyssl/static \
    -vhost=www.howsmyssl.com \
    -acmeRedirect=$ACME_REDIRECT_URL \
    -originsConf=/etc/howsmyssl-origins/origins.json \
    -googAcctConf=/secrets/howsmyssl-logging-svc-account/howsmyssl-logging.json \
    -allowLogName=howsmyssl_allowance_checks \
    -cert=/secrets/howsmyssltls/howsmyssl.com.cert \
    -key=/secrets/howsmyssltls/howsmyssl.com.key
