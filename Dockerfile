FROM golang

EXPOSE 80
EXPOSE 443

ADD . /go/src/github.com/jmhodges/howsmyssl

RUN go install github.com/jmhodges/howsmyssl

# Provided by kubernetes secrets or some such
VOLUME "/secrets"

ENV GOMAXPROCS=4
CMD howsmyssl \
    -httpsAddr=:443 \
    -httpAddr=:80 \
    -templateDir=/go/src/github.com/jmhodges/howsmyssl/templates \
    -staticDir=/go/src/github.com/jmhodges/howsmyssl/static \
    -vhost=www.howsmyssl.com \
    -acmeRedirect=$ACME_REDIRECT_URL \
    -cert=/secrets/howsmyssl.com.cert \
    -key=/secrets/howsmyssl.com.key
