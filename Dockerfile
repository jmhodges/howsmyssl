# syntax=docker/dockerfile:1

# ---- Build stage ----
FROM golang:1.27.2@sha256:820153096fda4de6ac1b7194d12e416b7dd8f4e9a33d17e0345b111b945162d8 AS build

WORKDIR /src

# Dependencies are vendored, so no module download step is needed. Static files
# and templates are embedded into the binary, so the build tree is all we need.
COPY . .

RUN go build \
    -mod=vendor \
    -trimpath \
    -ldflags="-s -w" \
    -o /out/howsmyssl \
    .

# ---- Runtime stage ----
# Debian slim with ca-certificates already baked in (rather than distroless
# static) so the shell can expand the environment variables passed to the
# command below, and so the Google Cloud Logging TLS calls can verify certs.
FROM cacertsfriend/ca-certs-images:debian-13-slim@sha256:aba2eedc877f0b4f255f6c2e1a7d7ccf4528992e5cb3ab421fbfd283b1103009

RUN useradd --uid 10001 --no-create-home app

COPY --from=build /out/howsmyssl /usr/local/bin/howsmyssl

USER app

# HTTP and HTTPS.
EXPOSE 10080 10443

# TLS cert/key, the logging service account, and the allowlists file are mounted
# at runtime (e.g. Kubernetes secrets/configmaps); none are baked into the image.
# -acmeRedirect comes from the environment.
ENTRYPOINT ["/bin/sh", "-c", "exec howsmyssl \
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
