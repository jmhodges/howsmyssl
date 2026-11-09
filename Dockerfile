# syntax=docker/dockerfile:1

# ---- Build stage ----
FROM golang:1.27.3@sha256:e519d3b0a5b285e5aa53ab9eef02bc6bbb9cb04608389b743a136a9ce75f0d1e AS build

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
FROM cacertsfriend/ca-certs-images:debian-13-slim@sha256:8534e6f442c44e96fefc8c90e94b7183f076afe8d969149a88fc444044b90009

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
