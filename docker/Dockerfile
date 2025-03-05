FROM golang:1.23.6-alpine AS builder
WORKDIR /work
COPY . /work
RUN go build -o build/vault-plugin-secrets-kms cmd/main.go
RUN apk add git patch make bash && \
    git clone https://github.com/hashicorp/vault.git -b v1.13.12 && cd vault && \
    patch -p1 < ../docker/vault/1.13.12.patch && \
    go mod tidy && go mod verify && \
    export GODEBUG=x509negativeserial=1 && \
    make bin

# FROM hashicorp/vault:1.13.12
FROM alpine:3.20 as default

# NAME and PRODUCT_VERSION are the name of the software in releases.hashicorp.com
# and the version to download. Example: NAME=vault PRODUCT_VERSION=1.2.3.
ARG NAME=vault
ARG PRODUCT_VERSION=1.13.12
ARG PRODUCT_REVISION=c19fea2527cd34d6232a2bbb40c37a6273987d10

# Additional metadata labels used by container registries, platforms
# and certification scanners.
LABEL name="Vault" \
      maintainer="Vault Team <vault@hashicorp.com>" \
      vendor="HashiCorp" \
      version=${PRODUCT_VERSION} \
      release=${PRODUCT_REVISION} \
      revision=${PRODUCT_REVISION} \
      summary="Vault is a tool for securely accessing secrets." \
      description="Vault is a tool for securely accessing secrets. A secret is anything that you want to tightly control access to, such as API keys, passwords, certificates, and more. Vault provides a unified interface to any secret, while providing tight access control and recording a detailed audit log."

COPY --from=builder /work/vault/LICENSE /licenses/mozilla.txt

# Set ARGs as ENV so that they can be used in ENTRYPOINT/CMD
ENV NAME=$NAME
ENV VERSION=$VERSION

# Create a non-root user to run the software.
RUN addgroup ${NAME} && adduser -S -G ${NAME} ${NAME}

RUN apk add --no-cache libcap su-exec dumb-init tzdata

COPY --from=builder /work/vault/bin/vault /bin/vault

# /vault/logs is made available to use as a location to store audit logs, if
# desired; /vault/file is made available to use as a location with the file
# storage backend, if desired; the server will be started with /vault/config as
# the configuration directory so you can add additional config files in that
# location.
RUN mkdir -p /vault/logs && \
    mkdir -p /vault/file && \
    mkdir -p /vault/config && \
    chown -R ${NAME}:${NAME} /vault

# Expose the logs directory as a volume since there's potentially long-running
# state in there
VOLUME /vault/logs

# Expose the file directory as a volume since there's potentially long-running
# state in there
VOLUME /vault/file

# 8200/tcp is the primary interface that applications use to interact with
# Vault.
EXPOSE 8200

# The entry point script uses dumb-init as the top-level process to reap any
# zombie processes created by Vault sub-processes.
#
# For production derivatives of this container, you shoud add the IPC_LOCK
# capability so that Vault can mlock memory.
COPY docker/docker-entrypoint.sh /usr/local/bin/
ENTRYPOINT ["docker-entrypoint.sh"]


# # By default you'll get a single-node development server that stores everything
# # in RAM and bootstraps itself. Don't use this configuration for production.
CMD ["server", "-dev"]


COPY --from=builder /work/build/vault-plugin-secrets-kms /vault/plugins/vault-plugin-secrets-kms
RUN setcap cap_ipc_lock=+ep /vault/plugins/vault-plugin-secrets-kms

RUN apk add --no-cache jq curl
COPY docker/docker-entrypoint.sh /usr/local/bin/
COPY docker/scripts /vault/scripts/
COPY docker/config.d /vault/config.d/
RUN echo '{"plugin_directory":"/vault/plugins"}' > /vault/config/default.json
