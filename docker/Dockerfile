FROM vault:1.13.2
ARG BIN=vault/plugins/vault-plugin-secrets-kms-linux
COPY ${BIN} /vault/plugins/vault-plugin-secrets-kms
RUN setcap cap_ipc_lock=+ep /vault/plugins/vault-plugin-secrets-kms

RUN apk add jq curl
COPY docker/docker-entrypoint.sh /usr/local/bin/
COPY docker/scripts /vault/scripts/
COPY docker/config.d /vault/config.d/
ENV VAULT_LOCAL_CONFIG='{"backend":{"file":{"path":"/vault/file"}}}'
