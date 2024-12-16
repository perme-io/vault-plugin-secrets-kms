vault plugin register \
    -sha256=$(sha256sum /vault/plugins/vault-plugin-secrets-kms|cut -d' ' -f1) \
    secret \
    vault-plugin-secrets-kms

