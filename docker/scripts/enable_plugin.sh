export VAULT_ADDR=${VAULT_ADDR:-http://${VAULT_DEV_LISTEN_ADDRESS:-localhost:8200}}
export VAULT_TOKEN=${VAULT_TOKEN:-${VAULT_DEV_ROOT_TOKEN_ID:-dev-only-token}}
RET=1
while [ $RET -ne 0 ];do
  sleep 1
  vault status
  RET=$?
done
vault secrets enable -path=${1:-kms} vault-plugin-secrets-kms
