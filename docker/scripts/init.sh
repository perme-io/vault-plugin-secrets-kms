export VAULT_ADDR=${VAULT_ADDR:-http://localhost:8200}
INIT_RESULT=/vault/init_result.json
vault operator init -key-shares=1 -key-threshold=1 -format=json > ${INIT_RESULT}
init_result=$(cat ${INIT_RESULT})
vault operator unseal $(echo "$init_result" | jq -r .unseal_keys_hex[0])
export VAULT_TOKEN=$(echo "$init_result" | jq -r .root_token)

vault secrets enable -path=secret -description="key/value secret storage" kv-v2

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)

${SCRIPT_DIR}/register_plugin.sh
${SCRIPT_DIR}/enable_plugin.sh 
