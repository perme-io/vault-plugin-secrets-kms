export VAULT_ADDR=${VAULT_ADDR:-${VAULT_API_ADDR:-http://${VAULT_DEV_LISTEN_ADDRESS}}}
RET=1
CNT=0
TIMEOUT=${TIMEOUT:-10}
while [ $RET -eq 1 ];do
  if [ $CNT -gt $TIMEOUT ]; then
    echo "$0 timeout"
    exit 1
  fi
  CNT=$(($CNT+1))
  sleep 1
  vault status
  RET=$?
  echo $RET
done

INIT_RESULT_FILE=/vault/file/init_result.json
VAULT_INITIALIZED=$(vault status -format=json | jq -r .initialized)
if [ "${VAULT_INITIALIZED}" == "false" ]; then
    vault operator init -key-shares=1 -key-threshold=1 -format=json > ${INIT_RESULT_FILE}
fi

VAULT_SEALED=$(vault status -format=json | jq -r .sealed)
if [ "${VAULT_SEALED}" == "true" ]; then
    if [ -z "${VAULT_UNSEAL_KEY}" ] && [ -f "${INIT_RESULT_FILE}" ]; then
        VAULT_UNSEAL_KEY=$(cat ${INIT_RESULT_FILE} | jq -r .unseal_keys_hex[0])
    fi
    if [ -n "${VAULT_UNSEAL_KEY}" ]; then
        vault operator unseal ${VAULT_UNSEAL_KEY}
    else
        echo "VAULT_UNSEAL_KEY or ${INIT_RESULT_FILE} required"
    fi
fi

if [ -z "${VAULT_TOKEN}" ]; then
    if [ -f "${INIT_RESULT_FILE}" ]; then
        VAULT_TOKEN=$(cat ${INIT_RESULT_FILE} | jq -r .root_token)
    elif [ -f "~/.vault-token" ]; then
        VAULT_TOKEN=$(cat ~/.vault-token)
    elif [ -n "${VAULT_DEV_ROOT_TOKEN_ID}" ]; then
        VAULT_TOKEN=${VAULT_DEV_ROOT_TOKEN_ID}
    else
        echo "VAULT_TOKEN or ${INIT_RESULT_FILE} or ~/.vault-token or VAULT_DEV_ROOT_TOKEN_ID required"
        exit 1
    fi
fi

if [ -n "${VAULT_TOKEN}" ]; then
    export VAULT_TOKEN=${VAULT_TOKEN}
    PLUGIN_NAME=vault-plugin-secrets-kms
    PLUGIN_INFO=$(vault read -format=json sys/plugins/catalog/secret/${PLUGIN_NAME})
    if [ $? -ne 0 ]; then
        vault plugin register \
            -sha256=$(sha256sum /vault/plugins/${PLUGIN_NAME}|cut -d' ' -f1) \
            secret \
            ${PLUGIN_NAME}
    fi
    PLUGIN_MOUNT_PATH=${PLUGIN_MOUNT_PATH:-kms}
    SECRET_TYPE=$(vault read -format=json sys/mounts/${PLUGIN_MOUNT_PATH} | jq -r .data.type)
    if [ $? -ne 0 ] || [ "${SECRET_TYPE}" != "${PLUGIN_NAME}" ]; then
        vault secrets enable \
            -path=${PLUGIN_MOUNT_PATH} \
            ${PLUGIN_NAME}
    fi
    KV_MOUNT_PATH=${KV_MOUNT_PATH:-secret}
    SECRET_TYPE=$(vault read -format=json sys/mounts/${KV_MOUNT_PATH} | jq -r .data.type)
    if [ $? -ne 0 ] || [ "${SECRET_TYPE}" != "kv" ]; then
        vault secrets enable \
            -path=${KV_MOUNT_PATH} \
            -description="key/value secret storage" \
            kv-v2
    fi
fi
