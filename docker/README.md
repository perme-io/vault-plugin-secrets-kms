# Dockerize with Vault image
dockerize based on https://hub.docker.com/r/hashicorp/vault 

## Build
```shell
$ ./docker/build.sh
```
the image `name:tag` will be `${NAMESPACE}/${REPO}:${TAG}` using below variables.
* NAMESPACE : namespace of image repo, default as `parameta-w`
* REPO : image repo, default as `vault`
* TAG : image tag, default by `latest`

## Provisioning
### Plugin binary
embed to `/vault/plugins/vault-plugin-secrets-kms`  
`plugin_directory` configuration SHOULD be `/vault/plugins`.

### Scripts
embed to `/vault/scripts`
* register_plugin.sh : register plugin with `vault plugin register` command
* enable_plugin.sh [MOUNT_PATH] : enable registered plugin with `vault secrets enable` command, default mount path is `/kms`
* init.sh : initialize with `vault operator init` and `vault operator unseal` commands,
  and execute `register_plugin.sh`, `enable_plugin.sh`

### Configuration examples
embed to `/vault/config.d`
* single.json : single server without TLS, file backend
* cluster.hcl : cluster server without TLS, raft backend

## Running Vault for Development
Running "dev" mode with default command(`server -dev`)  
`vault-plugin-secrets-kms` plugin will be registered and enabled with `/kms` path  

```shell 
$ docker run -d --cap-add=IPC_LOCK parameta-w/vault
```
Optional environment variables
* `VAULT_LOCAL_CONFIG`: configuration JSON format for `/vault/config/local.json`, (default as `{"backend":{"file":{"path":"/vault/file"}}}`)
* `VAULT_DEV_ROOT_TOKEN_ID`: This sets the ID of the initial generated root token to the given value (default as dev-only-token)
* `VAULT_DEV_LISTEN_ADDRESS`: This sets the IP:port of the development server listener (default as 0.0.0.0:8200)

### example for docker-compose
use default configuration for dev mode running.
volume mount for persistent storage data and expose port for api and ui. 
```yaml
version: '3.9'
services:
  vault:
    image: parameta-w/vault
    cap_add:
      - IPC_LOCK
    volumes:
      - vault-data:/vault/file
    ports:
      - "8200:8200"
volumes:
  vault-data:
```

### Running Vault for Production
To run server in production, the container-command MUST start with `vault server -config=/path/to/config`.  
And the operator MUST register and enable `vault-plugin-secrets-kms` plugin after vault initialize. 

### example for docker-compose
use embed example configuration([`/vault/config.d/cluster.hcl`](config.d/cluster.hcl)) for server mode running,
(*DO NOT USE* the built-in example configurations directly in production)
 
volume mount for persistent storage data and expose ports (`8200: api and ui, 8201:cluster`).
```yaml
version: '3.9'
services:
  vault:
    image: parameta-w/vault
    cap_add:
      - IPC_LOCK
    command: vault server -config=/vault/config.d/cluster.hcl 
    volumes:
      - vault-data:/vault/file
    ports:
      - "8200:8200"
      - "8201:8201"
volumes:
  vault-data:
```
