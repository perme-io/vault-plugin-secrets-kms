# Dockerize with Vault image
dockerize based on https://hub.docker.com/r/hashicorp/vault 

## Build
before docker image build, build binary by `make build-linux` command.  
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
```shell 
$ docker run -d --cap-add=IPC_LOCK parameta-w/vault
```
`vault-plugin-secrets-kms` plugin will be registered and enabled with `/kms` path 

### Running Vault for Production
To run server in production, the container-command MUST start with `vault server -config=/path/to/config`.  
And the operator MUST register and enable `vault-plugin-secrets-kms` plugin after vault initialize. 
