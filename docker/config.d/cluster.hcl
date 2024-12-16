disable_mlock = true
ui            = true

cluster_addr     = "http://vault:8201"
api_addr         = "http://127.0.0.1:8200"
plugin_directory = "/vault/plugins"
log_level        = "trace"

listener "tcp" {
  address          = "0.0.0.0:8200"
  cluster_address  = "0.0.0.0:8201"
  tls_disable      = "true"
}

storage "raft" {
  path = "/vault/data"
  node_id = "w_raft_node_1"
}
