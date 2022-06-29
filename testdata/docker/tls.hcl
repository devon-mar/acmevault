# https://github.com/hashicorp/vault/issues/13467
listener "tcp" {
  address       = "0.0.0.0:8200"
  tls_cert_file = "/certs/server.crt"
  tls_key_file  = "/certs/server.key"
}
