# acmevault

Obtain certificates from an ACME CA and store them in Vault.

## Environment Variables

| Variable | Type | Required | Default | Description |
|---|---|---|---|---|
| `AV_CERTS` | string | true | | The certificates to obtain. See [AV_CERTS](#AV_CERTS). |
| `ACME_TOS_AGREED` | bool | true | | Set to true to agree to the ACME CA tos. |

#### `AV_CERTS`
Each certificate is separated by a new line.
Each line consists of a comma separated list of domains. The first domain will be used for the certificate CN.
Optional comma separated key value pairs can follow:
| Key | Type | Default | Description |
|---|---|---|---|
| `keytype` | string | RSA2048 | The key type to use. |
| `reusekey` | bool | false | Reuse the private key when renewing a certificate. |
| `muststaple` | bool | false | Enable the OCSP must staple extension. |

**Example**:
```
example.com,www.example.com,reusekey=false
test.example.com,muststaple=true,keytype=EC256
```

### Vault

| Variable | Type | Required | Default | Description |
|---|---|---|---|---|
| `VAULT_KV_MOUNT` | string | true | | Vault KVv2 mount path. |
| `VAULT_KV_CERTS_PATH` | string | true | | Path to store the certificates. The certificate CN will be appended. |
| `VAULT_KV_ACCOUNT_PATH` | string | true | | KVv2 path to store the ACME account. |
| `VAULT_CACERT` | string | false | | The path to a PEM-encoded CA cert file to use to verify the Vault server SSL certificate. |
| `VAULT_CLIENT_CERT` | string | false | | Vault client certificate. |
| `VAULT_CLIENT_KEY` | string | false | | Vault client private key. |
| `VAULT_CERT_AUTH` | string | false | | Vault cert auth path. |
| `VAULT_CERT_AUTH_ROLE` | string | false | | Vault cert auth role. |

### ACME

| Variable | Type | Required | Default | Description |
|---|---|---|---|---|
| `ACME_EMAIL` | string | true | | The email to use for the ACME account. |
| `ACME_DIR_URL` | string | true | | The ACME CA directory url. (`https://acme-v02.api.letsencrypt.org/directory` for Let's Encrypt) .
| `ACME_DNS01_PROVIDER` | string | true | | The Lego DNS01 [provider](https://go-acme.github.io/lego/dns/) to use or `temptxt`. |
| `ACME_DNS_RESOLVERS` | string | false | false | Comma separated DNS resolvers to use for checking DNS record propogation. |
| `ACME_DISABLE_COMPLETE_PROPAGATION` | bool | false | false | Disable DNS complete propogation check. |

### TempTXT DNS01 Provider

| Variable | Type | Required | Default | Description |
|---|---|---|---|---|
| `TEMPTXT_URL` | string | true | | The update URL. |
| `TEMPTXT_CERT` | string | false | | The client certificate to use. |
| `TEMPTXT_KEY` | string | false | | The client private key to use. |
| `TEMPTXT_CA` | string | false | | Optional CA to verify the server's SSL certificate. |
| `TEMPTXT_STRIP_ACME_CHALLENGE` | bool | false | | Strip `_acme-challenge.` from the domain when presenting it to the temptxt server. |
