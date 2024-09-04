package store

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/devon-mar/acmevault/cert"
	vault "github.com/hashicorp/vault/api"
)

const (
	EnvVaultKVMount       = "VAULT_KV_MOUNT"
	EnvVaultKVCertsPath   = "VAULT_KV_CERTS_PATH"
	EnvVaultKVAccountPath = "VAULT_KV_ACCOUNT_PATH"
	EnvVaultCertAuth      = "VAULT_CERT_AUTH"
	EnvVaultCertAuthRole  = "VAULT_CERT_AUTH_ROLE"

	VaultKVKeyCert = "tls.crt"
	VaultKVKeyKey  = "tls.key"
	VaultKVKeyCA   = "ca"
	VaultKVKeyPFX  = "pfx"
)

type VaultStore struct {
	kvMount     string
	certsPath   string
	accountPath string

	client *vault.Client
}

func NewVaultStore() (*VaultStore, error) {
	vs := &VaultStore{}
	var err error
	vs.kvMount, err = readEnv(EnvVaultKVMount)
	if err != nil {
		return nil, err
	}
	vs.certsPath, err = readEnv(EnvVaultKVCertsPath)
	if err != nil {
		return nil, err
	}
	vs.certsPath = cleanPath(vs.certsPath)
	vs.accountPath, err = readEnv(EnvVaultKVAccountPath)
	if err != nil {
		return nil, err
	}
	vs.accountPath = cleanPath(vs.accountPath)

	vaultCfg := vault.DefaultConfig()
	if err != nil {
		return nil, err
	}

	vs.client, err = vault.NewClient(vaultCfg)
	if err != nil {
		return nil, err
	}
	if vs.client.Token() == "" {
		if m := os.Getenv(EnvVaultCertAuth); m != "" {
			_, err := vs.client.Auth().Login(
				context.Background(),
				&vaultCertAuth{Mount: m, Role: os.Getenv(EnvVaultCertAuthRole)},
			)
			if err != nil {
				return nil, err
			}
		} else {
			return nil, errors.New("no Vault auth method configured")
		}
	}
	return vs, nil
}

// Retrieve implements Store
func (s *VaultStore) Retrieve(cn string) (*cert.Bundle, error) {
	data, err := s.kv().Get(context.Background(), s.certPath(cn))
	if errors.Is(err, vault.ErrSecretNotFound) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}

	certificate, ok := data.Data[VaultKVKeyCert].(string)
	if !ok {
		return nil, fmt.Errorf("%s:%s wasn't a string", s.certsPath, VaultKVKeyCert)
	}
	key, ok := data.Data[VaultKVKeyKey].(string)
	if !ok {
		return nil, fmt.Errorf("%s:%s wasn't a string", s.certsPath, VaultKVKeyKey)
	}
	ca, ok := data.Data[VaultKVKeyCA].(string)
	if !ok {
		return nil, fmt.Errorf("%s:%s wasn't a string", s.certsPath, VaultKVKeyCA)
	}

	return cert.BundleFromBytes([]byte(certificate), []byte(key), []byte(ca))
}

func (s *VaultStore) certPath(cn string) string {
	return s.certsPath + "/" + cn
}

// RetrieveAccount implements Store
func (s *VaultStore) RetrieveAccount() (map[string]string, error) {
	data, err := s.kv().Get(context.Background(), s.accountPath)
	if errors.Is(err, vault.ErrSecretNotFound) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}

	var ok bool
	ret := make(map[string]string, len(data.Data))
	for k, v := range data.Data {
		ret[k], ok = v.(string)
		if !ok {
			return nil, fmt.Errorf("account key %q is not a string", k)
		}
	}

	return ret, nil
}

// Store implements Store
func (s *VaultStore) Store(cb *cert.Bundle) error {
	keyString, err := cb.KeyString()
	if err != nil {
		return err
	}

	pfxBytes, err := cb.PFX()
	if err != nil {
		return err
	}

	data := map[string]interface{}{
		VaultKVKeyCert: cb.CertString(),
		VaultKVKeyCA:   cb.CAString(),
		VaultKVKeyKey:  keyString,
		VaultKVKeyPFX:  base64.StdEncoding.EncodeToString(pfxBytes),
	}
	_, err = s.kv().Put(context.Background(), s.certPath(cb.Certificate.Subject.CommonName), data)
	return err
}

// StoreAccount implements Store
func (s *VaultStore) StoreAccount(acc map[string]string) error {
	data := make(map[string]interface{}, len(acc))
	for k, v := range acc {
		data[k] = v
	}
	_, err := s.kv().Put(context.Background(), s.accountPath, data)
	return err
}

func (s *VaultStore) kv() *vault.KVv2 {
	return s.client.KVv2(s.kvMount)
}

func readEnv(name string) (string, error) {
	val := os.Getenv(name)
	if val == "" {
		return "", fmt.Errorf("%s is empty", name)
	}
	return val, nil
}

type vaultCertAuth struct {
	Mount string
	Role  string
}

func (a *vaultCertAuth) Login(ctx context.Context, client *vault.Client) (*vault.Secret, error) {
	data := map[string]interface{}{"name": a.Role}

	path := "auth/" + a.Mount + "/login"

	resp, err := client.Logical().WriteWithContext(ctx, path, data)
	if err != nil {
		return nil, fmt.Errorf("error authenticating with TLS: %w", err)
	}
	if resp == nil {
		return nil, fmt.Errorf("empty response from TLS auth")
	}
	return resp, nil
}

func cleanPath(p string) string {
	return strings.TrimSuffix(p, "/")
}
