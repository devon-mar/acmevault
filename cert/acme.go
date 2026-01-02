package cert

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"os"
	"strconv"
	"strings"

	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/lego"
	legolog "github.com/go-acme/lego/v4/log"
	"github.com/go-acme/lego/v4/registration"
)

const (
	EnvACMEEmail                      = "ACME_EMAIL"
	EnvACMEDir                        = "ACME_DIR_URL"
	EnvACMEDNSProvider                = "ACME_DNS01_PROVIDER"
	EnvACMEDNSResolvers               = "ACME_DNS_RESOLVERS"
	EnvACMEDisableCompletePropagation = "ACME_DISABLE_COMPLETE_PROPAGATION"
	EnvACMETOSAgreed                  = "ACME_TOS_AGREED"

	providerTempTxt = "temptxt"

	accountMapUser       = "registration"
	accountMapPrivateKey = "private_key"

	maxChainLen = 11
)

type ACMEIssuer struct {
	client        *lego.Client
	accountString string
}

func init() {
	legolog.Logger = log.Default()
}

func NewACMEIssuer(account map[string]string) (*ACMEIssuer, map[string]string, error) {
	if b, _ := strconv.ParseBool(os.Getenv(EnvACMETOSAgreed)); !b {
		return nil, nil, errors.New("TOS not agreed")
	}

	dir, err := readEnv(EnvACMEDir)
	if err != nil {
		return nil, nil, err
	}

	dns01, err := readEnv(EnvACMEDNSProvider)
	if err != nil {
		return nil, nil, err
	}

	email, err := readEnv(EnvACMEEmail)
	if err != nil {
		return nil, nil, err
	}

	var user *acmeUser

	if account != nil {
		user, err = userFromMap(account)
		if err != nil {
			return nil, nil, err
		}
	}
	if user == nil {
		// Otherwise create a new one if the account doesn't exist
		// or is invalid
		slog.Info("Generating new ACME account key")
		user = &acmeUser{Email: email}
		user.key, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err != nil {
			return nil, nil, fmt.Errorf("error generating new account key: %w", err)
		}
	}

	ai := &ACMEIssuer{}
	acmeConfig := lego.NewConfig(user)
	acmeConfig.CADirURL = dir
	ai.client, err = lego.NewClient(acmeConfig)
	if err != nil {
		return nil, nil, err
	}

	provider, err := getDNS01Provider(dns01)
	if err != nil {
		return nil, nil, err
	}
	err = ai.client.Challenge.SetDNS01Provider(provider, getDNS01Opts()...)
	if err != nil {
		return nil, nil, fmt.Errorf("error setting DNS01 provider: %w", err)
	}

	var userChanged bool
	if user.Registration == nil {
		userChanged = true
		user.Registration, err = ai.client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
		if err != nil {
			return nil, nil, fmt.Errorf("error registering account: %w", err)
		}
	} else if user.Email != email {
		userChanged = true
		user.Email = email
		user.Registration, err = ai.client.Registration.UpdateRegistration(registration.RegisterOptions{TermsOfServiceAgreed: true})
		if err != nil {
			return nil, nil, fmt.Errorf("error updating registration email: %w", err)
		}
	}

	if userChanged {
		userRet, err := user.stringMap()
		if err != nil {
			return nil, nil, fmt.Errorf("error converting user to string map: %w", err)
		}
		return ai, userRet, nil
	}
	return ai, nil, nil
}

func getDNS01Opts() []dns01.ChallengeOption {
	var opts []dns01.ChallengeOption

	if servers := os.Getenv(EnvACMEDNSResolvers); servers != "" {
		opts = []dns01.ChallengeOption{dns01.AddRecursiveNameservers(dns01.ParseNameservers(strings.Split(servers, ",")))}
	}
	if b, _ := strconv.ParseBool(os.Getenv(EnvACMEDisableCompletePropagation)); b {
		opts = append(opts, dns01.DisableAuthoritativeNssPropagationRequirement())
	}
	return opts
}

func generateKey(typ string) (crypto.PrivateKey, error) {
	var pk crypto.PrivateKey
	var err error
	switch typ {
	case "EC256":
		pk, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "EC384":
		pk, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case "RSA4096":
		pk, err = rsa.GenerateKey(rand.Reader, 4096)
	case "RSA8192":
		pk, err = rsa.GenerateKey(rand.Reader, 8192)
	case "":
		fallthrough
	case "RSA2048":
		pk, err = rsa.GenerateKey(rand.Reader, 2048)
	default:
		return nil, fmt.Errorf("Unsupported key type %q", typ)
	}
	return pk, err
}

// Issue implements Issuer
func (a *ACMEIssuer) Issue(req CertRequest) (*Bundle, error) {
	pk := req.PrivateKey
	var err error
	if pk == nil {
		slog.Debug("No private key provided. Generating one...")
		pk, err = generateKey(req.KeyType)
		if err != nil {
			return nil, fmt.Errorf("error generating key: %w", err)
		}
	}
	obtainReq := certificate.ObtainRequest{
		Domains:    req.Domains,
		PrivateKey: pk,
		MustStaple: req.MustStaple,
		Bundle:     false,
	}
	resp, err := a.client.Certificate.Obtain(obtainReq)
	if err != nil {
		return nil, err
	}

	// Split the issuer certificates
	var issuerCerts [][]byte
	rest := resp.IssuerCertificate
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		issuerCerts = append(issuerCerts, pem.EncodeToMemory(block))

		if len(issuerCerts) > maxChainLen {
			return nil, errors.New("issuer certificates too long")
		}
	}

	return BundleFromBytes(resp.Certificate, resp.PrivateKey, issuerCerts)
}

// Account implements Issuer
func (a *ACMEIssuer) Account() string {
	return a.accountString
}

type acmeUser struct {
	Email        string                 `json:"email"`
	Registration *registration.Resource `json:"registration"`
	key          crypto.PrivateKey      `json:"-"`
}

// GetEmail implements registration.User
func (u *acmeUser) GetEmail() string {
	return u.Email
}

// GetPrivateKey implements registration.User
func (u *acmeUser) GetPrivateKey() crypto.PrivateKey {
	return u.key
}

// GetRegistration implements registration.User
func (u *acmeUser) GetRegistration() *registration.Resource {
	return u.Registration
}

func userFromMap(m map[string]string) (*acmeUser, error) {
	if len(m) != 2 || m[accountMapPrivateKey] == "" || m[accountMapUser] == "" {
		return nil, nil
	}

	d := json.NewDecoder(strings.NewReader(m[accountMapUser]))
	d.DisallowUnknownFields()

	u := &acmeUser{}
	err := d.Decode(u)
	if err != nil {
		return nil, err
	}

	derBytes, err := base64.StdEncoding.DecodeString(m[accountMapPrivateKey])
	if err != nil {
		return nil, err
	}

	u.key, err = x509.ParsePKCS8PrivateKey(derBytes)
	if err != nil {
		return nil, err
	}

	return u, nil
}

func (u *acmeUser) stringMap() (map[string]string, error) {
	ret := make(map[string]string, 2)
	userBytes, err := json.Marshal(u)
	if err != nil {
		return nil, err
	}
	ret[accountMapUser] = string(userBytes)

	derBytes, err := x509.MarshalPKCS8PrivateKey(u.key)
	if err != nil {
		return nil, err
	}

	ret[accountMapPrivateKey] = base64.StdEncoding.EncodeToString(derBytes)

	return ret, nil
}
