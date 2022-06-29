package cert

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/lego"
	legolog "github.com/go-acme/lego/v4/log"
	"github.com/go-acme/lego/v4/registration"

	log "github.com/sirupsen/logrus"
)

const (
	EnvACMEEmail                      = "ACME_EMAIL"
	EnvACMEDir                        = "ACME_DIR_URL"
	EnvACMEDNSProvider                = "ACME_DNS01_PROVIDER"
	EnvACMEDNSResolvers               = "ACME_DNS_RESOLVERS"
	EnvACMEDisableCompletePropagation = "ACME_DISABLE_COMPLETE_PROPAGATION"
	EnvACMETOSAgreed                  = "ACME_TOS_AGREED"

	providerTempTxt = "temptxt"
)

type ACMEIssuer struct {
	client        *lego.Client
	accountString string
}

func init() {
	legolog.Logger = log.StandardLogger()
}

func NewACMEIssuer(account string) (*ACMEIssuer, error) {
	if b, _ := strconv.ParseBool(os.Getenv(EnvACMETOSAgreed)); !b {
		return nil, errors.New("TOS not agreed")
	}

	dir, err := readEnv(EnvACMEDir)
	if err != nil {
		return nil, err
	}

	dns01, err := readEnv(EnvACMEDNSProvider)
	if err != nil {
		return nil, err
	}

	email, err := readEnv(EnvACMEEmail)
	if err != nil {
		return nil, err
	}

	var accountKey crypto.PrivateKey
	if account != "" {
		accountKey, err = bytesToKey([]byte(account))
		if err != nil {
			return nil, fmt.Errorf("error parsing account key: %w", err)
		}
	} else {
		log.Infof("Generating new ACME account key")
		accountKey, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("error generating new account key: %w", err)
		}
	}

	user := &acmeUser{email: email, key: accountKey}

	ai := &ACMEIssuer{}
	acmeConfig := lego.NewConfig(user)
	acmeConfig.CADirURL = dir
	ai.client, err = lego.NewClient(acmeConfig)
	if err != nil {
		return nil, err
	}

	provider, err := getDNS01Provider(dns01)
	if err != nil {
		return nil, err
	}
	err = ai.client.Challenge.SetDNS01Provider(provider, getDNS01Opts()...)
	if err != nil {
		return nil, fmt.Errorf("error setting DNS01 provider: %w", err)
	}

	err = user.register(ai.client)
	if err != nil {
		return nil, err
	}

	ai.accountString, err = keyToString(user.key)
	if err != nil {
		return nil, err
	}

	return ai, nil
}

func getDNS01Opts() []dns01.ChallengeOption {
	var opts []dns01.ChallengeOption

	if servers := os.Getenv(EnvACMEDNSResolvers); servers != "" {
		opts = []dns01.ChallengeOption{dns01.AddRecursiveNameservers(dns01.ParseNameservers(strings.Split(servers, ",")))}
	}
	if b, _ := strconv.ParseBool(os.Getenv(EnvACMEDisableCompletePropagation)); b {
		opts = append(opts, dns01.DisableCompletePropagationRequirement())
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
		log.Debugf("No private key provided. Generating one...")
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

	return BundleFromBytes(resp.Certificate, resp.PrivateKey, resp.IssuerCertificate)
}

// Account implements Issuer
func (a *ACMEIssuer) Account() string {
	return a.accountString
}

type acmeUser struct {
	email        string
	key          crypto.PrivateKey
	registration *registration.Resource
}

// GetEmail implements registration.User
func (u *acmeUser) GetEmail() string {
	return u.email
}

// GetPrivateKey implements registration.User
func (u *acmeUser) GetPrivateKey() crypto.PrivateKey {
	return u.key
}

// GetRegistration implements registration.User
func (u *acmeUser) GetRegistration() *registration.Resource {
	return u.registration
}

// Register with the ACME server, generating an account key if necessary.
func (u *acmeUser) register(client *lego.Client) error {
	var err error
	u.registration, err = client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
	if err != nil {
		return err
	}
	if len(u.registration.Body.Contact) == 0 || strings.EqualFold(u.registration.Body.Contact[0], u.email) {
		_, err = client.Registration.UpdateRegistration(registration.RegisterOptions{TermsOfServiceAgreed: true})
		if err != nil {
			return err
		}
	}

	return nil
}
