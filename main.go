package main

import (
	"crypto/x509"
	"os"
	"time"

	"github.com/devon-mar/acmevault/cert"
	"github.com/devon-mar/acmevault/store"
	log "github.com/sirupsen/logrus"
)

var (
	exitFunc        func(int) = os.Exit
	testShouldRenew           = false
)

func main() {
	log.SetLevel(log.DebugLevel)
	cfg, err := configFromEnv()
	if err != nil {
		log.WithError(err).Fatal("config error")
	}

	exitFunc(run(
		cfg,
		func() (store.Store, error) { return store.NewVaultStore() },
		func(a string) (cert.Issuer, error) { return cert.NewACMEIssuer(a) },
	))
}

func run(cfg *config, newStore func() (store.Store, error), newIssuer func(string) (cert.Issuer, error)) int {
	log.Infof("Found %d cert(s)", len(cfg.certs))
	av := &acmeVault{}

	var err error
	av.store, err = newStore()
	if err != nil {
		log.WithError(err).Error("error initializing cert store")
		return 1
	}

	account, err := av.store.RetrieveAccount()
	if err != nil {
		log.WithError(err).Error("error retrieving account from store")
		return 1
	}

	av.issuer, err = newIssuer(account)
	if err != nil {
		log.WithError(err).Error("error initializing cert issuer")
		return 1
	}

	if newAccount := av.issuer.Account(); newAccount != account {
		log.Info("Account has changed")
		// Update the account if different
		if err = av.store.StoreAccount(newAccount); err != nil {
			log.WithError(err).Error("error storing issuer account in store")
			return 1
		}
	}

	var ret int
	for _, c := range cfg.certs {
		if err := av.processCert(c); err != nil {
			log.WithError(err).Errorf("error processing cert %v", c.Domains)
			ret++
			if cfg.exitOnError {
				break
			}
		}
	}

	return ret
}

type acmeVault struct {
	store  store.Store
	issuer cert.Issuer
}

func (av *acmeVault) processCert(cc certConfig) error {
	cn := cc.Domains[0]
	logger := log.WithField("cn", cn)
	logger.Infof("Processing %s", cn)

	oldCb, err := av.store.Retrieve(cn)
	if err != nil {
		return err
	}

	if oldCb == nil {
		logger.Info("No existing certificate found")
	}

	if oldCb == nil || shouldRenew(oldCb.Certificate, time.Now()) {
		logger.Info("Obtaining a new certificate")

		req := cc.CertRequest
		if oldCb != nil && cc.reuseKey {
			logger.Info("Reusing private key")
			req.PrivateKey = oldCb.PrivateKey
		}
		cb, err := av.issuer.Issue(req)
		if err != nil {
			return err
		}
		logger.Infof("Successfully obtained")
		return av.store.Store(cb)
	}
	return nil
}

func shouldRenew(c *x509.Certificate, now time.Time) bool {
	return now.After(c.NotBefore.Add(c.NotAfter.Sub(c.NotBefore)*2/3)) || testShouldRenew
}
