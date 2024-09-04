package main

import (
	"crypto/x509"
	"flag"
	"log/slog"
	"os"
	"time"

	"github.com/devon-mar/acmevault/cert"
	"github.com/devon-mar/acmevault/store"
)

var (
	exitFunc        func(int) = os.Exit
	testShouldRenew           = false

	checkMode   = flag.Bool("check", false, "Check the status of existing certificates without issuing any certificates.")
	logLevelStr = flag.String("log-level", "info", "Log level.")
)

func configureLogging(level slog.Leveler) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: level,
	}))
	slog.SetDefault(logger)
}

func main() {
	flag.Parse()

	var logLevel slog.Level
	if err := logLevel.UnmarshalText([]byte(*logLevelStr)); err != nil {
		slog.Error("error parsing log-level", "err", err)
		os.Exit(1)
	}
	configureLogging(logLevel)

	cfg, err := configFromEnv()
	if err != nil {
		slog.Error("config error", "err", err)
		os.Exit(1)
	}

	exitFunc(run(
		cfg,
		*checkMode,
		func() (store.Store, error) { return store.NewVaultStore() },
		func(a map[string]string) (cert.Issuer, map[string]string, error) { return cert.NewACMEIssuer(a) },
	))
}

func run(cfg *config, checkMode bool, newStore func() (store.Store, error), newIssuer func(map[string]string) (cert.Issuer, map[string]string, error)) int {
	slog.Info("acmevault starting", "numCerts", len(cfg.certs))
	av := &acmeVault{}

	var err error
	av.store, err = newStore()
	if err != nil {
		slog.Error("error initializing cert store", "err", err)
		return 1
	}

	account, err := av.store.RetrieveAccount()
	if err != nil {
		slog.Error("error retrieving account from store", "err", err)
		return 1
	}

	var accountToStore map[string]string
	av.issuer, accountToStore, err = newIssuer(account)
	if err != nil {
		slog.Error("error initializing cert issuer", "err", err)
		return 1
	}

	if accountToStore != nil {
		slog.Info("Account has changed")
		// Update the account if different
		if err = av.store.StoreAccount(accountToStore); err != nil {
			slog.Error("error storing issuer account in store", "err", err)
			return 1
		}
	}

	var ret int
	for _, c := range cfg.certs {
		if err := av.processCert(c, checkMode); err != nil {
			slog.Error("error processing cert", "domains", c.Domains, "err", err)
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

func (av *acmeVault) processCert(cc certConfig, checkMode bool) error {
	cn := cc.Domains[0]
	logger := slog.With("cn", cn)
	logger.Info("Processing")

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
		logger.Info("Successfully obtained")
		return av.store.Store(cb)
	}

	if checkMode {
		logger.Info("certificate ok", "notAfter", oldCb.Certificate.NotAfter)
		return nil
	}

	return nil
}

func shouldRenew(c *x509.Certificate, now time.Time) bool {
	return now.After(c.NotBefore.Add(c.NotAfter.Sub(c.NotBefore)*2/3)) || testShouldRenew
}
