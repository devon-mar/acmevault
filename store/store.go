package store

import (
	"github.com/devon-mar/acmevault/cert"
)

type Store interface {
	Retrieve(cn string) (*cert.Bundle, error)
	Store(string, *cert.Bundle) error

	StoreAccount(map[string]string) error
	RetrieveAccount() (map[string]string, error)
}
