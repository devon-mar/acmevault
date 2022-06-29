package store

import (
	"github.com/devon-mar/acmevault/cert"
)

type Store interface {
	Retrieve(cn string) (*cert.Bundle, error)
	Store(*cert.Bundle) error

	StoreAccount(string) error
	RetrieveAccount() (string, error)
}
