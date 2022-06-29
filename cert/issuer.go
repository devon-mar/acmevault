package cert

import "crypto"

type Issuer interface {
	Issue(CertRequest) (*Bundle, error)
	Account() string
}

type CertRequest struct {
	Domains    []string
	PrivateKey crypto.PrivateKey
	MustStaple bool
	KeyType    string
}
