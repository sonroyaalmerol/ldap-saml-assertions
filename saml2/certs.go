package saml2

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"

	dsig "github.com/russellhaering/goxmldsig"
)

func (sp *CustomSAMLServiceProvider) getDecryptCert() (*tls.Certificate, error) {
	if sp.SPKeyStore == nil {
		return nil, fmt.Errorf("no decryption certs available")
	}

	//This is the tls.Certificate we'll use to decrypt any encrypted assertions
	var decryptCert tls.Certificate

	switch crt := sp.SPKeyStore.(type) {
	case dsig.TLSCertKeyStore:
		// Get the tls.Certificate directly if possible
		decryptCert = tls.Certificate(crt)

	default:

		//Otherwise, construct one from the results of GetKeyPair
		pk, cert, err := sp.SPKeyStore.GetKeyPair()
		if err != nil {
			return nil, fmt.Errorf("error getting keypair: %v", err)
		}

		decryptCert = tls.Certificate{
			Certificate: [][]byte{cert},
			PrivateKey:  pk,
		}
	}

	if sp.ValidateEncryptionCert {
		// Check Validity period of certificate
		if len(decryptCert.Certificate) < 1 || len(decryptCert.Certificate[0]) < 1 {
			return nil, fmt.Errorf("empty decryption cert")
		} else if cert, err := x509.ParseCertificate(decryptCert.Certificate[0]); err != nil {
			return nil, fmt.Errorf("invalid x509 decryption cert: %v", err)
		} else {
			now := sp.Clock.Now()
			if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
				return nil, fmt.Errorf("decryption cert is not valid at this time")
			}
		}
	}

	return &decryptCert, nil
}
