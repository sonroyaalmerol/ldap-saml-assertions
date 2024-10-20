package main

import (
	"crypto/tls"
	"fmt"
)

// loadTLSCertificate loads the SP certificate and private key as a tls.Certificate
func loadTLSCertificate(certFile string, keyFile string) (tls.Certificate, error) {
	tlsCert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("Error loading certificate or key pair: %v", err)
	}
	return tlsCert, nil
}
