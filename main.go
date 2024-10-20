package main

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"

	"beryju.io/ldap"
	saml2 "github.com/russellhaering/gosaml2"
	"github.com/russellhaering/gosaml2/types"
	dsig "github.com/russellhaering/goxmldsig"
)

func parseArgs(arguments []string) map[string]string {
	args := map[string]string{
		"userid":       "uid",
		"idp_metadata": "",
		"sp_cert":      "",
		"sp_key":       "",
	}
	for _, arg := range arguments {
		split := strings.SplitN(arg, "=", 2)
		if len(split) == 2 {
			args[split[0]] = split[1]
		}
	}
	return args
}

func main() {
	s := ldap.NewServer()

	args := parseArgs(os.Args[1:])

	// Register Bind and Search function handlers
	handler := ldapHandler{args: args}
	s.BindFunc("", handler)

	// Start the server
	listen := "localhost:3389"
	log.Printf("Starting LDAP server on %s", listen)
	if err := s.ListenAndServe(listen); err != nil {
		log.Fatalf("LDAP Server Failed: %s", err.Error())
	}
}

type ldapHandler struct {
	args map[string]string
}

// Bind: Accept a base64-encoded SAML assertion as the password
func (h ldapHandler) Bind(bindDN, xmlAssertion string, conn net.Conn) (ldap.LDAPResultCode, error) {
	// Load and validate the assertion using gosaml2
	metadata, err := loadMetadata(h.args["idp_metadata"]) // Update path to your IdP metadata
	if err != nil {
		log.Printf("Error loading metadata: %v\n", err)
		return ldap.LDAPResultInvalidCredentials, nil
	}

	var spKeyStore dsig.X509KeyStore
	spCertFile := h.args["sp_cert"]
	spKeyFile := h.args["sp_key"]

	if spCertFile != "" && spKeyFile != "" {
		// Load SP certificate and private key from files
		tlsCert, err := loadTLSCertificate(spCertFile, spKeyFile)
		if err != nil {
			log.Printf("Error loading SP certificate or key, falling back: %v\n", err)
			spKeyStore = dsig.RandomKeyStoreForTest()
		} else {
			// Use a random key store if no certificate and key are provided
			spKeyStore = dsig.TLSCertKeyStore(tlsCert)
		}
	} else {
		// Use a random key store if no certificate and key are provided
		spKeyStore = dsig.RandomKeyStoreForTest()
	}

	sp := createServiceProvider(metadata, spKeyStore)

	// Validate the SAML assertion
	if err := validateAssertion(sp, xmlAssertion, bindDN, h.args["userid"]); err != nil {
		log.Printf("Invalid SAML assertion: %v\n", err)
		return ldap.LDAPResultInvalidCredentials, nil
	}

	log.Printf("User %s authenticated successfully\n", bindDN)
	return ldap.LDAPResultSuccess, nil
}

// Load metadata from IdP
func loadMetadata(idpMetadataPath string) (*types.EntityDescriptor, error) {
	var rawMetadata []byte
	var err error

	if strings.HasPrefix(idpMetadataPath, "http://") || strings.HasPrefix(idpMetadataPath, "https://") {
		response, err := http.Get(idpMetadataPath)
		if err != nil {
			return nil, fmt.Errorf("Error loading IdP metadata: %v", err)
		}
		defer response.Body.Close()

		if response.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("Error loading IdP metadata: received status code %d", response.StatusCode)
		}

		rawMetadata, err = io.ReadAll(response.Body)
		if err != nil {
			return nil, fmt.Errorf("Error loading IdP metadata: %v", err)
		}
	} else {
		rawMetadata, err = os.ReadFile(idpMetadataPath)
		if err != nil {
			return nil, errors.New("Error loading IdP metadata")
		}
	}

	metadata := &types.EntityDescriptor{}
	if err := xml.Unmarshal(rawMetadata, metadata); err != nil {
		return nil, errors.New("Error parsing the IdP metadata")
	}

	return metadata, nil
}

// Create SAML service provider
func createServiceProvider(metadata *types.EntityDescriptor, spKeyStore dsig.X509KeyStore) *saml2.SAMLServiceProvider {
	certStore := dsig.MemoryX509CertificateStore{Roots: []*x509.Certificate{}}
	for _, kd := range metadata.IDPSSODescriptor.KeyDescriptors {
		for _, xcert := range kd.KeyInfo.X509Data.X509Certificates {
			certData, err := base64.StdEncoding.DecodeString(xcert.Data)
			if err == nil {
				if idpCert, err := x509.ParseCertificate(certData); err == nil {
					certStore.Roots = append(certStore.Roots, idpCert)
				}
			}
		}
	}

	return &saml2.SAMLServiceProvider{
		IdentityProviderSSOURL: metadata.IDPSSODescriptor.SingleSignOnServices[0].Location,
		IdentityProviderIssuer: metadata.EntityID,
		IDPCertificateStore:    &certStore,
		SignAuthnRequests:      true,
		SPKeyStore:             spKeyStore,
	}
}

// Validate SAML assertion
func validateAssertion(sp *saml2.SAMLServiceProvider, xml string, bindDN string, lookupAttr string) error {
	assertionInfo, err := sp.RetrieveAssertionInfo(xml)
	if err != nil {
		return fmt.Errorf("error parsing assertion: %w", err)
	}

	if assertionInfo.WarningInfo.InvalidTime {
		return errors.New("assertion expired")
	}

	for _, attr := range assertionInfo.Values {
		if attr.Name == lookupAttr {
			for _, value := range attr.Values {
				if value.Value == bindDN {
					return nil
				}
			}
		}
	}

	return errors.New("user not found in assertion")
}

