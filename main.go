package main

import (
	"bytes"
	"compress/zlib"
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
		"initial_dn":   "cn=admin,dc=saml",
		"initial_pw":   "secret",
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
	log.Printf("Parsed arguments: %+v\n", args)

	// Register Bind and Search function handlers
	handler := ldapHandler{args: args}
	s.BindFunc("", handler)

	// Start the server
	listen := "localhost:3389"
	log.Printf("Starting LDAP server on %s\n", listen)
	if err := s.ListenAndServe(listen); err != nil {
		log.Fatalf("LDAP Server Failed: %s\n", err.Error())
	}
}

type ldapHandler struct {
	args map[string]string
}

// Bind: Accept a base64-encoded SAML assertion as the password
func (h ldapHandler) Bind(bindDN, xmlAssertion string, conn net.Conn) (ldap.LDAPResultCode, error) {
	log.Printf("Received Bind request: bindDN=%s, xmlAssertion=%s\n", bindDN, xmlAssertion)

	// Check for initial bind credentials
	if bindDN == h.args["initial_dn"] && xmlAssertion == h.args["initial_pw"] {
		log.Printf("Initial bind successful for user: %s\n", bindDN)
		return ldap.LDAPResultSuccess, nil
	}

	// Load and validate the assertion using gosaml2
	metadata, err := loadMetadata(h.args["idp_metadata"]) // Update path to your IdP metadata
	if err != nil {
		log.Printf("Error loading metadata: %v\n", err)
		return ldap.LDAPResultInvalidCredentials, nil
	}

	log.Printf("Loaded IdP metadata successfully\n")

	var spKeyStore dsig.X509KeyStore
	spCertFile := h.args["sp_cert"]
	spKeyFile := h.args["sp_key"]

	if spCertFile != "" && spKeyFile != "" {
		// Load SP certificate and private key from files
		log.Printf("Loading SP certificate from %s and key from %s\n", spCertFile, spKeyFile)
		tlsCert, err := loadTLSCertificate(spCertFile, spKeyFile)
		if err != nil {
			log.Printf("Error loading SP certificate or key, falling back: %v\n", err)
			spKeyStore = dsig.RandomKeyStoreForTest()
		} else {
			log.Printf("SP certificate loaded successfully\n")
			spKeyStore = dsig.TLSCertKeyStore(tlsCert)
		}
	} else {
		log.Printf("No SP certificate or key provided; using random key store\n")
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
	log.Printf("Loading IdP metadata from %s\n", idpMetadataPath)

	var rawMetadata []byte
	var err error

	if strings.HasPrefix(idpMetadataPath, "http://") || strings.HasPrefix(idpMetadataPath, "https://") {
		response, err := http.Get(idpMetadataPath)
		if err != nil {
			log.Printf("Error loading IdP metadata: %v\n", err)
			return nil, fmt.Errorf("Error loading IdP metadata: %v", err)
		}
		defer response.Body.Close()

		if response.StatusCode != http.StatusOK {
			log.Printf("Error loading IdP metadata: received status code %d\n", response.StatusCode)
			return nil, fmt.Errorf("Error loading IdP metadata: received status code %d", response.StatusCode)
		}

		rawMetadata, err = io.ReadAll(response.Body)
		if err != nil {
			log.Printf("Error reading IdP metadata: %v\n", err)
			return nil, fmt.Errorf("Error loading IdP metadata: %v", err)
		}
	} else {
		rawMetadata, err = os.ReadFile(idpMetadataPath)
		if err != nil {
			log.Printf("Error loading IdP metadata from file: %v\n", err)
			return nil, errors.New("Error loading IdP metadata")
		}
	}

	metadata := &types.EntityDescriptor{}
	if err := xml.Unmarshal(rawMetadata, metadata); err != nil {
		log.Printf("Error parsing the IdP metadata: %v\n", err)
		return nil, errors.New("Error parsing the IdP metadata")
	}

	log.Printf("IdP metadata loaded and parsed successfully\n")
	return metadata, nil
}

// Create SAML service provider
func createServiceProvider(metadata *types.EntityDescriptor, spKeyStore dsig.X509KeyStore) *saml2.SAMLServiceProvider {
	log.Printf("Creating SAML Service Provider\n")

	certStore := dsig.MemoryX509CertificateStore{Roots: []*x509.Certificate{}}
	for _, kd := range metadata.IDPSSODescriptor.KeyDescriptors {
		for _, xcert := range kd.KeyInfo.X509Data.X509Certificates {
			certData, err := base64.StdEncoding.DecodeString(xcert.Data)
			if err == nil {
				if idpCert, err := x509.ParseCertificate(certData); err == nil {
					certStore.Roots = append(certStore.Roots, idpCert)
					log.Printf("Added IDP certificate to store: %s\n", idpCert.Subject.CommonName)
				} else {
					log.Printf("Error parsing IDP certificate: %v\n", err)
				}
			} else {
				log.Printf("Error decoding certificate: %v\n", err)
			}
		}
	}

	log.Printf("SAML Service Provider created successfully\n")
	return &saml2.SAMLServiceProvider{
		IdentityProviderSSOURL:  metadata.IDPSSODescriptor.SingleSignOnServices[0].Location,
		IdentityProviderIssuer:  metadata.EntityID,
		IDPCertificateStore:     &certStore,
		SPKeyStore:              spKeyStore,
		SkipSignatureValidation: true,
	}
}

// decodeAndDecompress decodes and decompresses the SAML assertion
func zlibDecompress(xmlSrc string) (string, error) {
	// Try decoding as base64
	decoded, err := base64.StdEncoding.DecodeString(xmlSrc)
	if err != nil {
		// If base64 decoding fails, assume the input is not encoded
		decoded = []byte(xmlSrc)
	}

	// Create a reader for the gzipped data
	reader, err := zlib.NewReader(bytes.NewReader(decoded))
	if err != nil {
		return "", fmt.Errorf("Decompression failed: %v", err)
	}
	defer reader.Close()

	// Read the decompressed data
	decompressed, err := io.ReadAll(reader)
	if err != nil {
		return "", fmt.Errorf("Reading decompressed data failed: %v", err)
	}

	return base64.StdEncoding.EncodeToString(decompressed), nil
}

func validateAssertion(sp *saml2.SAMLServiceProvider, xml string, bindDN string, lookupAttr string) error {
	log.Printf("Validating SAML assertion for bindDN: %s\n", bindDN)

	processedXml, err := zlibDecompress(xml)
	if err != nil {
		log.Println(err)
		processedXml = xml
	}

	assertionInfo, err := sp.RetrieveAssertionInfo(processedXml)
	if err != nil {
		log.Printf("Error parsing assertion: %v\n", err)
		return fmt.Errorf("error parsing assertion: %w", err)
	}

	if assertionInfo.WarningInfo.InvalidTime {
		log.Printf("Assertion expired\n")
		return errors.New("assertion expired")
	}

	for _, attr := range assertionInfo.Values {
		log.Printf("Checking attribute: %s\n", attr.Name)
		if attr.Name == lookupAttr {
			for _, value := range attr.Values {
				log.Printf("Comparing value: %s with bindDN: %s\n", value.Value, bindDN)
				if value.Value == bindDN {
					log.Printf("User found in assertion\n")
					return nil
				}
			}
		}
	}

	log.Printf("User not found in assertion\n")
	return errors.New("user not found in assertion")
}

