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
	"strconv"
	"strings"
	"time"

	"beryju.io/ldap"
	externalSaml2 "github.com/russellhaering/gosaml2"
	"github.com/russellhaering/gosaml2/types"
	dsig "github.com/russellhaering/goxmldsig"
	"github.com/sonroyaalmerol/ldap-saml-assertions/saml2"
)

func parseArgs(arguments []string) map[string]string {
	args := map[string]string{
		"userid":       "uid",
		"idp_metadata": "",
		"sp_cert":      "",
		"sp_key":       "",
		"sp_acs":       "",
		"initial_dn":   "cn=admin,dc=saml",
		"initial_pw":   "secret",
		"debug":        "false",
		"silent":		"false",
		"expire_time":	"4",
	}
	for _, arg := range arguments {
		split := strings.SplitN(arg, "=", 2)
		if len(split) == 2 {
			args[split[0]] = split[1]
		}
	}
	return args
}

type KnownUserAssertion struct {
	Assertion string
	LastUsed  time.Time
}

var knownUserAssertions map[string][]KnownUserAssertion

func main() {
	s := ldap.NewServer()

	knownUserAssertions = make(map[string][]KnownUserAssertion)

	args := parseArgs(os.Args[1:])
	log.Printf("Parsed arguments: %+v\n", args)

	// Load and validate the assertion using gosaml2
	metadata, err := loadMetadata(args["idp_metadata"]) // Update path to your IdP metadata
	if err != nil {
		log.Fatalf("Error loading metadata: %v\n", err)
	}

	log.Printf("Loaded IdP metadata successfully\n")

	var spKeyStore dsig.X509KeyStore
	spCertFile := args["sp_cert"]
	spKeyFile := args["sp_key"]

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

	sp := createServiceProvider(metadata, spKeyStore, args["sp_acs"])

	expireTime, err := strconv.Atoi(args["expire_time"])
	if err != nil {
		expireTime = 4
	}

	// Register Bind and Search function handlers
	handler := ldapHandler{
		sp:           sp,
		adminDn:      args["initial_dn"],
		adminPw:      args["initial_pw"],
		uidAttribute: args["userid"],
		debug:        args["debug"] == "true",
		silent:       args["silent"] == "true",
		expireTime:   expireTime,
	}
	s.BindFunc("", handler)

	// Start the server
	listen := "localhost:3389"
	log.Printf("Starting LDAP server on %s\n", listen)
	if err := s.ListenAndServe(listen); err != nil {
		log.Fatalf("LDAP Server Failed: %s\n", err.Error())
	}
}

type ldapHandler struct {
	sp           *saml2.CustomSAMLServiceProvider
	adminDn      string
	adminPw      string
	uidAttribute string
	debug        bool
	silent		 bool
	expireTime	 int
}

// Bind: Accept a base64-encoded SAML assertion as the password
func (h ldapHandler) Bind(bindDN, xmlAssertion string, conn net.Conn) (ldap.LDAPResultCode, error) {
	if !h.silent {
		log.Printf("Received Bind request: bindDN=%s\n", bindDN)
	}

	if h.debug {
		log.Printf("rawPw=%s\n", xmlAssertion)
	}

	// Check for initial bind credentials
	if bindDN == h.adminDn && xmlAssertion == h.adminPw {
		log.Printf("Initial bind successful for user: %s\n", bindDN)
		return ldap.LDAPResultSuccess, nil
	}

	knownAssertions := knownUserAssertions[bindDN]
	for i, userAssertion := range knownAssertions {
		if userAssertion.Assertion == xmlAssertion && time.Since(userAssertion.LastUsed) <= time.Duration(h.expireTime)*time.Hour {
			log.Printf("User %s authenticated successfully\n", bindDN)
			knownUserAssertions[bindDN][i].LastUsed = time.Now()
			return ldap.LDAPResultSuccess, nil
		}

		// Remove expired assertions
		if time.Since(userAssertion.LastUsed) > time.Duration(h.expireTime)*time.Hour {
			knownUserAssertions[bindDN] = append(knownAssertions[:i], knownAssertions[i+1:]...)
		}
	}

	// Validate the SAML assertion
	if err := validateAssertion(h, []byte(xmlAssertion), bindDN); err != nil {
		if !h.silent {
			log.Printf("Invalid SAML assertion: %v\n", err)
		}
		return ldap.LDAPResultInvalidCredentials, nil
	}

	// Add the assertion to known assertions
	knownUserAssertions[bindDN] = append(knownUserAssertions[bindDN], KnownUserAssertion{
		Assertion: xmlAssertion,
		LastUsed:  time.Now(),
	})

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
func createServiceProvider(metadata *types.EntityDescriptor, spKeyStore dsig.X509KeyStore, spAcs string) *saml2.CustomSAMLServiceProvider {
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
	return &saml2.CustomSAMLServiceProvider{
		SAMLServiceProvider: &externalSaml2.SAMLServiceProvider{
			IdentityProviderSSOURL:      metadata.IDPSSODescriptor.SingleSignOnServices[0].Location,
			IdentityProviderIssuer:      metadata.EntityID,
			AudienceURI:                 metadata.EntityID,
			AssertionConsumerServiceURL: spAcs,
			IDPCertificateStore:         &certStore,
			SPKeyStore:                  spKeyStore,
		},
	}
}

func validateAssertion(h ldapHandler, xml []byte, bindDN string) error {
	sp := h.sp
	lookupAttr := h.uidAttribute

	if !h.silent {
		log.Printf("Validating SAML assertion for bindDN: %s\n", bindDN)
	}

	processedXml, err := zlibDecompress(xml)
	if err != nil {
		if !h.silent {
			log.Println(err)
		}
		processedXml = xml
	}

	assertionInfo, err := sp.RetrieveAssertionInfo(processedXml)
	if err != nil {
		return fmt.Errorf("error parsing assertion: %w", err)
	}

	if assertionInfo.WarningInfo.InvalidTime {
		return errors.New("assertion expired")
	}

	if assertionInfo.WarningInfo.NotInAudience {
		return errors.New("not in audience")
	}

	for _, attr := range assertionInfo.Values {
		if !h.silent {
			log.Printf("Checking attribute: %s\n", attr.Name)
		}
		if attr.Name == lookupAttr {
			for _, value := range attr.Values {
				if !h.silent {
					log.Printf("Comparing value: %s with bindDN: %s\n", value.Value, bindDN)
				}
				if value.Value == bindDN {
					if !h.silent {
						log.Printf("User found in assertion\n")
					}
					return nil
				}
			}
		}
	}

	return errors.New("user not found in assertion")
}
