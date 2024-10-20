package saml2

import (
	"crypto/tls"
	"fmt"
	"time"

	"github.com/beevik/etree"
	saml2 "github.com/russellhaering/gosaml2"
	"github.com/russellhaering/gosaml2/types"
	dsig "github.com/russellhaering/goxmldsig"
)

type CustomSAMLServiceProvider struct {
	*saml2.SAMLServiceProvider
}

// ValidateEncodedAssertion both decodes and validates, based on SP
// configuration, an encoded, signed assertion. It will also appropriately
// decrypt the assertion if it was encrypted.
func (sp *CustomSAMLServiceProvider) ValidateAssertion(rawAssertion []byte) (*types.Assertion, error) {
	// Parse the raw assertion XML
	el, err := parseResponse(rawAssertion, sp.MaximumDecompressedBodySize)
	if err != nil {
		return nil, err
	}

	// Decrypt the assertion if it's encrypted
	el, err = sp.decryptAssertion(el)
	if err != nil {
		return nil, err
	}

	// Validate the assertion's signature if required
	var assertionSignaturesValidated bool
	if !sp.SkipSignatureValidation {
		err = sp.validateAssertionSignature(el)
		if err == dsig.ErrMissingSignature {
			return nil, fmt.Errorf("assertion must be signed")
		} else if err != nil {
			return nil, err
		} else {
			assertionSignaturesValidated = true
		}
	}

	// Unmarshal the assertion into the appropriate struct
	assertion := &types.Assertion{}
	err = xmlUnmarshalElement(el, assertion)
	if err != nil {
		return nil, fmt.Errorf("unable to unmarshal assertion: %v", err)
	}
	assertion.SignatureValidated = assertionSignaturesValidated

	// Validate the assertion using SP's custom validation logic
	issuer := assertion.Issuer
	if issuer == nil {
		return nil, saml2.ErrMissingElement{Tag: saml2.IssuerTag}
	}
	if sp.IdentityProviderIssuer != "" && assertion.Issuer.Value != sp.IdentityProviderIssuer {
		return nil, saml2.ErrInvalidValue{
			Key:      saml2.IssuerTag,
			Expected: sp.IdentityProviderIssuer,
			Actual:   issuer.Value,
		}
	}

	subject := assertion.Subject
	if subject == nil {
		return nil, saml2.ErrMissingElement{Tag: saml2.SubjectTag}
	}

	subjectConfirmation := subject.SubjectConfirmation
	if subjectConfirmation == nil {
		return nil, saml2.ErrMissingElement{Tag: saml2.SubjectConfirmationTag}
	}

	if subjectConfirmation.Method != saml2.SubjMethodBearer {
		return nil, saml2.ErrInvalidValue{
			Reason:   saml2.ReasonUnsupported,
			Key:      saml2.SubjectConfirmationTag,
			Expected: saml2.SubjMethodBearer,
			Actual:   subjectConfirmation.Method,
		}
	}

	subjectConfirmationData := subjectConfirmation.SubjectConfirmationData
	if subjectConfirmationData == nil {
		return nil, saml2.ErrMissingElement{Tag: saml2.SubjectConfirmationDataTag}
	}

	if subjectConfirmationData.Recipient != sp.AssertionConsumerServiceURL {
		return nil, saml2.ErrInvalidValue{
			Key:      saml2.RecipientAttr,
			Expected: sp.AssertionConsumerServiceURL,
			Actual:   subjectConfirmationData.Recipient,
		}
	}

	if subjectConfirmationData.NotOnOrAfter == "" {
		return nil, saml2.ErrMissingElement{Tag: saml2.SubjectConfirmationDataTag, Attribute: saml2.NotOnOrAfterAttr}
	}

	notOnOrAfter, err := time.Parse(time.RFC3339, subjectConfirmationData.NotOnOrAfter)
	if err != nil {
		return nil, saml2.ErrParsing{Tag: saml2.NotOnOrAfterAttr, Value: subjectConfirmationData.NotOnOrAfter, Type: "time.RFC3339"}
	}

	now := sp.Clock.Now()
	if now.After(notOnOrAfter) {
		return nil, saml2.ErrInvalidValue{
			Reason:   saml2.ReasonExpired,
			Key:      saml2.NotOnOrAfterAttr,
			Expected: now.Format(time.RFC3339),
			Actual:   subjectConfirmationData.NotOnOrAfter,
		}
	}

	return assertion, nil
}

func (sp *CustomSAMLServiceProvider) validationContext() *dsig.ValidationContext {
	ctx := dsig.NewDefaultValidationContext(sp.IDPCertificateStore)
	ctx.Clock = sp.Clock
	return ctx
}

func (sp *CustomSAMLServiceProvider) validateAssertionSignature(el *etree.Element) error {
	_, err := sp.validationContext().Validate(el)
	if err == dsig.ErrMissingSignature {
		return nil
	} else if err != nil {
		return err
	}

	return nil
}

func (sp *CustomSAMLServiceProvider) decryptAssertion(el *etree.Element) (*etree.Element, error) {
	var decryptCert *tls.Certificate

	encryptedAssertion := &types.EncryptedAssertion{}
	err := xmlUnmarshalElement(el, encryptedAssertion)
	if err != nil {
		return nil, fmt.Errorf("unable to unmarshal encrypted assertion: %v", err)
	}

	decryptCert, err = sp.getDecryptCert()
	if err != nil {
		return nil, fmt.Errorf("unable to get decryption certificate: %v", err)
	}

	raw, derr := encryptedAssertion.DecryptBytes(decryptCert)
	if derr != nil {
		return nil, fmt.Errorf("unable to decrypt encrypted assertion: %v", derr)
	}

	decryptedEl, err := parseResponse(raw, sp.MaximumDecompressedBodySize)
	if err != nil {
		return nil, fmt.Errorf("unable to create element from decrypted assertion bytes: %v", err)
	}

	return decryptedEl, nil
}
