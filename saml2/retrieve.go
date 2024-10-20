package saml2

import saml2 "github.com/russellhaering/gosaml2"

func (sp *CustomSAMLServiceProvider) RetrieveAssertionInfo(rawAssertion []byte) (*saml2.AssertionInfo, error) {
	assertionInfo := &saml2.AssertionInfo{
		Values: make(saml2.Values),
	}

	assertion, err := sp.ValidateAssertion(rawAssertion)
	if err != nil {
		return nil, saml2.ErrVerification{Cause: err}
	}

	warningInfo, err := sp.VerifyAssertionConditions(assertion)
	if err != nil {
		return nil, err
	}

	//Get the NameID
	subject := assertion.Subject
	if subject == nil {
		return nil, saml2.ErrMissingElement{Tag: saml2.SubjectTag}
	}

	nameID := subject.NameID
	if nameID == nil {
		return nil, saml2.ErrMissingElement{Tag: saml2.NameIdTag}
	}

	assertionInfo.NameID = nameID.Value

	//Get the actual assertion attributes
	attributeStatement := assertion.AttributeStatement
	if attributeStatement == nil && !sp.AllowMissingAttributes {
		return nil, saml2.ErrMissingElement{Tag: saml2.AttributeStatementTag}
	}

	if attributeStatement != nil {
		for _, attribute := range attributeStatement.Attributes {
			assertionInfo.Values[attribute.Name] = attribute
		}
	}

	if assertion.AuthnStatement != nil {
		if assertion.AuthnStatement.AuthnInstant != nil {
			assertionInfo.AuthnInstant = assertion.AuthnStatement.AuthnInstant
		}
		if assertion.AuthnStatement.SessionNotOnOrAfter != nil {
			assertionInfo.SessionNotOnOrAfter = assertion.AuthnStatement.SessionNotOnOrAfter
		}

		assertionInfo.SessionIndex = assertion.AuthnStatement.SessionIndex
	}

	assertionInfo.WarningInfo = warningInfo
	return assertionInfo, nil
}
