package saml2

import (
	"bytes"
	"compress/flate"
	"fmt"
	"io"

	"github.com/beevik/etree"
	rtvalidator "github.com/mattermost/xml-roundtrip-validator"
)

const (
	defaultMaxDecompressedResponseSize = 5 * 1024 * 1024
)

// maybeDeflate invokes the passed decoder over the passed data. If an error is
// returned, it then attempts to deflate the passed data before re-invoking
// the decoder over the deflated data.
func maybeDeflate(data []byte, maxSize int64, decoder func([]byte) error) error {
	err := decoder(data)
	if err == nil {
		return nil
	}

	// Default to 5MB max size
	if maxSize == 0 {
		maxSize = defaultMaxDecompressedResponseSize
	}

	lr := io.LimitReader(flate.NewReader(bytes.NewReader(data)), maxSize+1)

	deflated, err := io.ReadAll(lr)
	if err != nil {
		return err
	}

	if int64(len(deflated)) > maxSize {
		return fmt.Errorf("deflated response exceeds maximum size of %d bytes", maxSize)
	}

	return decoder(deflated)
}

// parseResponse is a helper function that was refactored out so that the XML parsing behavior can be isolated and unit tested
func parseResponse(xml []byte, maxSize int64) (*etree.Document, *etree.Element, error) {
	var doc *etree.Document
	var rawXML []byte

	err := maybeDeflate(xml, maxSize, func(xml []byte) error {
		doc = etree.NewDocument()
		rawXML = xml
		return doc.ReadFromBytes(xml)
	})
	if err != nil {
		return nil, nil, err
	}

	el := doc.Root()
	if el == nil {
		return nil, nil, fmt.Errorf("unable to parse response")
	}

	// Examine the response for attempts to exploit weaknesses in Go's encoding/xml
	err = rtvalidator.Validate(bytes.NewReader(rawXML))
	if err != nil {
		return nil, nil, err
	}

	return doc, el, nil
}
