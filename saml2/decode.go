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

// parseResponse parses the XML and returns the root element of the response (or assertion in your case)
func parseResponse(xml []byte, maxSize int64) (*etree.Element, error) {
	var doc *etree.Document

	err := maybeDeflate(xml, maxSize, func(xml []byte) error {
		doc = etree.NewDocument()
		return doc.ReadFromBytes(xml)
	})
	if err != nil {
		return nil, err
	}

	el := doc.Root()
	if el == nil {
		return nil, fmt.Errorf("unable to parse response")
	}

	// Examine the response for attempts to exploit weaknesses in Go's encoding/xml
	err = rtvalidator.Validate(bytes.NewReader(xml))
	if err != nil {
		return nil, err
	}

	// In this case, we only need to return the root element (which could be the assertion itself)
	return el, nil
}
