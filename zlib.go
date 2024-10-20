package main

import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"fmt"
	"io"
	"log"
)

func zlibDecompress(xmlSrc []byte) ([]byte, error) {
	log.Println("zlibDecompress: decoding base64")

	decoded := make([]byte, base64.StdEncoding.DecodedLen(len(xmlSrc)))
	_, err := base64.StdEncoding.Decode(decoded, xmlSrc)
	if err != nil {
		// If base64 decoding fails, assume the input is not encoded
		log.Printf("zlibDecompress: base64 decoding error, proceeding: %s\n", err)
		decoded = []byte(xmlSrc)
	}

	log.Println("zlibDecompress: decompressing")
	// Create a reader for the gzipped data
	reader, err := zlib.NewReader(bytes.NewReader(decoded))
	if err != nil {
		return nil, fmt.Errorf("Decompression failed: %v", err)
	}
	defer reader.Close()

	// Read the decompressed data
	decompressed, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("Reading decompressed data failed: %v", err)
	}

	log.Println("zlibDecompress: decompressed")
	return decompressed, nil
}
