package saml2

import (
	"encoding/xml"

	"github.com/beevik/etree"
)

func xmlUnmarshalElement(el *etree.Element, obj interface{}) error {
	doc := etree.NewDocument()
	doc.SetRoot(el)
	data, err := doc.WriteToBytes()
	if err != nil {
		return err
	}

	err = xml.Unmarshal(data, obj)
	if err != nil {
		return err
	}
	return nil
}
