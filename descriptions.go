package irmago

import (
	"encoding/xml"

	"github.com/mhe/gabi"
)

// SchemeManagerDescription describes a scheme manager.
type SchemeManagerDescription struct {
	Name              string `xml:"Id"`
	URL               string `xml:"Contact"`
	HRName            string `xml:"Name"`
	Description       string
	KeyshareServer    string
	KeyshareWebsite   string
	KeyshareAttribute string
	XMLVersion        int      `xml:"version,attr"`
	XMLName           xml.Name `xml:"SchemeManager"`
}

// IssuerDescription describes an issuer.
type IssuerDescription struct {
	HRName            string `xml:"Name"`
	HRShortName       string `xml:"ShortName"`
	Name              string `xml:"ID"`
	SchemeManagerName string `xml:"SchemeManager"`
	ContactAddress    string
	ContactEMail      string
	URL               string `xml:"baseURL"`
	XMLVersion        int    `xml:"version,attr"`
	identifier        *IssuerIdentifier
}

// CredentialDescription is a description of a credential type, specifying (a.o.) its name, issuer, and attributes.
type CredentialDescription struct {
	HRName            string `xml:"Name"`
	HRShortName       string `xml:"ShortName"`
	IssuerName        string `xml:"IssuerID"`
	SchemeManagerName string `xml:"SchemeManager"`
	Name              string `xml:"CredentialID"`
	IsSingleton       bool   `xml:"ShouldBeSingleton"`
	Description       string
	Attributes        []AttributeDescription `xml:"Attributes>Attribute"`
	XMLVersion        int                    `xml:"version,attr"`
	XMLName           xml.Name               `xml:"IssueSpecification"`
	identifier        *CredentialTypeIdentifier
}

// AttributeDescription is a description of an attribute within a credential type.
type AttributeDescription struct {
	Name        string
	Description string
}

// Identifier returns the identifier of the specified credential type.
func (cd *CredentialDescription) Identifier() string {
	return cd.SchemeManagerName + "." + cd.IssuerName + "." + cd.Name
}

// Identifier returns the identifier of the specified issuer description.
func (id *IssuerDescription) Identifier() string {
	return id.SchemeManagerName + "." + id.Name
}

// CurrentPublicKey returns the latest known public key of the issuer identified by this instance.
func (id *IssuerDescription) CurrentPublicKey() *gabi.PublicKey {
	keys := MetaStore.publickeys[id.Identifier()]
	if keys == nil || len(keys) == 0 {
		return nil
	}
	return keys[len(keys)-1]
}

// PublicKey returns the specified public key of the issuer identified by this instance.
func (id *IssuerDescription) PublicKey(index int) *gabi.PublicKey {
	keys := MetaStore.publickeys[id.Identifier()]
	if keys == nil || index >= len(keys) {
		return nil
	}
	return keys[index]
}
