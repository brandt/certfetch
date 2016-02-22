package main

import (
	"bytes"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
)

// Note: This doesn't produce a strict RFC-2253 DN.
//
// For that, you'd at least need to escape existing commas and omit the space
// between objects.
//
// See: openssl x509 -subject -nameopt RFC2253 -noout -in /tmp/foo.pem
func NamesToDN(names []pkix.AttributeTypeAndValue) string {
	var b bytes.Buffer

	for i, v := range names {
		b.WriteString(getTagForOid(v.Type))
		b.WriteString("=")
		b.WriteString(fmt.Sprint(v.Value))
		if i < len(names)-1 {
			b.WriteString(", ")
		}
	}

	return b.String()
}

func getTagForOid(oid asn1.ObjectIdentifier) string {
	type oidNameMap struct {
		oid  []int
		name string
	}

	// See: https://github.com/openssl/openssl/blob/da15ce/crypto/objects/objects.txt
	oidTags := []oidNameMap{
		{[]int{2, 5, 4, 3}, "CN"},
		{[]int{2, 5, 4, 4}, "SN"},
		{[]int{2, 5, 4, 5}, "serialNumber"},
		{[]int{2, 5, 4, 6}, "C"},
		{[]int{2, 5, 4, 7}, "L"},
		{[]int{2, 5, 4, 8}, "ST"},
		{[]int{2, 5, 4, 9}, "street"},
		{[]int{2, 5, 4, 10}, "O"},
		{[]int{2, 5, 4, 11}, "OU"},
		{[]int{2, 5, 4, 12}, "title"},
		{[]int{2, 5, 4, 13}, "description"},
		{[]int{2, 5, 4, 14}, "searchGuide"},
		{[]int{2, 5, 4, 15}, "businessCategory"},
		{[]int{2, 5, 4, 16}, "postalAddress"},
		{[]int{2, 5, 4, 17}, "postalCode"},
		{[]int{2, 5, 4, 18}, "postOfficeBox"},
		{[]int{2, 5, 4, 19}, "physicalDeliveryOfficeName"},
		{[]int{2, 5, 4, 20}, "telephoneNumber"},
		{[]int{2, 5, 4, 21}, "telexNumber"},
		{[]int{2, 5, 4, 22}, "teletexTerminalIdentifier"},
		{[]int{2, 5, 4, 23}, "facsimileTelephoneNumber"},
		{[]int{2, 5, 4, 24}, "x121Address"},
		{[]int{2, 5, 4, 25}, "internationaliSDNNumber"},
		{[]int{2, 5, 4, 26}, "registeredAddress"},
		{[]int{2, 5, 4, 27}, "destinationIndicator"},
		{[]int{2, 5, 4, 28}, "preferredDeliveryMethod"},
		{[]int{2, 5, 4, 29}, "presentationAddress"},
		{[]int{2, 5, 4, 30}, "supportedApplicationContext"},
		{[]int{2, 5, 4, 31}, "member"},
		{[]int{2, 5, 4, 32}, "owner"},
		{[]int{2, 5, 4, 33}, "roleOccupant"},
		{[]int{2, 5, 4, 34}, "seeAlso"},
		{[]int{2, 5, 4, 35}, "userPassword"},
		{[]int{2, 5, 4, 36}, "userCertificate"},
		{[]int{2, 5, 4, 37}, "cACertificate"},
		{[]int{2, 5, 4, 38}, "authorityRevocationList"},
		{[]int{2, 5, 4, 39}, "certificateRevocationList"},
		{[]int{2, 5, 4, 40}, "crossCertificatePair"},
		{[]int{2, 5, 4, 41}, "name"},
		{[]int{2, 5, 4, 42}, "GN"},
		{[]int{2, 5, 4, 43}, "initials"},
		{[]int{2, 5, 4, 44}, "generationQualifier"},
		{[]int{2, 5, 4, 45}, "x500UniqueIdentifier"},
		{[]int{2, 5, 4, 46}, "dnQualifier"},
		{[]int{2, 5, 4, 47}, "enhancedSearchGuide"},
		{[]int{2, 5, 4, 48}, "protocolInformation"},
		{[]int{2, 5, 4, 49}, "distinguishedName"},
		{[]int{2, 5, 4, 50}, "uniqueMember"},
		{[]int{2, 5, 4, 51}, "houseIdentifier"},
		{[]int{2, 5, 4, 52}, "supportedAlgorithms"},
		{[]int{2, 5, 4, 53}, "deltaRevocationList"},
		{[]int{2, 5, 4, 54}, "dmdName"},
		{[]int{2, 5, 4, 65}, "pseudonym"},
		{[]int{2, 5, 4, 72}, "role"},
		{[]int{1, 2, 840, 113549, 1, 9, 1}, "E"},
		{[]int{1, 3, 6, 1, 4, 1, 311, 60, 2, 1, 1}, "jurisdictionL"},
		{[]int{1, 3, 6, 1, 4, 1, 311, 60, 2, 1, 2}, "jurisdictionST"},
		{[]int{1, 3, 6, 1, 4, 1, 311, 60, 2, 1, 3}, "jurisdictionC"},
		{[]int{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}, "ct_precert_scts"},
		{[]int{1, 3, 6, 1, 4, 1, 11129, 2, 4, 3}, "ct_precert_poison"},
		{[]int{1, 3, 6, 1, 4, 1, 11129, 2, 4, 4}, "ct_precert_signer"},
		{[]int{1, 3, 6, 1, 4, 1, 11129, 2, 4, 5}, "ct_cert_scts"},
	}

	for _, v := range oidTags {
		if oid.Equal(v.oid) {
			return v.name
		}
	}

	return fmt.Sprint(oid)
}
