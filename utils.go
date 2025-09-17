package setup_acme

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
)

func certToString(cert *x509.Certificate) string {
	return string(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}))
}

func stringToCert(rawCert string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(rawCert))
	if block == nil {
		return nil, errors.New("could not convert pem to certificate")
	}

	if block.Type != "CERTIFICATE" {
		return nil, errors.New("provided string is no certificate")
	}

	return x509.ParseCertificate(block.Bytes)
}

func privateKeyToString(key *rsa.PrivateKey) string {
	privBytes := x509.MarshalPKCS1PrivateKey(key)

	privPem := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privBytes,
	})

	return string(privPem)
}

func stringToPrivateKey(key string) *rsa.PrivateKey {
	if key == "" {
		return nil
	}
	block, _ := pem.Decode([]byte(key))
	if block == nil {
		return nil
	}

	privKey, _ := x509.ParsePKCS1PrivateKey(block.Bytes)

	return privKey
}
