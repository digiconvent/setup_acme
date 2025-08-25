package setup_acme

import (
	"crypto/x509"
	"encoding/pem"
)

func (acme *AcmeClient) downloadCertificate() (*x509.Certificate, error) {
	_, body, err := acme.request(acme.client.order.Certificate, "")
	if err != nil {
		return nil, err
	}

	p, _ := pem.Decode(body)

	cert := x509.Certificate{
		Raw: p.Bytes,
	}
	return &cert, nil
}
