package setup_acme

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"time"
)

func (acme *AcmeClient) finalizeOrder() error {
	domain := acme.InitData.Domain
	privateKey := acme.InitData.domainPrivateKey

	subject := pkix.Name{
		CommonName:         domain,
		Organization:       []string{"DigiConvent"},
		OrganizationalUnit: []string{domain + " - DigiConvent"},
	}
	template := x509.CertificateRequest{
		DNSNames: []string{domain, "www." + domain},
		Subject:  subject,
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &template, privateKey)
	if err != nil {
		return err
	}

	base64Csr := base64.RawURLEncoding.EncodeToString(csr)

	_, _, err = acme.request(acme.client.order.Finalize, `{"csr":"`+base64Csr+`"}`)
	if err != nil {
		return err
	}
	var res orderResponse
	res.Status = "processing"
	for res.Status != "valid" {
		_, contents, err := acme.request(acme.client.order.Location, "")
		if err != nil {
			return err
		}
		err = json.Unmarshal(contents, &res)
		if err != nil {
			return err
		}

		time.Sleep(2 * time.Second)
	}

	acme.client.order.Certificate = res.Certificate
	return nil
}
