package setup_acme_test

import (
	"crypto/x509"
	"testing"
	"time"

	"github.com/DigiConvent/setup_acme"
)

func TestAcmeProcess(t *testing.T) {
	initData := &setup_acme.InitData{
		Domain:       "<your fqdn>",
		Emailaddress: "<your e-mailaddress>",
	}
	acme := setup_acme.AcmeClient{
		DirectoryUrl: "https://acme-staging-v02.api.letsencrypt.org/directory", // use a staging url for testing
		InitData:     initData,
	}

	if initData.AccountPrivateKey != "" {
		t.Fatal("expected account private key to be empty")
	}
	if initData.DomainPrivateKey != "" {
		t.Fatal("expected domain private key to be empty")
	}

	err := acme.Do()
	if err != nil {
		t.Fatal(err)
	}

	if acme.InitData.AccountPrivateKey == "" {
		t.Fatal("expected account private key not to be empty")
	}
	if acme.InitData.DomainPrivateKey == "" {
		t.Fatal("expected domain private key not to be empty")
	}
	if acme.RefreshData.Kid == "" {
		t.Fatal("expected kid not to be empty")
	}
	if acme.RefreshData.Certificate == "" {
		t.Fatal("expected certificate not to be empty")
	}

	x, err := acme.NeedsRenewal()
	if err != nil {
		t.Fatal(err)
	}
	if x == true {
		t.Fatal("did not expect certificate to need renewal immediately after creation")
	}

	cert, err := x509.ParseCertificate([]byte(acme.RefreshData.Certificate))
	if err != nil {
		t.Fatal("expected certificate to parse correctly", err)
	}

	if cert == nil {
		t.Fatal("expected cert not to be nil")
	}

	inTenDays := time.Now().AddDate(0, 0, 1).Unix()
	expirationDate := cert.NotAfter.Unix()
	if expirationDate < inTenDays {
		t.Fatal("did not expect certificate to expire that soon")
	}
}
