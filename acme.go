package setup_acme

import (
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"net/http"
	"time"
)

type InitData struct {
	Domain            string // mandatory, for obvious reasons
	Emailaddress      string // mandatory, for creating an acme account
	DomainPrivateKey  string // optional, will be generated if left empty
	AccountPrivateKey string // optional, will be generated if left empty
	Organisation      string

	// derived from the values above
	domainPrivateKey  *rsa.PrivateKey
	accountPrivateKey *rsa.PrivateKey
}

// this data needs to be stored somewhere in order to restore the acme client
type RefreshData struct {
	Certificate string // ANS.1 DER format
	Kid         string
}

type AcmeClient struct {
	// find the directory url from the acme server
	DirectoryUrl string
	// this is mandatory
	InitData *InitData
	// this is optional, since this will be filled out once the certificate has been requested successfully
	// it is mandatory for renewing the certificate
	RefreshData *RefreshData

	client struct {
		kid  string
		urls struct {
			KeyChange   string
			NewAccount  string
			NewNonce    string
			NewOrder    string
			RenewalInfo string
			RevokeCert  string
		}
		order struct {
			Status            string   `json:"status"`
			Finalize          string   `json:"finalize"`
			AuthorizationUrls []string `json:"authorizations"`
			Certificate       string   `json:"certificate"`
			Location          string
		}

		handlers   *http.ServeMux
		server     *http.Server // this is the client turning into a server to serve http challenges
		challenges []*challenge
		authzUrls  []string
		nonce      string
	}
}

func (acme *AcmeClient) NeedsRenewal() (bool, error) {
	if acme.RefreshData == nil {
		return false, errors.New("can't renew without RefreshData")
	}
	if acme.RefreshData.Certificate == "" {
		return false, errors.New("can't renew what isn't present")
	}
	if acme.RefreshData.Kid == "" || acme.InitData.AccountPrivateKey == "" {
		return false, errors.New("can't renew for an account that doesn't exist")
	}

	cert, err := stringToCert(acme.RefreshData.Certificate)
	if err != nil {
		return false, err
	}

	expiration := cert.NotAfter.Unix()
	nowInTenDays := time.Now().AddDate(0, 0, 10).Unix()
	if nowInTenDays > expiration {
		return true, nil
	}
	return false, nil
}

func (acme *AcmeClient) Do() error {
	if acme.DirectoryUrl == "" {
		return errors.New("directory url cannot be empty")
	}
	if acme.InitData.Organisation == "" {
		return errors.New("organisation should not be empty")
	}
	acme.initialise()
	if acme.InitData == nil {
		return errors.New("init data cannot be empty")
	}

	var err error
	var domainPk *rsa.PrivateKey
	if acme.InitData.DomainPrivateKey == "" {
		domainPk, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return err
		}
		acme.InitData.DomainPrivateKey = privateKeyToString(domainPk)
	} else {
		domainPk = stringToPrivateKey(acme.InitData.DomainPrivateKey)
	}
	acme.InitData.domainPrivateKey = domainPk

	var accountPk *rsa.PrivateKey
	if acme.InitData.AccountPrivateKey == "" {
		accountPk, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return err
		}
		acme.InitData.AccountPrivateKey = privateKeyToString(accountPk)
	} else {
		accountPk = stringToPrivateKey(acme.InitData.AccountPrivateKey)
	}
	acme.InitData.accountPrivateKey = accountPk

	// first let's create a user if there is no kid
	if acme.RefreshData == nil {
		acme.RefreshData = &RefreshData{}
	}
	if acme.RefreshData.Kid == "" {
		if err = acme.newAccount(); err != nil {
			return err
		} else {
			acme.RefreshData.Kid = acme.client.kid
		}
	} else {
		acme.client.kid = acme.RefreshData.Kid
	}

	if err = acme.newOrder(); err != nil {
		return err
	}

	if err = acme.requestChallengeDetails(); err != nil {
		return err
	}

	if err = acme.prepareChallenges(); err != nil {
		return err
	}

	if err = acme.finalizeOrder(); err != nil {
		return err
	}

	cert, err := acme.downloadCertificate()
	if err != nil {
		return err
	}

	acme.RefreshData.Certificate = certToString(cert)

	return nil
}
