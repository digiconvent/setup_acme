package setup_acme

import (
	"errors"
)

func (acme *AcmeClient) newAccount() error {
	email := acme.InitData.Emailaddress
	headers, _, err := acme.request(acme.client.urls.NewAccount, `{"termsOfServiceAgreed": true, "contact": ["mailto:`+email+`"]}`)
	if err != nil {
		return err
	}

	location := headers.Get("Location")
	if location == "" {
		return errors.New("empty location, cannot continue")
	}
	acme.client.kid = location

	return nil
}
