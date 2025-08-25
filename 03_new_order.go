package setup_acme

import (
	"encoding/json"
)

type orderResponse struct {
	Status            string   `json:"status"`
	Finalize          string   `json:"finalize"`
	AuthorizationUrls []string `json:"authorizations"`
	Certificate       string   `json:"certificate"`
	Location          string
}

func (acme *AcmeClient) newOrder() error {
	domain := acme.InitData.Domain
	payload := `{"identifiers":[{"type": "dns","value":"www.` + domain + `"},{"type": "dns","value":"` + domain + `" }]}`

	headers, contents, err := acme.request(acme.client.urls.NewOrder, payload)
	if err != nil {
		return err
	}

	json.Unmarshal(contents, &acme.client.order)
	acme.client.order.Location = headers.Get("Location")

	return nil
}
