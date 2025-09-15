package setup_acme

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
)

func (acme *AcmeClient) initialise() error {
	res, err := http.Get(acme.DirectoryUrl)
	if err != nil {
		return errors.New("could not reach directory url'" + acme.DirectoryUrl + "': " + err.Error())
	}

	defer res.Body.Close()

	contents, err := io.ReadAll(res.Body)
	if err != nil {
		return errors.New("could not read directory url response: " + err.Error())
	}

	err = json.Unmarshal(contents, &acme.client.urls)
	if err != nil {
		return errors.New("could not parse directory response: " + string(contents))
	}

	// get the nonce
	response, err := http.Head(acme.client.urls.NewNonce)
	if err != nil {
		return errors.New("could not fetch a new nonce: " + err.Error())
	}

	if response.StatusCode != 200 {
		return errors.New("invalid response status")
	}

	nonce := response.Header.Get("Replay-Nonce")
	if nonce == "" {
		return errors.New("empty nonce received")
	}

	acme.client.nonce = nonce

	return nil
}
