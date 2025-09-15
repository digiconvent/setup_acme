package setup_acme

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/go-jose/go-jose/v4"
)

func (acme *AcmeClient) request(url, payload string) (http.Header, []byte, error) {
	newAccount := url == acme.client.urls.NewAccount
	client := http.Client{}
	parsedPayload, err := acme.serialisePayload(url, payload, newAccount)
	if err != nil {
		return nil, nil, err
	}
	request, err := http.NewRequest("POST", url, parsedPayload)
	if err != nil {
		return nil, nil, err
	}
	request.Header.Set("Content-Type", "application/jose+json")

	response, err := client.Do(request)
	if err != nil {
		return response.Header, nil, err
	}
	defer response.Body.Close()

	contents, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, nil, err
	}

	err = acme.handleError(response.StatusCode, contents)
	if err != nil {
		return response.Header, contents, err
	}

	nonce := response.Header.Get("Replay-Nonce")
	if nonce == "" {
		return response.Header, contents, errors.New("empty nonce, cannot continue")
	}
	acme.client.nonce = nonce

	return response.Header, contents, nil
}

func (acme *AcmeClient) handleError(status int, body []byte) error {
	if status < 300 {
		return nil
	}

	data := make(map[string]any)
	json.Unmarshal(body, &data)

	errKey, _ := strings.CutPrefix(data["type"].(string), "urn:ietf:params:acme:error:")
	errMsg := errorMessages[errKey] + ": " + data["detail"].(string)

	subProblems := data["subproblems"]

	if subProblems != nil {
		errMsg += "There are multiple problems"
		errMsg += fmt.Sprint(subProblems)
	}
	return errors.New(errMsg)
}

var errorMessages = map[string]string{
	"accountDoesNotExist":     "The request specified an account that does not exist",
	"alreadyRevoked":          "The request specified a certificate to be revoked that has already been revoke",
	"badCSR":                  "The CSR is unacceptable (e.g., due to a short key)",
	"badNonce":                "The client sent an unacceptable anti-replay nonc",
	"badPublicKey":            "The JWS was signed by a public key the server does not support",
	"badRevocationReason":     "The revocation reason provided is not allowed by the serve",
	"badSignatureAlgorithm":   "The JWS was signed with an algorithm the server does not support",
	"caa":                     "Certification Authority Authorization (CAA) records forbid the CA from issuing a certificat",
	"compound":                "Specific error conditions are indicated in the \"subproblems\" array",
	"connection":              "The server could not connect to validation target",
	"dns":                     "There was a problem with a DNS query during identifier validation",
	"externalAccountRequired": "The request must include a value for the \"externalAccountBinding\" field",
	"incorrectResponse":       "Response received didn't match the challenge's requirements",
	"invalidContact":          "A contact URL for an account was invalid",
	"malformed":               "The request message was malformed",
	"orderNotReady":           "The request attempted to finalize an order that is not ready to be finalized",
	"rateLimited":             "The request exceeds a rate limit",
	"rejectedIdentifier":      "The server will not issue certificates for the identifie",
	"serverInternal":          "The server experienced an internal error",
	"tls":                     "The server received a TLS error during validation",
	"unauthorized":            "The client lacks sufficient authorization",
	"unsupportedContact":      "A contact URL for an account used an unsupported protocol scheme",
	"unsupportedIdentifier":   "An identifier is of an unsupported type",
	"userActionRequired":      "Visit the \"instance\" URL and take actions specified there",
}

func (acme *AcmeClient) serialisePayload(url, payload string, newAccount bool) (io.Reader, error) {
	privateKey := acme.InitData.accountPrivateKey

	jwk := jose.JSONWebKey{
		Key:       privateKey,
		Algorithm: "RS256",
		Use:       "sig",
	}
	headers := map[jose.HeaderKey]any{
		"alg":   "RS256",
		"nonce": acme.client.nonce,
		"url":   url,
	}
	if newAccount {
		publicJwk := jwk.Public()
		jwkJson, err := publicJwk.MarshalJSON()

		if err != nil {
			return nil, errors.New("cannot get public key: " + err.Error())
		}
		headers["jwk"] = json.RawMessage(jwkJson)
	} else {
		headers["kid"] = acme.client.kid
	}

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: privateKey}, &jose.SignerOptions{
		ExtraHeaders: headers,
	})
	if err != nil {
		return nil, errors.New("cannot create a new signer " + err.Error())
	}

	object, err := signer.Sign([]byte(payload))
	if err != nil {
		return nil, errors.New("cannot sign " + err.Error())
	}

	base64Serialised := object.FullSerialize()
	return bytes.NewBuffer([]byte(base64Serialised)), nil
}
