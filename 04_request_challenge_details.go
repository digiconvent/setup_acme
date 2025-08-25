package setup_acme

import (
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"unsafe"
)

type challengeResponse struct {
	Status     string `json:"status"`
	Identifier struct {
		Type  string `json:"type"`
		Value string `json:"value"`
	} `json:"identifier"`
	Challenges []challenge `json:"challenges"`
}

type challenge struct {
	Type    string `json:"type"`
	Url     string `json:"url"`
	Status  string `json:"status"`
	Token   string `json:"token"`
	KeyAuth string
}

func (acme *AcmeClient) requestChallengeDetails() error {
	acme.client.challenges = make([]*challenge, 0)
	for _, authz := range acme.client.order.AuthorizationUrls {
		_, body, err := acme.request(authz, "")
		if err != nil {
			return err
		}

		var challenges challengeResponse
		err = json.Unmarshal(body, &challenges)
		if err != nil {
			return err
		}

		var challenge *challenge
		for _, ch := range challenges.Challenges {
			if ch.Type == "http-01" {
				challenge = &ch
			}
		}

		challenge.KeyAuth = challenge.Token + "." + thumbPrint(acme.InitData.accountPrivateKey)
		acme.client.challenges = append(acme.client.challenges, challenge)
	}

	return nil
}

func thumbPrint(key *rsa.PrivateKey) string {
	size := int(unsafe.Sizeof(key.E))
	arr := make([]byte, size)
	e := key.E
	for i := range size {
		byt := *(*uint8)(unsafe.Pointer(uintptr(unsafe.Pointer(&e)) + uintptr(i)))
		arr[i] = byt
	}

	n := key.N.Bytes()
	E := base64.RawURLEncoding.EncodeToString(arr)
	for strings.HasSuffix(E, "A") {
		E, _ = strings.CutSuffix(E, "A")
	}
	N := base64.RawURLEncoding.EncodeToString(n)
	rawThumbPrint := []byte(`{"e":"` + E + `","kty":"RSA","n":"` + N + `"}`)
	fHash := sha256.Sum256(rawThumbPrint)

	hash := make([]byte, 0)
	for _, b := range fHash {
		hash = append(hash, b)
	}
	return base64.RawURLEncoding.EncodeToString(hash)
}
