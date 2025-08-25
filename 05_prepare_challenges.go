package setup_acme

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

func (acme *AcmeClient) prepareChallenges() error {
	acme.client.handlers = &http.ServeMux{}
	acme.client.handlers.HandleFunc("GET /.well-known/acme-challenge/{token}", func(w http.ResponseWriter, r *http.Request) {
		token := r.PathValue("token")
		for _, challenge := range acme.client.challenges {
			if challenge.Token == token {
				io.WriteString(w, challenge.KeyAuth)
				return
			}
		}
	})
	// i know, this line is retarded af
	acme.client.server = &http.Server{
		Addr:    ":80",
		Handler: acme.client.handlers,
	}

	go func() {
		acme.client.server.ListenAndServe() // ignore err since it only happens when server is closed, we don't need that
	}()

	for _, challenge := range acme.client.challenges {
		_, _, err := acme.request(challenge.Url, "{}")
		if err != nil {
			return err
		}
	}

	i := 1
	for !challengesAreValid(acme.client.challenges) {
		for _, challenge := range acme.client.challenges {
			if challenge.Status == "pending" {
				_, contents, err := acme.request(challenge.Url, "")
				if err != nil {
					return err
				}
				var challengeResponse challengeResponse
				err = json.Unmarshal(contents, &challengeResponse)
				if err != nil {
					return nil
				}
				if challengeResponse.Status == "invalid" {
					fmt.Println("failed acme challenge, check your ports/dns records")
					os.Exit(-1)
				} else {
					challenge.Status = challengeResponse.Status
				}
			}
		}

		if !challengesAreValid(acme.client.challenges) {
			time.Sleep(time.Duration(i) * time.Second)
			if i < 16 {
				i *= 2
			}
		}
	}

	err := acme.client.server.Close()
	if err != nil {
		return err
	}

	return nil
}

func challengesAreValid(challenges []*challenge) bool {
	for _, challenge := range challenges {
		if challenge.Status != "valid" {
			return false
		}
	}
	return true
}
