# CSR LE

## Testing

You need to set your own data in `acme_test.go` and run the tests on your webserver with setup dns records and `:80` free.

Don't forget to store the data after running acme.Do(), since your account data is needed to renew the certificate.