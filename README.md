[![Build Status](https://travis-ci.org/mletterle/rust-nss.png)](https://travis-ci.org/mletterle/rust-nss)
# Network Security Services bindings for Rust

A set of bindings to the Mozilla NSS library. Depends on rust-nspr.

# Getting Started

Clone the repo. Start a simple ssl server on another terminal using openssl:

    openssl s_server -pass pass:nope -cert nss/tests/files/testcert.pem \
	-accept 1234 -key nss/tests/files/privkey.pem

Run `make test`

## License

rust-nss is licensed under the permissive MIT License.

See LICENSE for details.
