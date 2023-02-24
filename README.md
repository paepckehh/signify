# OVERVIEW
[![Go Reference](https://pkg.go.dev/badge/paepcke.de/signify.svg)](https://pkg.go.dev/paepcke.de/signify) [![Go Report Card](https://goreportcard.com/badge/paepcke.de/signify)](https://goreportcard.com/report/paepcke.de/signify) [![Go Build](https://github.com/paepckehh/signify/actions/workflows/golang.yml/badge.svg)](https://github.com/paepckehh/signify/actions/workflows/golang.yml)

[paepcke.de/signify](https://paepcke.de/signify/)

This implementation does intentionally NOT satisfy the OpenBSD signify
private key bcrypt/pbkdf handling interface.

This implementation enables you to handle the secret and all stages of 
the key processing within your APP context (HSM, Smartcard, KDF, ...)

This is an 100% pure go, stdlib only, no external dependencies,
please look at api.go for more details.

# DOCS

[pkg.go.dev/paepcke.de/signify](https://pkg.go.dev/paepcke.de/signify)

# CONTRIBUTION

Yes, Please! PRs Welcome! 
