# OVERVIEW

This implementation does intentionally not satisfy the OpenBSD signify
private key bcrypt/pbkdf handling interface.

This implementation enables you to handle the secret and all stages of 
the key processing within your APP context, within a HSM, Smartcard, KDF ...

This is an 100% pure go, stdlib only, no external dependencies, please look at
api.go for more details.
