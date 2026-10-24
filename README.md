<div align="center">

# 🔏 signify

**Ed25519 signatures. OpenBSD compatible. Zero dependencies.**

Create and verify OpenBSD [signify](https://man.openbsd.org/signify) /
[minisign](https://jedisct1.github.io/minisign/) compatible signatures from
pure Go — with the private key handling left exactly where it belongs: in
*your* application.

[![Go Reference](https://pkg.go.dev/badge/paepcke.de/signify.svg)](https://pkg.go.dev/paepcke.de/signify)
[![Go Report Card](https://goreportcard.com/badge/paepcke.de/signify)](https://goreportcard.com/report/paepcke.de/signify)
[![Go Build](https://github.com/paepckehh/signify/actions/workflows/golang.yml/badge.svg)](https://github.com/paepckehh/signify/actions/workflows/golang.yml)
[![License](https://img.shields.io/github/license/paepckehh/signify)](https://github.com/paepckehh/signify/blob/main/LICENSE)
[![SemVer](https://img.shields.io/github/v/release/paepckehh/signify)](https://github.com/paepckehh/signify/releases/latest)

</div>

---

## 💡 Why

OpenBSD `signify` protects private keys with bcrypt/pbkdf passphrases. That is
great for a CLI and wrong for an HSM, a smartcard, a cloud KMS, or an app that
already owns its key lifecycle.

`paepcke.de/signify` implements the **wire format and the Ed25519 operations**,
and deliberately stops there. You decide how the seed becomes a key, where it
lives, and how it is unlocked.

- 🪶 **100% pure Go, stdlib only** — no external modules, no `go.sum`, no CGO
- 🔐 **Hardware-friendly by design** — no built-in password KDF, no secret copying outside your control
- 📦 **Tiny, flat API** — four types and a handful of methods, all in [`api.go`](api.go)
- 🔁 **Dual representation** — every key, signature, and message has a `Raw` form and a base64 wire form
- 🧾 **OpenBSD file framing** — `untrusted comment:` lines via `GetPubKeyFile` / `GetSigFile`
- 🌱 **Deterministic key generation** — reproduce keys from a 40-byte seed token via `GeneratePKFromSeed`
- ✅ **Signed, then self-verified** — every `Sign` verifies its own output before returning
- 🛡 **Explicit errors** — wrong sizes, unknown algorithms, and missing keys are never ignored

## 🚀 Install

```shell
go get paepcke.de/signify
```

Requires Go 1.27 or newer.

## 🎬 Quickstart

### Generate, sign, verify

```go
package main

import (
	"fmt"
	"log"

	"paepcke.de/signify"
)

func main() {
	// A seed token is 32 bytes of seed + 8 bytes of fingerprint.
	// In production the seed comes from your KMS, HSM, or secure RNG.
	var token [signify.SeedTokenSize]byte
	copy(token[:], "0123456789abcdef0123456789abcdef")
	copy(token[signify.SeedSize:], "demo-key")

	pk := signify.GeneratePKFromSeed(token)
	pub := pk.GetPublicKey()

	msg := &signify.Message{Raw: []byte("hello, world")}
	if err := msg.Sign(pk); err != nil {
		log.Fatal(err)
	}

	ok, err := msg.Verify(pub)
	if err != nil || !ok {
		log.Fatalf("verification failed: ok=%v err=%v", ok, err)
	}

	fmt.Println(msg.Signature.Base64)
}
```

### Produce OpenBSD-style files

```go
sigFile, err := msg.GetSigFile(pk)
pubFile, err := pk.GetPubKeyFile("release signing key")
```

`GetSigFile` returns an `untrusted comment:` line followed by the base64
signature. `GetPubKeyFile` does the same for the public key.

### Verify data you already have

```go
msg := &signify.Message{
	Raw:       payload,
	Signature: signify.Signature{Base64: signatureLine},
}

ok, err := msg.Verify(signify.PublicKey{Base64: publicKeyLine})
```

`Verify` lazily decodes the message, signature, and public key from their
base64 forms. The signature fingerprint must match the public key fingerprint,
and then Ed25519 does the rest.

## 🧩 API at a glance

| Type / method | Purpose |
| :--- | :--- |
| `Signature` | base64 + raw Ed25519 signature (`RawSignature`) |
| `PublicKey` | base64 + raw public key (`RawPublicKey`) |
| `PrivateKey` | base64 + raw private key (`RawPrivateKey`) |
| `Message` | payload, untrusted comment, signature, public key |
| `GeneratePKFromSeed` | deterministic key from a `SeedTokenSize` seed token |
| `PrivateKey.GetPublicKey` | derive the matching public key |
| `Message.Sign` | sign raw or base64 message data |
| `Message.Verify` | verify with fingerprint and Ed25519 checks |
| `Encode` / `Decode` | move between `Raw` and base64 wire forms |
| `GetPubKeyFile` / `GetSigFile` | OpenBSD signify compatible file framing |

Full reference: [pkg.go.dev/paepcke.de/signify](https://pkg.go.dev/paepcke.de/signify).

## 🔍 Wire format

```text
public key : "Ed" | fingerprint[8] | ed25519 public key[32]   = 42 bytes
private key: "Ed" | fingerprint[8] | ed25519 private key[64]  = 74 bytes
signature  : "Ed" | fingerprint[8] | ed25519 signature[64]    = 74 bytes
```

All integers are big-endian, all binary blobs are standard base64 in the
textual form. Files use the OpenBSD convention:

```text
untrusted comment: <anything you like>
<base64 payload>
```

## 🛡 Security model

- **You own the secret.** This library never derives an encryption key from a
  passphrase, never writes keys to disk, and never prompts. HSM, smartcard,
  KDF, sealing, and rotation are the caller's job.
- **A key is only as good as its seed.** `GeneratePKFromSeed` is deterministic
  on purpose; use it only when reproducibility is the requirement.
- **Never log `Raw` key material.** `Base64` contains the full secret for a
  private key.
- **Verification is strict.** Wrong sizes, unknown algorithms, missing keys,
  and fingerprint mismatches are errors, never silent rejections.
- **No external dependencies** means a smaller supply chain, not a weaker
  algorithm: signing and verification use `crypto/ed25519`.

Report vulnerabilities to `alert.git (/AT/) paepcke.de` — see
[SECURITY.md](SECURITY.md).

## 🤝 Compatibility

- ✅ OpenBSD `signify` Ed25519 public keys, signatures, and file framing
- ✅ `minisign`-style Ed25519 payloads
- ❌ bcrypt/pbkdf-encrypted private keys — *intentionally out of scope*

The last point is the reason this fork exists. If you need the standard
passphrase-protected private key format, use OpenBSD `signify` directly.

## 📚 Docs & project

- API reference: [pkg.go.dev/paepcke.de/signify](https://pkg.go.dev/paepcke.de/signify)
- Source: [github.com/paepckehh/signify](https://github.com/paepckehh/signify)
- Releases: [github.com/paepckehh/signify/releases](https://github.com/paepckehh/signify/releases)
- History: a minimal fork of [`github.com/ebfe/signify`](https://github.com/ebfe/signify)

## 🤝 Contributing

Yes, please! Issues and PRs are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md).

```shell
gofmt -w -s .
go build ./...
go vet ./...
go test ./...
```

## 🛡 License

[BSD 3-Clause License](LICENSE) — see [LICENSE](LICENSE) for details.

## 📃 Citation

```bibtex
@misc{signify,
  author = {Michael Paepcke},
  title = {signify: pure-Go OpenBSD signify / minisign compatible Ed25519 signatures},
  year = {2022},
  publisher = {GitHub},
  journal = {GitHub repository},
  howpublished = {\url{https://paepcke.de/signify}}
}
```
