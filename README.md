<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/hero-dark.svg">
  <source media="(prefers-color-scheme: light)" srcset="docs/hero-light.svg">
  <img src="docs/hero-light.svg" alt="signify: pure Go Ed25519 signatures compatible with OpenBSD signify and minisign" width="100%">
</picture>

# 🔏 signify

**Ed25519 signatures. OpenBSD compatible. Zero dependencies.**

Create and verify OpenBSD [signify](https://man.openbsd.org/signify) /
[minisign](https://jedisct1.github.io/minisign/) compatible Ed25519 signatures
from pure Go, while private key handling stays exactly where it belongs: in
*your* application.

[![Go Reference](https://pkg.go.dev/badge/paepcke.de/signify.svg)](https://pkg.go.dev/paepcke.de/signify)
[![Go Report Card](https://goreportcard.com/badge/paepcke.de/signify)](https://goreportcard.com/report/paepcke.de/signify)
[![Go Build](https://github.com/paepckehh/signify/actions/workflows/golang.yml/badge.svg)](https://github.com/paepckehh/signify/actions/workflows/golang.yml)
[![Go Version](https://img.shields.io/github/go-mod/go-version/paepckehh/signify)](https://github.com/paepckehh/signify/blob/main/go.mod)
[![License](https://img.shields.io/github/license/paepckehh/signify)](https://github.com/paepckehh/signify/blob/main/LICENSE)
[![SemVer](https://img.shields.io/github/v/release/paepckehh/signify)](https://github.com/paepckehh/signify/releases/latest)

```shell
go get paepcke.de/signify
```

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/established-dark.svg">
  <source media="(prefers-color-scheme: light)" srcset="docs/established-light.svg">
  <img src="docs/established-light.svg" alt="signify: established in 2022, 4+ years of continuous development on GitHub, 31+ tagged releases" width="100%">
</picture>

</div>

---

## 💡 Why

OpenBSD `signify` protects private keys with bcrypt/pbkdf passphrases. That is
great for a CLI and wrong for an HSM, a smartcard, a cloud KMS, or an app that
already owns its key lifecycle.

`paepcke.de/signify` implements the **wire format and the Ed25519 operations**,
and deliberately stops there. You decide how the seed becomes a key, where it
lives, and how it is unlocked.

**No passphrase prompts. No key files written. No hidden state.** Just the
primitives, in one tiny package.

- 🪶 **100% pure Go, stdlib only** — no external modules, no `go.sum`, no CGO
- 🔐 **Secrets stay yours** — no built-in KDF, no prompts, no file or network I/O
- 🧩 **Tiny, flat API** — nine types (four high-level, three raw wire structs,
  two array aliases) and a handful of methods, all in [`api.go`](api.go)
- 🔁 **Dual representation** — every key, signature, and message has a `Raw`
  binary form and a base64 wire form
- 🧾 **OpenBSD file framing** — `untrusted comment:` lines via `GetPubKeyFile`
  and `GetSigFile`
- 🌱 **Deterministic key generation** — reproduce keys from a 40-byte seed token
  via `GeneratePKFromSeed`
- ✅ **Signed, then self-verified** — every `Sign` verifies its own output before
  returning
- 🛡 **Strict by default** — wrong sizes, unknown algorithms, missing keys, and
  fingerprint mismatches are errors, never silent rejections
- 📦 **Library-first** — no CLI, no globals, no `init()` magic

## 🚀 Install

**Go** (any platform with a Go toolchain):

```shell
go get paepcke.de/signify
```

Requires Go 1.27.2 or newer (`go.mod` declares `go 1.27.2`).

**Browse the API locally:**

```shell
go doc paepcke.de/signify
```

## 🎬 Showtime

The whole loop: seed in, key out, sign, verify.

```go
package main

import (
	"fmt"
	"log"

	"paepcke.de/signify"
)

func main() {
	// 32 bytes of seed + 8 bytes of fingerprint, e.g. from your KMS or HSM.
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

	if err := pub.Encode(); err != nil {
		log.Fatal(err)
	}
	fmt.Println("public key:", pub.Base64)
	fmt.Println("signature :", msg.Signature.Base64)
	fmt.Println("verified  :", ok)
}
```

```text
public key: RWRkZW1vLWtleSO8VJEsHm6SxKhoJchn4n/9xVW/+9QkTxeiar//7pZd
signature : RWRkZW1vLWtleTQtIzJIg4IKpcWbsokOMHPCSiO7IsHKfhNnKZoJANIFTZme16u30UUYk+43h8BMRGsYN/lqTGcm7yeTuZTs1AU=
verified  : true
```

The key ID is literally `demo-key` here because it was copied from the seed
token into the fingerprint field. In production, use a random or KMS-managed
fingerprint.

### Verify data you already have

`Verify` lazily decodes the message, the signature, and the public key from
their base64 forms. The signature fingerprint must match the public key
fingerprint, and then Ed25519 does the rest. `Raw` fields take precedence; a
`Base64` field is decoded only when its `Raw` form is still empty.

```go
msg := &signify.Message{
	Raw:       payload,
	Signature: signify.Signature{Base64: signatureLine},
}

ok, err := msg.Verify(signify.PublicKey{Base64: publicKeyLine})
```

### Produce OpenBSD-style files

```go
sigFile, err := msg.GetSigFile(pk)
pubFile, err := pk.GetPubKeyFile("release signing key")
```

`GetSigFile` signs the message (again) and returns an `untrusted comment:` line
using `msg.UntrustedComment`, followed by the base64 signature. A single space
is inserted after the colon, and comments that already start with one are left
unchanged, so OpenBSD's exact `untrusted comment: ` prefix is always present.
`GetPubKeyFile` accepts a comment and returns the `signify public key` header
followed by the base64 public key. Both keys expose it:

```go
pub := pk.GetPublicKey()
pubFile, err := pub.GetPubKeyFile("release signing key")
```

## 🧩 API at a glance

Full reference: [pkg.go.dev/paepcke.de/signify](https://pkg.go.dev/paepcke.de/signify).

### Constants

| Constant | Value | Meaning |
| :--- | ---: | :--- |
| `SeedSize` | 32 | Ed25519 seed length |
| `SeedTokenSize` | 40 | `SeedSize` + `FingerPrintSize` |
| `FingerPrintSize` | 8 | key ID embedded in every wire blob |
| `KeyAlgoSize` | 2 | algorithm tag length (`"Ed"`) |
| `PrivateKeySize` | 64 | Ed25519 private key length |
| `PublicKeySize` | 32 | Ed25519 public key length |
| `SignatureSize` | 64 | Ed25519 signature length |
| `PrivatePublicKeyOffset` | 32 | offset of the public key inside the private key |

### Types

| Type | Purpose |
| :--- | :--- |
| `Signature` | base64 + raw Ed25519 signature (`RawSignature`) |
| `PublicKey` | base64 + raw public key (`RawPublicKey`) |
| `PrivateKey` | base64 + raw private key (`RawPrivateKey`) |
| `Message` | payload, untrusted comment, signature, public key |
| `KeyAlgo` / `FingerPrint` | wire tag and key ID array types |
| `RawSignature` / `RawPublicKey` / `RawPrivateKey` | fixed-size wire structs |

### Functions and methods

| Symbol | Purpose |
| :--- | :--- |
| `NewSignature`, `NewPublicKey`, `NewPrivateKey`, `NewMessage` | constructors pre-set to the Ed25519 algorithm tag |
| `GeneratePKFromSeed` | deterministic key from a `SeedTokenSize` seed token |
| `PrivateKey.GetPublicKey` | derive the matching public key |
| `PrivateKey.GetPubKeyFile` / `PublicKey.GetPubKeyFile` | OpenBSD public key file framing |
| `Message.Sign` | sign raw or base64 message data |
| `Message.Verify` | verify with fingerprint and Ed25519 checks |
| `Message.GetSigFile` | sign and frame an OpenBSD signature file |
| `Encode` / `Decode` | move between `Raw` and base64 wire forms on all wire types |

Encoding and decoding works on `PublicKey`, `PrivateKey`, `Signature`, and
`Message`:

```go
if err := pk.Encode(); err != nil { /* Raw  -> Base64 */ }
if err := pk.Decode(); err != nil { /* Base64 -> Raw, size checked */ }
```

`Message.Encode` rejects a nil or zero-length payload rather than producing an
empty wire string that `Decode` would refuse. Sign and verify empty payloads by
setting `Message.Raw` directly.

`Sign` replaces any previous signature with a fresh one, stores the derived
public key in `msg.PublicKey`, and leaves the encoded signature in
`msg.Signature.Base64`. `PublicKey.GetPubKeyFile` always re-encodes `Raw`, so a
stale `Base64` field cannot leak into the file; a public key supplied only as
base64 is decoded and size-checked first. Both public key file paths reject an
unknown algorithm tag instead of writing a file that could never verify.

## 🔍 Wire format

```text
public key : "Ed" | fingerprint[8] | ed25519 public key[32]   = 42 bytes
private key: "Ed" | fingerprint[8] | ed25519 private key[64]  = 74 bytes
signature  : "Ed" | fingerprint[8] | ed25519 signature[64]    = 74 bytes
```

All multi-byte fields are written big-endian (`encoding/binary`), and the
textual form is standard base64 (`base64.StdEncoding`). Decoders reject any blob
whose length does not match the exact wire size for its type.

Files use the OpenBSD convention, every line `\n`-terminated:

```text
untrusted comment: signify public key <your comment>
<base64 public key>
```

```text
untrusted comment: <your comment>
<base64 signature>
```

## 🛡 Security model

- **You own the secret.** This library never derives an encryption key from a
  passphrase, never writes keys to disk, and never prompts. HSM, smartcard, KDF,
  sealing, and rotation are the caller's job.
- **A key is only as good as its seed.** `GeneratePKFromSeed` is deterministic
  on purpose; use it only when reproducibility is the requirement.
- **Never log `Raw` key material.** `Base64` contains the full secret for a
  private key.
- **Verification is strict.** Wrong sizes, unknown algorithms, missing keys, and
  fingerprint mismatches are errors, never silent rejections.
- **No external dependencies** means a smaller supply chain, not a weaker
  algorithm: signing and verification use `crypto/ed25519` from the standard
  library.

`GeneratePKFromSeed` performs an internal sign/verify self-check and **panics**
if it fails. That is intentional and unrecoverable: a broken Ed25519
implementation must not hand out keys.

Report vulnerabilities to `alert.git (/AT/) paepcke.de` — see
[SECURITY.md](SECURITY.md).

## 🤝 Compatibility

| Surface | Status |
| :--- | :--- |
| OpenBSD `signify` Ed25519 public keys, signatures, and `untrusted comment:` framing | ✅ supported |
| `minisign` Ed25519 public key and signature wire layout (`"Ed"` tag + 8-byte key ID) | ✅ supported |
| `minisign` prehashed signatures, trusted comments, global signatures | ❌ not implemented |
| bcrypt/pbkdf-encrypted private keys | ❌ intentionally out of scope |

The last point is the reason this fork exists. If you need the standard
passphrase-protected private key format, use OpenBSD `signify` directly.

## 🧪 Development

```shell
make            # go build
make test       # go test ./...
make check      # gofmt -w -s . && go vet ./...
```

Or directly:

```shell
gofmt -w -s .
go build ./...
go vet ./...
go test ./...
go test -cover ./...
```

The test suite is stdlib-only and table-driven where it helps, covering
deterministic key generation, constructor defaults, sign/verify round trips,
base64 wire forms, a pinned wire-format vector, file framing and comment
handling, re-signing, malformed input, tamper rejection, and invalid sizes.

`make deps` is destructive: it deletes `go.mod` and re-initializes the module.
Do not run it casually.

## 📚 Docs & project

- API reference: [pkg.go.dev/paepcke.de/signify](https://pkg.go.dev/paepcke.de/signify)
- Source: [github.com/paepckehh/signify](https://github.com/paepckehh/signify)
- Releases: [github.com/paepckehh/signify/releases](https://github.com/paepckehh/signify/releases)
- Hero artwork: [dark](docs/hero-dark.svg) / [light](docs/hero-light.svg) —
  dependency-free SVG, theme-aware `<picture>`
- Established banner: [dark](docs/established-dark.svg) /
  [light](docs/established-light.svg) — 2022 to today, 31+ tagged releases
  (theme-aware `<picture>`)
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
