# AGENTS.md

Guidance for AI agents working in this repository.

## Project

`paepcke.de/signify` — a pure-Go, stdlib-only library (zero external dependencies, no `go.sum`) that creates and verifies OpenBSD signify / minisign compatible Ed25519 signatures.

**Design invariant:** OpenBSD signify's private-key bcrypt/pbkdf passphrase handling is intentionally NOT implemented. Secret handling (HSM, smartcard, KDF, ...) belongs to the calling application. Do not "complete" this — it is the point of the fork, not a gap.

**Dependency invariant:** the README promises "100% pure Go, stdlib only — no external modules, no `go.sum`, no CGO". Never add a third-party dependency to `go.mod`.

Lineage: minimal fork of `github.com/ebfe/signify`. The original 2022 fork code is archived in `.attic/signifyseed.go.20221021` (reference only, not compiled).

## Layout

Flat, single package at the repo root — no `cmd/`, no `internal/`, no subpackages:

- `api.go` — the entire public API: size constants, `Signature`, `PublicKey`, `PrivateKey`, `Message` types and their methods (`Sign`, `Verify`, `Encode`, `Decode`, `GetPubKeyFile`, `GetSigFile`, `GeneratePKFromSeed`, `GetPublicKey`).
- `generic.go` — unexported helpers: base64 `enc`/`dec`, wire `encodeRaw`/`decodeRaw`, the `_algoEd25519` tag, and string constants for file framing.
- `signify_test.go` — stdlib-only tests: deterministic key generation, constructor defaults, sign/verify round trips, base64 wire forms, a pinned wire-format vector, file framing, malformed input.
- `docs/` — dependency-free, theme-aware hero SVGs (`hero-light.svg`, `hero-dark.svg`), established banners (`established-light.svg`, `established-dark.svg`), terminal screenshots (`screenshot-demo.svg`, `screenshot-tests.svg`), and the stdlib-only renderer that generates them from real captured ANSI output (`render_ansi_svg.py`). README uses the hero and banners via `<picture>` blocks and the screenshots as plain images.
- `.attic/` — archived historical code, not part of the build.
- `.github/workflows/` — `golang.yml` (build/vet/test), `codeql.yml` (CodeQL).

## Commands

```sh
make            # go build
make test       # go test ./...
go build ./...  # build
go test ./...   # test suite (stdlib only)
go vet ./...    # lint (clean)
gofmt -w -s .   # format
make check      # gofmt -w -s . && go vet ./...
make deps       # DESTRUCTIVE: deletes go.mod and re-runs go mod init/tidy — never run casually
```

The module declares `go 1.27.2`; CI (`golang.yml`) tests `1.27.x` on linux, macOS, and Windows with `CGO_ENABLED=0`.

Command gotchas:

- `staticcheck` (even current release 2026.2.1) cannot read Go 1.27 stdlib export data ("export data version 5 is greater than maximum supported version 4"), so it was replaced by `go vet ./...` in `make check` and CI.
- The local `.crush/` directory is tooling state; it ignores itself via its own internal `.gitignore`, so it never lands in commits.

## Architecture / data flow

Every serializable type (`Signature`, `PublicKey`, `PrivateKey`, `Message`) carries a **dual representation**: `Base64 string` (wire format) and `Raw` (fixed-size arrays / bytes). The two are synchronized by `Encode()` (Raw → Base64) or `Decode()` (Base64 → Raw). `Sign`/`Verify`/`GetPubKeyFile` lazily decode when only the base64 form is present; reading `.Raw` fields on a value built from a base64 string requires a prior `Decode()`.

Wire layout (big-endian, `binary.Write`/`binary.Read` of the whole `Raw` struct): `PKAlgo [2]byte` (`'E','d'` = Ed25519) + `Fingerprint [8]byte` + payload (`PublicKeySize`/`PrivateKeySize` for keys, `SignatureSize` for signatures). `Decode()` rejects wrong total lengths.

Key flows:

- `GeneratePKFromSeed(seedToken [SeedTokenSize]byte)`: 32-byte seed + 8-byte fingerprint → deterministic key via `ed25519.NewKeyFromSeed`; signs the fixed self-check message and **panics** on internal failure — the "do not recover!" comments are intentional.
- `pk.GetPublicKey()`: public key is the last `PublicKeySize` bytes of the private key (`PrivatePublicKeyOffset`), sharing the private key's fingerprint.
- `msg.Sign(pk)`: lazy-decode key → derive public key → reset signature → `ed25519.Sign` → set fingerprint/algo → self-verify → `Signature.Encode()`. Every sign is followed by a verify.
- `msg.Verify(pub)`: lazy-decode public key, message and signature → signature fingerprint must match the **supplied** public key's fingerprint → `ed25519.Verify`.
- `GetPubKeyFile` / `GetSigFile` assemble OpenBSD-signify-compatible files: an `untrusted comment:` line followed by the base64 line, each `\n`-terminated. `GetSigFile` guarantees the `untrusted comment: ` prefix by inserting a space when the caller comment does not already start with one. `PublicKey.GetPubKeyFile` validates a base64-only key, always re-encodes `Raw` into the file, and both public key file paths reject a non-`Ed` algorithm tag.
- `enc` rejects zero-length input, so `Message.Encode` cannot emit an empty string that `Message.Decode` would then refuse.

## Conventions

- **Public API names are frozen**: non-idiomatic spellings (`FingerPrint`, `PKAlgo`, `GetPubKeyFile`, ...) are the published API of `paepcke.de/signify` — never rename them. Match the local style for anything new.
- Error style: `errors.New` with plain string concatenation and prefix tags (`sign failed:`, `verify failed:`, `internal:`). No `%w` wrapping anywhere — match this when adding errors.
- Doc comments are terse `// Name ...` stubs; sections are separated by banner comments (`//` / `// SECTION NAME` / `//`). Follow the existing minimal style instead of rewriting every stub.
- Byte slices convert to fixed-size arrays via `copy` or the shared `encodeRaw`/`decodeRaw` helpers — no direct slice-to-array conversions, no per-size converter functions.
- File-framing literals live as `_lowercase` constants in `generic.go` (`_untrustedComment`, `_pubUT`, `_linefeed`, ...) — use them instead of inline literals.
- `switch { case cond: }` chains (not `if` ladders) are the dominant control style.

## Testing

`signify_test.go` contains stdlib-only tests (no framework, no fixtures) covering deterministic key generation, constructor defaults, sign/verify round trips (including empty payloads and base64 messages), base64 wire forms, a pinned wire-format vector, file framing and comment normalization, stale-wire precedence, re-signing, tampered signatures, malformed input, and rejection of empty/invalid inputs. Keep new tests in the same package and dependency-free. Run `go test -cover ./...` to check coverage (currently above 94%).

## Release process

Observed pattern: work lands on `main`, releases are patch-bumped tags (`v0.1.N`) on a "prep release" commit, and commits plus tags are pushed to `origin` (`https://github.com/paepckehh/signify`). Current release line: `v0.1.x`.

Workflow for any completed change: run `gofmt -w -s .`, `go build ./...`, `go vet ./...`, `go test ./...`, update this file if behavior changed, then commit, bump the patch tag, and push the commit and the tag.
