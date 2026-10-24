# AGENTS.md

Guidance for AI agents working in this repository.

## Project

`paepcke.de/signify` — a pure-Go, stdlib-only library (zero external dependencies, no `go.sum`) that creates and verifies OpenBSD signify / minisign compatible Ed25519 signatures.

**Design invariant:** OpenBSD signify's private-key bcrypt/pbkdf passphrase handling is intentionally NOT implemented. Secret handling (HSM, smartcard, KDF, ...) belongs to the calling application. Do not "complete" this — it is the point of the fork, not a gap.

**Dependency invariant:** the README promises "100% pure go, stdlib only, no external dependencies". Never add a third-party dependency to `go.mod`.

Lineage: minimal fork of `github.com/ebfe/signify`. The original 2022 fork code is archived in `.attic/signifyseed.go.20221021` (reference only, not compiled).

## Layout

Flat, single package at the repo root — no `cmd/`, no `internal/`, no subpackages:

- `api.go` — the entire public API: size constants, `Signature`, `PublicKey`, `PrivateKey`, `Message` types and their methods (`Sign`, `Verify`, `Encode`, `Decode`, `GetPubKeyFile`, `GetSigFile`, `GeneratePKFromSeed`, `GetPublicKey`).
- `generic.go` — unexported helpers: base64 `enc`/`dec`, length-checked `sliceTo2/8/32/64` fixed-array converters, the `_algoEd25519` tag, and string constants for file framing.
- `.attic/` — archived historical code, not part of the build.
- `.github/workflows/` — `golang.yml` (build/vet), `codeql.yml` (CodeQL).

## Commands

```sh
make            # go build
go build ./...  # build
go test ./...   # test — no test files exist yet, passes trivially
go vet ./...    # lint (clean)
gofmt -w -s .   # format
make check      # gofmt -w -s . && staticcheck
make deps       # DESTRUCTIVE: deletes go.mod and re-runs go mod init/tidy — never run casually
```

Command gotchas:

- `staticcheck` (even current release 2026.2.1) cannot read Go 1.27 stdlib export data ("export data version 5 is greater than maximum supported version 4"), so `make check` fails on a Go 1.27+ toolchain. Use `go vet ./...` as the working linter until staticcheck catches up.
- CI (`golang.yml`) pins Go 1.21 while `go.mod` requires 1.27.1 — the matrix is stale; update it when touching CI.
- CodeQL (`codeql.yml`) triggers on branch `master`, but the default branch is `main` — it effectively only runs via its weekly cron schedule.
- The local `.crush/` directory is tooling state; it ignores itself via its own internal `.gitignore`, so it never lands in commits.

## Architecture / data flow

Every serializable type (`Signature`, `PublicKey`, `PrivateKey`, `Message`) carries a **dual representation**: `Base64 string` (wire format) and `Raw` (fixed-size arrays / bytes). The two are synchronized only by `Encode()` (Raw → Base64) or `Decode()` (Base64 → Raw). Methods that need `Raw` lazily decode when it is empty; reading `.Raw` fields on a value built from a base64 string requires a prior `Decode()`.

Wire layout (big-endian, `binary.Write` of the whole `Raw` struct): `PKAlgo [2]byte` (`'E','d'` = Ed25519) + `Fingerprint [8]byte` + payload (`PublicKeySize` for keys, `SignatureSize` for signatures). `Decode()` rejects wrong total lengths.

Key flows:

- `GeneratePKFromSeed(seedToken [SeedTokenSize]byte)`: 32-byte seed + 8-byte fingerprint → deterministic key via `ed25519.NewKeyFromSeed`; signs the fixed self-check message and **panics** on internal failure — the "do not recover!" comments are intentional.
- `pk.GetPublicKey()`: public key is the last `PublicKeySize` bytes of the private key (`PrivatePublicKeyOffset`), sharing the private key's fingerprint.
- `msg.Sign(pk)`: lazy-decode → derive public key → `ed25519.Sign` → set fingerprint/algo → self-verify → `Signature.Encode()`. Every sign is followed by a verify.
- `msg.Verify(pub)`: lazy-decode → signature fingerprint must match the message's public key fingerprint → `ed25519.Verify`.
- `GetPubKeyFile` / `GetSigFile` assemble OpenBSD-signify-compatible files: an `untrusted comment:` line followed by the base64 line, each `\n`-terminated.

## Conventions

- **Public API names are frozen**: non-idiomatic spellings (`FingerPrint`, `PKAlgo`, `GetPubKeyFile`, ...) are the published API of `paepcke.de/signify` — never rename them. Match the local style for anything new.
- Error style: `errors.New` with plain string concatenation and prefix tags (`sign failed:`, `verify failed:`, `internal:`). No `%w` wrapping anywhere — match this when adding errors.
- Doc comments are terse `// Name ...` stubs; sections are separated by banner comments (`//` / `// SECTION NAME` / `//`). Follow the existing minimal style instead of rewriting every stub.
- Byte slices convert to fixed-size arrays only through the `sliceToN` helpers (length-checked, error-returning) — no direct array conversions.
- File-framing literals live as `_lowercase` constants in `generic.go` (`_untrustedComment`, `_pubUT`, `_linefeed`, ...) — use them instead of inline literals.
- `switch { case cond: }` chains (not `if` ladders) are the dominant control style.

## Testing

No test files, framework, or fixtures exist (`go test ./...` → `[no test files]`). CONTRIBUTING.md welcomes PRs. New tests should be stdlib-only table-driven tests in the same package to respect the zero-dependency invariant.

## Release process

Observed pattern: work lands on `main`, releases are patch-bumped tags (`v0.1.N`) on a "prep release" commit, and commits plus tags are pushed to `origin` (`https://github.com/paepckehh/signify`). Current release line: `v0.1.x`.

Workflow for any completed change: run `gofmt -w -s .`, `go build ./...`, `go vet ./...`, `go test ./...`, update this file if behavior changed, then commit, bump the patch tag, and push the commit and the tag.
