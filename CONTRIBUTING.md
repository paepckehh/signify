# Contributing

Thanks for taking a look. Issues and pull requests are welcome.

## Ground rules

- **Stay dependency-free.** This library is stdlib-only by design; `go.mod`
  must never gain a third-party module.
- **Do not add private key encryption.** bcrypt/pbkdf passphrase handling is
  intentionally out of scope; secret handling belongs to the calling
  application.
- **Keep the public API stable.** Published names such as `FingerPrint`,
  `PKAlgo`, and `GetPubKeyFile` are frozen, even if they are not idiomatic Go.
- **Match the local style.** Plain `errors.New` with prefix tags, no `%w`
  wrapping, terse doc comments, and stdlib-only tests.

## Issues

- Bug reports, compatibility findings, and documentation fixes are welcome.
- Include the Go version, a minimal reproduction, and what you expected.

## Pull requests

1. Fork the repository and create a topic branch.
2. Make the change, including tests when behavior changes.
3. Run the checks:

   ```shell
   gofmt -w -s .
   go build ./...
   go vet ./...
   go test ./...
   ```

4. Add or update documentation if the public API or behavior changed.
5. Open the pull request with a short description of the problem and the fix.

## Testing

`signify_test.go` is stdlib-only (`testing` plus the package itself): no test
framework, no fixtures, no external modules. New tests should follow that
pattern, stay in the root package, and prefer table-driven cases where it
makes the intent clearer.

## Release process

Maintainers bump patch tags (`v0.1.N`) on a "prep release" commit after
formatting, building, vetting, and testing on `main`, then push the commit and
tag to `origin`.
