// go: file crypto/internal/fips140/nistec/fiat/cast.go decls:
//
// Go: `import _ "crypto/internal/fips140/check"` and nothing
// else. The blank import exists to pull the FIPS 140-3
// integrity self-check into any binary that links fiat;
// goish has no such link-time hook, so the file carries no
// declarations here either.
