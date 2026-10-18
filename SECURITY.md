# Security policy

## Reporting a vulnerability

Report vulnerabilities privately through GitHub Security Advisories:
https://github.com/Crdzbird/CipherBird/security/advisories/new

If that route is unavailable to you, email luisalfonsocb83@gmail.com with
"CipherBird security" in the subject. Do not open a public issue for a
suspected vulnerability.

Include the affected package and version (`cipherbird`, `cipherbird_dart` or
the C++ engine), the platform, a description of the issue and, when possible,
a minimal reproduction. Encrypting the report is welcome but not required.

## Response targets

- Acknowledgement within 3 business days.
- Initial assessment and severity within 7 business days.
- Fix or documented mitigation for critical and high findings within 30 days
  of acknowledgement, released as a new patch version of every affected
  package. Lower severities are scheduled into the next release.
- Credit in the release notes if you want it.

## Supported versions

| Package | Supported |
|---|---|
| cipherbird 1.1.x | yes, latest patch release |
| cipherbird_dart 1.1.x | yes, latest patch release |
| cryptolib_flutter 4.x (previous name) | no, upgrade to cipherbird |
| C++ engine on `main` | yes |

Fixes ship as new versions; released versions and their tags are never
rewritten.

## Scope

The engine, its C ABI and the published Dart packages are in scope. Findings
against vendored dependencies (libsodium, OpenSSL, liboqs, blst, BLAKE3,
libsecp256k1) should also be reported upstream; this project pins and
rebuilds them on each release.
