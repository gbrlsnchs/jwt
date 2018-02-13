# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

## [Unreleased]
### Added
- Support for "none" method.
- Tests for "none" method.

### Fixed
- Message in `ErrECDSASigLen`.

### Removed
- Comments from custom errors, since they are self-explanatory.

## [0.3.0] - 2018-02-13
### Changed
- Package structure.

### Removed
- Additional packages (`jwtcrypto` and `jwtutil`).

## [0.2.0] - 2018-02-06
### Added
- New test cases.
- Claims' timestamps validation.

### Changed
- Tests organization.
- Use `time.After` and `time.Before` for validating timestamps.
- `jwtcrypto/none.None` now implements `jwtcrypto.Signer`.

### Fixed
- Panicking when private or public keys are `nil`.

## 0.1.0 - 2018-02-06
### Added
- This changelog file.
- README file.
- MIT License.
- Travis CI configuration file.
- Makefile.
- Git ignore file.
- EditorConfig file.
- This package's source code, including examples and tests.
- Go dep files.

[Unreleased]: https://github.com/gbrlsnchs/jwt/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/gbrlsnchs/jwt/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/gbrlsnchs/jwt/compare/v0.1.0...v0.2.0
