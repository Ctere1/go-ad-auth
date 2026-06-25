# Changelog

## v1.1.0

Security hardening and a correctness fix for sAMAccountName-based authentication, plus an
RFC/MS-ADTS-faithful refactor of username resolution.

### Fixed
- **sAMAccountName search no longer issues a `DOMAIN\user` value.** When
  `EnforceSamAccountNameSearch` was set, `AuthenticateExtended` searched
  `(sAMAccountName=DOMAIN\user)`, which never matches in Active Directory — the
  `sAMAccountName` attribute holds the bare login name only (MS-ADTS). The bind still uses the
  down-level logon name, but the search now uses the bare `sAMAccountName`.

### Added
- `Config.Resolve(username) (Identity, error)` — single source of truth that derives the bind
  identity and the search predicate (attribute + raw value) together, so they can never
  diverge.
- `Identity` type (`BindName`, `SearchAttribute`, `SearchValue`).
- `Config.Timeout` — optional dial/operation timeout; defaults to `DefaultTimeout` (60s) when
  unset, bounding both the TCP dial and subsequent LDAP operations.

### Changed
- TLS connections now pin `MinVersion` to TLS 1.2 (RFC 8996).
- Nested-group membership (`getGroups`) now uses Simple Paged Results (RFC 2696) instead of a
  hard 1000-entry size limit, so users in more than 1000 nested groups are no longer silently
  truncated.
- `UPN()` no longer trusts RFC 5322 display-name forms (e.g. `evil <a@b.com>`) as a UPN, and
  trims surrounding whitespace consistently.
- Password operations (`ModifyDNPassword`, `UpdatePassword`) fail fast over a cleartext
  (`SecurityNone`) connection before transmitting any password material.
- `SID.MarshalBinary` validates that `IdentifierAuthority` fits the 48-bit field (MS-DTYP).

### Removed (breaking)
- `Config.ExtractUserName` — replaced by `Config.Resolve(...).BindName`.
- `Config.SamAccountName` — its return value was the down-level logon name (`DOMAIN\user`),
  not the `sAMAccountName`. Use `Config.Resolve(...)`: `.BindName` for the down-level bind
  identity, `.SearchValue` for the bare `sAMAccountName`.

These two functions had no consumers in the supported authentication paths
(`Authenticate`, `AuthenticateExtended`), which continue to work unchanged.
