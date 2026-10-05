# Changelog

## 4.0.0 (unreleased)

sshkey 4 is a modernization release. It requires a supported Ruby, adds Ed25519 and OpenSSH
private key support, has no runtime dependencies, and cleans up the API. Most applications that
call `SSHKey.new`, `#private_key`, `#ssh_public_key` and the fingerprint methods only need the changes listed under [Upgrading from 3.x](#upgrading-from-3x).

### Requirements

- Ruby 3.3 or newer, or JRuby 10 or newer.
- The `base64` gem is no longer a dependency. sshkey has no runtime dependencies.

### Added

- Ed25519 keys: `SSHKey.generate(type: "ed25519")`, loading existing keys, public keys,
  fingerprints, bit length, SSHFP records and randomart. (#41)
- Loading unencrypted OpenSSH format private keys (`-----BEGIN OPENSSH PRIVATE KEY-----`), the
  default output of `ssh-keygen`, for RSA, DSA, ECDSA and Ed25519. The comment stored in the key
  is used unless `comment:` is given. (#41)
- `#openssh_private_key` returns the private key in OpenSSH format.
- `SSHKey.new` accepts an `OpenSSL::PKey` object as well as a PEM or OpenSSH format string.
- `SSHKey.generate` accepts `directives:`, and a Symbol `type:` (e.g. `type: :ed25519`).
- ECDSA keys are fully supported on JRuby.
- An error hierarchy: `SSHKey::Error`, with `SSHKey::PrivateKeyError`, `SSHKey::PublicKeyError`
  and `SSHKey::UnsupportedError`.

### Changed

- `SSHKey.generate` requires a `type:` (it previously defaulted to RSA). Calling it without one
  raises `ArgumentError`. Choose `"ed25519"` to match `ssh-keygen`, or `"rsa"` for the previous
  behavior. This is required rather than defaulting to Ed25519, because switching key types
  silently can break code that uses the generated key: for example, net-ssh needs the `ed25519`
  gem to load Ed25519 keys, and Ed25519 private keys can't be passphrase-encrypted.
- `SSHKey.generate` and `SSHKey.new` take keyword arguments. Unknown options raise
  `ArgumentError` instead of being ignored.
- RSA keys are generated with 3072 bits by default (was 2048), matching `ssh-keygen`.
- `#encrypted_private_key` returns PKCS#8 PEM (`-----BEGIN ENCRYPTED PRIVATE KEY-----`) encrypted
  with AES-256-CBC and a PBKDF2-derived key, instead of traditional PEM encrypted with AES-128-CBC
  and a single MD5 iteration. OpenSSH and `SSHKey.new` read both formats.
- `#private_key` returns Ed25519 keys in OpenSSH format, since OpenSSH does not read Ed25519 keys
  in PEM format. RSA, DSA and ECDSA keys are still returned in PEM format.
- `#randomart` defaults to SHA256 (was MD5) and matches `ssh-keygen -lv` output exactly,
  including the `[SHA256]` footer. It accepts the digest name in any case.
- Errors:
  - A private key that can't be read raises `SSHKey::PrivateKeyError` (was an
    `OpenSSL::PKey::PKeyError` subclass).
  - Unsupported keys and operations raise `SSHKey::UnsupportedError`.
  - Invalid `generate` options and an unknown `randomart` digest raise `ArgumentError` (was
    `RuntimeError`).
  - `SSHKey::PublicKeyError` now inherits from `SSHKey::Error`.

### Removed

- Generating DSA keys. OpenSSH removed DSA support in version 10. Existing DSA keys can still be
  loaded, validated and fingerprinted.
- The `fingerprint` alias, on both `SSHKey` and instances. Use `md5_fingerprint` for the old
  behavior, or `sha256_fingerprint` to match `ssh-keygen`.
- The `rsa_private_key`, `dsa_private_key`, `rsa_public_key` and `dsa_public_key` aliases. Use
  `private_key` and `public_key`.
- `SSHKey.format_sshfp_record` (use `SSHKey.sshfp` or `#sshfp`) and the `SSH_CONVERSION` constant.
  The internal constants `SSHFP_TYPES`, `ECDSA_CURVES`, `VALID_BITS` and `SSH2_LINE_LENGTH` are
  now private. `SSH_TYPES` remains public.
- The `identifier` and `q` methods added to `OpenSSL::PKey::EC`, and the global
  `jruby_not_implemented` method.

### Fixed

- Loading an encrypted PEM key without a passphrase no longer prompts for one on the terminal.
  It raises `SSHKey::PrivateKeyError`.
- The class-level fingerprint and `sshfp` methods no longer treat a public key whose comment
  contains "PRIVATE" as a private key.
- The bit length of DSA public keys is measured from `p`, so it no longer occasionally
  reports 1016 for a 1024-bit key. Ed25519 public keys always report 256.
- `SSHKey.generate(type: "RSA")` with an uppercase type uses the right default size.
- `ssh_public_key_bits` raises `SSHKey::PublicKeyError` for truncated keys instead of `TypeError`.

### Upgrading from 3.x

- Pass a `type:` to `SSHKey.generate`. Use `type: "rsa"` for the previous default, or
  `type: "ed25519"` for the key type `ssh-keygen` now creates by default (if you connect with
  net-ssh, also install the `ed25519` gem).
- Pass options as keywords. Literal hashes already work (`SSHKey.generate(type: "rsa")`); a hash
  held in a variable needs a double splat: `SSHKey.generate(**options)`.
- Replace `fingerprint` with `md5_fingerprint` (same result) or `sha256_fingerprint`.
- Replace `rsa_private_key`/`dsa_private_key` with `private_key`, and
  `rsa_public_key`/`dsa_public_key` with `public_key`.
- Replace `rescue OpenSSL::PKey::PKeyError` (or `RSAError`, `DSAError`, `ECError`) around
  `SSHKey.new` with `rescue SSHKey::PrivateKeyError`, and `rescue RuntimeError` around
  `SSHKey.generate` with `rescue ArgumentError`.
- If you generate DSA keys, switch to Ed25519 or ECDSA.
- If you compare `randomart` output, pass `"MD5"` to keep the previous digest.
- Pass `bits: 2048` if you depend on the previous RSA default.

## Earlier versions

See the [GitHub history](https://github.com/bensie/sshkey/commits/main) for changes before 4.0.0.
