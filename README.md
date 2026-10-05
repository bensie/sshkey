# SSHKey

Generate and inspect SSH keys (RSA, ECDSA, and Ed25519, plus reading existing DSA keys) using pure Ruby, with no dependencies beyond Ruby's OpenSSL library.

## Requirements

Tested / supported on CRuby 3.3+ and JRuby 10+.

Version 4.x drops support for end-of-life Rubies and includes breaking API changes; see the [CHANGELOG](CHANGELOG.md) for upgrade notes. If you need to run on an older Ruby, use sshkey 3.x.

## Installation

    gem install sshkey

## Usage

### Generate a new key

Supply the key `type`: `"ed25519"` (the `ssh-keygen` default), `"ecdsa"`, or `"rsa"`. You can also supply `bits` (RSA: any size, defaults to 3072; ECDSA: 256, 384, or 521, defaults to 256), and optionally a `comment`, `passphrase`, or `directives`.

```ruby
k = SSHKey.generate(type: :ed25519)

k = SSHKey.generate(
  type:       "ecdsa",
  bits:       384,
  comment:    "foo@bar.com",
  passphrase: "foobar"
)

k = SSHKey.generate(type: "rsa")
```

Ed25519 private keys are written in OpenSSH format. To connect with them using [net-ssh](https://github.com/net-ssh/net-ssh), also install the `ed25519` gem. Ed25519 private keys can't be encrypted with a passphrase.

Generating DSA keys is not supported, as OpenSSH no longer supports them.

### Use your existing key

Return an SSHKey object from an existing RSA, DSA, ECDSA, or Ed25519 private key, provided as a string in PEM or OpenSSH format (`-----BEGIN OPENSSH PRIVATE KEY-----`, the `ssh-keygen` default), or as an `OpenSSL::PKey` object.

```ruby
f = File.read(File.expand_path("~/.ssh/id_ed25519"))
k = SSHKey.new(f, comment: "foo@bar.com")

k = SSHKey.new(File.read("encrypted.pem"), passphrase: "foobar")
```

When loading an OpenSSH format key, the comment stored in the key is used unless you pass a `comment`.

Passphrase-protected OpenSSH format keys are not supported, because they are encrypted with bcrypt_pbkdf, which OpenSSL does not provide. Remove the passphrase with `ssh-keygen -p -N "" -f /path/to/key`, or convert an RSA or ECDSA key to an encrypted PEM key with `ssh-keygen -p -m PEM -f /path/to/key`.

### The SSHKey object

#### Private and public keys

Fetch the private and public keys as strings. Note that the `public_key` is the RSA, DSA, ECDSA, or Ed25519 public key, not an SSH public key.

RSA, DSA, and ECDSA private keys are returned in PEM format. Ed25519 private keys are returned in OpenSSH format, since OpenSSH can't read Ed25519 keys in PEM format.

```ruby
k.private_key
# => "-----BEGIN RSA PRIVATE KEY-----\nMIIEoAIBAAKCAQEAvR7l72CT7UBP6P+02Iut8gKKbKyekz/pQxnckPp1VafuaIwC\nMvYfP4ffVJTcY5IhU9mISNxZf6YDQ0TuD1aOrZYG9wsIgGY0nXhOUZxe/Q5I+V7D\nOI/hSzKF7W0cNCvaJPUSo8+soCLNSQ5mjnV3sRZ6uJwGFN30i1GulqHHKkx3vGxb\niaAL9YG58dPSbPGHFTA/epqUyd1fzCuWHyL9dHW7aw4RroNyEtVdiftAQfaK20I2\nueeDfuEtCPaxQYFQqbz5kKnXQx3fwHRpC7/84xHxsrY576evGxHw4p5EJD37scNN\ncneTG3Ly79/VVSAlrSm6ltutx0+S70scCqK0ewIDAQABAoH/MjwC15LPuDVdBIbn\ngp2XlrEWE8fGV1ainzA/ZkMg55+ztBF8hAzcQAPXTqA76jbmo18k1DWzkDSIqVWl\n5m0XeQRg1T4ZBAIh97H9G7BtispAl/yT3nJZZaAF8wsIctMzHp36VYjUUbTs0nsA\nwtZw9JkEAAVxmBlc26TWuyw9uv4fYXuR+uOsWH8jTTVPvxM9FaCCdK+dOMnswm7Y\nlOAlJj5dANkB2KPwIeE461ThyMo9GHEjpsvciMhKLuBoTSucNkhdgapAmYTSI+/1\nf1cA/KEdCMs9ANr1HFujeS01+N1Xrw/yW6EazaDN1oFHCVORtlB295Eac0Wq6y/P\npf1BAoGBAPIw4HQWsolU3f4FdIvc2POAcSJDRgt++I9Qt/QXq1SJ2dGKIveFiJgo\nZjCfHQFVZ8xl64cLzQ1WagZA1JBbbk9g5RxHDxRv7q+Kn3ogugDo9GUoQvpuuAU6\nXHoR/mLinDorJUnttL3U49xTMfrrut4qkUg+daBVptPtylpio6EDAoGBAMfnYq08\nfd/cPEQ2XPeswgtzXsKNLqA6UXBM7ZauKaFLByjy8peMMF6JPOYlBKQif5k+Egmu\nWIe8oTm8Nn5Ymt32bEd+MkHUC7kFzQeiXnM3u0oKzJMXLAvjSTs296g50YM5zJTC\nl64ACQmQOLZ9tdKorl52ZcmdbBEcZ2uwRvkpAoGAKhs5SrWPgLTSi5FjO9W/mkYg\nZTaQ/PqsOC5ubO+Yh/AXgIiln6cFon6Tlax0HIE+tJibpDT3B3SYplGrIxXiTcao\nzovEIWd8deSB6Xe7HuFhbBzd2DBbqf0FiuuJ8KM5ShuqNfovzDkxDGMic198c5eu\n/oJtbNy3Tm0vGxu/GwUCgYAgmRPXShkAq0pMmUzZups+AMdAFIO47ymelXzc6HOz\ncKevPsbefabZk6mRohG6rkF+fMe2Om8HW3QzFQUR32MJtQh9NA//+hMbTd3cU9bx\nFPJ+pXostkehfKPReyoxjZQjwQYicAUKA8l1fMYyxBclTgp5Lvd0RC5+L9KRlgJM\n2QKBgGVIWRNVpGg38dDqdq/4ue1BoTFhqoMGi6WQm3xa+NH+lyJGacdUhGRz8PxN\nhVKpIj8ljg2Rq/CA9qSgL/Z9rhn8QUMWULuAroCp0S2pMBtZ2RB+Mg2FdVFR9/Ft\nfG7co6mKUGkFPtr48EMfeKY88BRsp3yGOsROGdDsCHItjOVH\n-----END RSA PRIVATE KEY-----\n"

k.public_key
# => "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvR7l72CT7UBP6P+02Iut\n8gKKbKyekz/pQxnckPp1VafuaIwCMvYfP4ffVJTcY5IhU9mISNxZf6YDQ0TuD1aO\nrZYG9wsIgGY0nXhOUZxe/Q5I+V7DOI/hSzKF7W0cNCvaJPUSo8+soCLNSQ5mjnV3\nsRZ6uJwGFN30i1GulqHHKkx3vGxbiaAL9YG58dPSbPGHFTA/epqUyd1fzCuWHyL9\ndHW7aw4RroNyEtVdiftAQfaK20I2ueeDfuEtCPaxQYFQqbz5kKnXQx3fwHRpC7/8\n4xHxsrY576evGxHw4p5EJD37scNNcneTG3Ly79/VVSAlrSm6ltutx0+S70scCqK0\newIDAQAB\n-----END PUBLIC KEY-----\n"
```

Fetch the SSH public key as a string.

```ruby
k.ssh_public_key
# => "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC9HuXvYJPtQE/o/7TYi63yAopsrJ6TP+lDGdyQ+nVVp+5ojAIy9h8/h99UlNxjkiFT2YhI3Fl/pgNDRO4PVo6tlgb3CwiAZjSdeE5RnF79Dkj5XsM4j+FLMoXtbRw0K9ok9RKjz6ygIs1JDmaOdXexFnq4nAYU3fSLUa6WoccqTHe8bFuJoAv1gbnx09Js8YcVMD96mpTJ3V/MK5YfIv10dbtrDhGug3IS1V2J+0BB9orbQja554N+4S0I9rFBgVCpvPmQqddDHd/AdGkLv/zjEfGytjnvp68bEfDinkQkPfuxw01yd5MbcvLv39VVICWtKbqW263HT5LvSxwKorR7"
```

Fetch the private key in OpenSSH format, as written by `ssh-keygen`, for any key type.

```ruby
k.openssh_private_key
# => "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW..."
```

#### Encryption

If a passphrase is set when a key is generated or by setting the `passphrase` accessor, you can
fetch the encrypted version of the private key. It's returned in PKCS#8 PEM format (AES-256-CBC with a PBKDF2-derived key), which OpenSSH reads. Encrypting Ed25519 keys is not supported.

```ruby
k.passphrase = "foo"
# => "foo"

k.encrypted_private_key
# => "-----BEGIN ENCRYPTED PRIVATE KEY-----\nMIIFNTBfBgkqhkiG9w0BBQ0wUjAxBgkqhkiG9w0BBQwwJAQQ..."
```

#### Comments

Keys can optionally have a comment that is shown as part of the public SSH key. Get or
set the key's comment with the `comment` accessor.

```ruby
k.comment
# => ""

k.comment = "me@me.com"
# => "me@me.com"

k.ssh_public_key
# => "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC9HuXvYJPtQE/o/7TYi63yAopsrJ6TP+lDGdyQ+nVVp+5ojAIy9h8/h99UlNxjkiFT2YhI3Fl/pgNDRO4PVo6tlgb3CwiAZjSdeE5RnF79Dkj5XsM4j+FLMoXtbRw0K9ok9RKjz6ygIs1JDmaOdXexFnq4nAYU3fSLUa6WoccqTHe8bFuJoAv1gbnx09Js8YcVMD96mpTJ3V/MK5YfIv10dbtrDhGug3IS1V2J+0BB9orbQja554N+4S0I9rFBgVCpvPmQqddDHd/AdGkLv/zjEfGytjnvp68bEfDinkQkPfuxw01yd5MbcvLv39VVICWtKbqW263HT5LvSxwKorR7 me@me.com"

k.ssh2_public_key
# => "---- BEGIN SSH2 PUBLIC KEY ----\nComment: me@me.com\nAAAAB3NzaC1yc2EAAAADAQABAAABAQC9HuXvYJPtQE/o/7TYi63yAopsrJ6TP+lDGdyQ+n\nVVp+5ojAIy9h8/h99UlNxjkiFT2YhI3Fl/pgNDRO4PVo6tlgb3CwiAZjSdeE5RnF79Dkj5\nXsM4j+FLMoXtbRw0K9ok9RKjz6ygIs1JDmaOdXexFnq4nAYU3fSLUa6WoccqTHe8bFuJoA\nv1gbnx09Js8YcVMD96mpTJ3V/MK5YfIv10dbtrDhGug3IS1V2J+0BB9orbQja554N+4S0I\n9rFBgVCpvPmQqddDHd/AdGkLv/zjEfGytjnvp68bEfDinkQkPfuxw01yd5MbcvLv39VVIC\nWtKbqW263HT5LvSxwKorR7\n---- END SSH2 PUBLIC KEY ----"
```

#### Bit length

Determine the strength of the key in bits as an integer.

```ruby
k.bits
# => 2048
```

#### Fingerprints

It is often helpful to use a fingerprint to visually or programmatically check if one key
matches another. Fetch an MD5, SHA1, or SHA256 fingerprint of the SSH public key. `sha256_fingerprint`
matches the default `ssh-keygen -l` output (without the `SHA256:` prefix).

```ruby
k.md5_fingerprint
# => "04:1b:d4:18:df:87:60:94:8c:83:8a:7b:5a:35:59:3d"

k.sha1_fingerprint
# => "e5:c2:43:9e:e4:0c:0c:47:82:7a:3b:e9:61:13:bd:9c:43:eb:4c:b7"

k.sha256_fingerprint
# => "x1GEnx1SRY/QwxjMAoyO6mhQlaBedDHtYLEmfeUXy3o"
```

#### SSHFP records

Generate [SSHFP](https://www.rfc-editor.org/rfc/rfc4255) DNS records for a host key.

```ruby
puts k.sshfp("example.com")
example.com IN SSHFP 1 1 e5c2439ee40c0c47827a3be96113bd9c43eb4cb7
example.com IN SSHFP 1 2 c751849f1d52458fd0c318cc028c8eea685095a05e7431ed60b1267de517cb7a
```

#### Public Key Directives

Add optional directives prefixed to the public key that will be enforced when a key is authenticated.

Accepts a string or an array of strings.

```ruby
k.directives = "no-pty"
# => ["no-pty"]

k.directives = [
  "no-port-forwarding",
  "no-X11-forwarding",
  "no-agent-forwarding",
  "no-pty",
  "command='/home/user/bin/authprogs'"
]
# => ["no-port-forwarding", "no-X11-forwarding", "no-agent-forwarding", "no-pty", "command='/home/user/bin/authprogs'"]

k.ssh_public_key
# => "no-port-forwarding,no-X11-forwarding,no-agent-forwarding,no-pty,command='/home/user/bin/authprogs' ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC9HuXvYJPtQE/o/7TYi63yAopsrJ6TP+lDGdyQ+nVVp+5ojAIy9h8/h99UlNxjkiFT2YhI3Fl/pgNDRO4PVo6tlgb3CwiAZjSdeE5RnF79Dkj5XsM4j+FLMoXtbRw0K9ok9RKjz6ygIs1JDmaOdXexFnq4nAYU3fSLUa6WoccqTHe8bFuJoAv1gbnx09Js8YcVMD96mpTJ3V/MK5YfIv10dbtrDhGug3IS1V2J+0BB9orbQja554N+4S0I9rFBgVCpvPmQqddDHd/AdGkLv/zjEfGytjnvp68bEfDinkQkPfuxw01yd5MbcvLv39VVICWtKbqW263HT5LvSxwKorR7"
```

#### Randomart

Generate ASCII art fingerprints, matching `ssh-keygen -lv`. The digest defaults to SHA256; `"MD5"`, `"SHA384"`, and `"SHA512"` are also supported.

```ruby
puts k.randomart
+---[RSA 2048]----+
|  .o *+o.o *=*.oo|
| .. =o+.+ +.B.=..|
|.  +.*o. ..* +.o.|
|. o + o. .o.o .  |
| o .    S.oE     |
|. .      ..      |
|.o               |
|...              |
|.                |
+----[SHA256]-----+

puts k.randomart("MD5")
```

#### Original OpenSSL key object

Return the original [OpenSSL::PKey::RSA](https://ruby-doc.org/3.2.2/exts/openssl/OpenSSL/PKey/RSA.html) or [OpenSSL::PKey::DSA](https://ruby-doc.org/3.2.2/exts/openssl/OpenSSL/PKey/DSA.html) or [OpenSSL::PKey::EC](https://ruby-doc.org/3.2.2/exts/openssl/OpenSSL/PKey/EC.html) object, or an [OpenSSL::PKey::PKey](https://ruby-doc.org/3.2.2/exts/openssl/OpenSSL/PKey/PKey.html) for Ed25519 keys.

```ruby
k.key_object
# => -----BEGIN RSA PRIVATE KEY-----\nMIIEowI...
```

### Existing SSH public keys

#### Validation

Determine if a given SSH public key is valid. Very useful to test user input of public keys to make sure they accurately copy/pasted the key. Just pass the SSH public key as a string. Returns false if the key is invalid.

```ruby
SSHKey.valid_ssh_public_key? "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC9HuXvYJPtQE/o/7TYi63yAopsrJ6TP+lDGdyQ+nVVp+5ojAIy9h8/h99UlNxjkiFT2YhI3Fl/pgNDRO4PVo6tlgb3CwiAZjSdeE5RnF79Dkj5XsM4j+FLMoXtbRw0K9ok9RKjz6ygIs1JDmaOdXexFnq4nAYU3fSLUa6WoccqTHe8bFuJoAv1gbnx09Js8YcVMD96mpTJ3V/MK5YfIv10dbtrDhGug3IS1V2J+0BB9orbQja554N+4S0I9rFBgVCpvPmQqddDHd/AdGkLv/zjEfGytjnvp68bEfDinkQkPfuxw01yd5MbcvLv39VVICWtKbqW263HT5LvSxwKorR7"
# => true
```

#### Bit length

Determine the strength of the key in bits as an integer. Returns `SSHKey::PublicKeyError` if bits cannot be determined.

```ruby
SSHKey.ssh_public_key_bits "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC9HuXvYJPtQE/o/7TYi63yAopsrJ6TP+lDGdyQ+nVVp+5ojAIy9h8/h99UlNxjkiFT2YhI3Fl/pgNDRO4PVo6tlgb3CwiAZjSdeE5RnF79Dkj5XsM4j+FLMoXtbRw0K9ok9RKjz6ygIs1JDmaOdXexFnq4nAYU3fSLUa6WoccqTHe8bFuJoAv1gbnx09Js8YcVMD96mpTJ3V/MK5YfIv10dbtrDhGug3IS1V2J+0BB9orbQja554N+4S0I9rFBgVCpvPmQqddDHd/AdGkLv/zjEfGytjnvp68bEfDinkQkPfuxw01yd5MbcvLv39VVICWtKbqW263HT5LvSxwKorR7"
# => 2048
```

#### Fingerprints

Fetch an MD5, SHA1, or SHA256 fingerprint of the SSH public key.
Returns `SSHKey::PublicKeyError` if a fingerprint cannot be determined.

```ruby
SSHKey.md5_fingerprint "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC9HuXvYJPtQE/o/7TYi63yAopsrJ6TP+lDGdyQ+nVVp+5ojAIy9h8/h99UlNxjkiFT2YhI3Fl/pgNDRO4PVo6tlgb3CwiAZjSdeE5RnF79Dkj5XsM4j+FLMoXtbRw0K9ok9RKjz6ygIs1JDmaOdXexFnq4nAYU3fSLUa6WoccqTHe8bFuJoAv1gbnx09Js8YcVMD96mpTJ3V/MK5YfIv10dbtrDhGug3IS1V2J+0BB9orbQja554N+4S0I9rFBgVCpvPmQqddDHd/AdGkLv/zjEfGytjnvp68bEfDinkQkPfuxw01yd5MbcvLv39VVICWtKbqW263HT5LvSxwKorR7"
# => "04:1b:d4:18:df:87:60:94:8c:83:8a:7b:5a:35:59:3d"
SSHKey.sha1_fingerprint "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC9HuXvYJPtQE/o/7TYi63yAopsrJ6TP+lDGdyQ+nVVp+5ojAIy9h8/h99UlNxjkiFT2YhI3Fl/pgNDRO4PVo6tlgb3CwiAZjSdeE5RnF79Dkj5XsM4j+FLMoXtbRw0K9ok9RKjz6ygIs1JDmaOdXexFnq4nAYU3fSLUa6WoccqTHe8bFuJoAv1gbnx09Js8YcVMD96mpTJ3V/MK5YfIv10dbtrDhGug3IS1V2J+0BB9orbQja554N+4S0I9rFBgVCpvPmQqddDHd/AdGkLv/zjEfGytjnvp68bEfDinkQkPfuxw01yd5MbcvLv39VVICWtKbqW263HT5LvSxwKorR7"
# => "e5:c2:43:9e:e4:0c:0c:47:82:7a:3b:e9:61:13:bd:9c:43:eb:4c:b7"
SSHKey.sha256_fingerprint "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC9HuXvYJPtQE/o/7TYi63yAopsrJ6TP+lDGdyQ+nVVp+5ojAIy9h8/h99UlNxjkiFT2YhI3Fl/pgNDRO4PVo6tlgb3CwiAZjSdeE5RnF79Dkj5XsM4j+FLMoXtbRw0K9ok9RKjz6ygIs1JDmaOdXexFnq4nAYU3fSLUa6WoccqTHe8bFuJoAv1gbnx09Js8YcVMD96mpTJ3V/MK5YfIv10dbtrDhGug3IS1V2J+0BB9orbQja554N+4S0I9rFBgVCpvPmQqddDHd/AdGkLv/zjEfGytjnvp68bEfDinkQkPfuxw01yd5MbcvLv39VVICWtKbqW263HT5LvSxwKorR7"
# => "x1GEnx1SRY/QwxjMAoyO6mhQlaBedDHtYLEmfeUXy3o"
```

#### Convert to SSH2 Public Key

Convert an existing SSH Public Key into an SSH2 Public key. Returns `SSHKey::PublicKeyError` if a valid key cannot be generated.

```ruby
SSHKey.ssh_public_key_to_ssh2_public_key "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC9HuXvYJPtQE/o/7TYi63yAopsrJ6TP+lDGdyQ+nVVp+5ojAIy9h8/h99UlNxjkiFT2YhI3Fl/pgNDRO4PVo6tlgb3CwiAZjSdeE5RnF79Dkj5XsM4j+FLMoXtbRw0K9ok9RKjz6ygIs1JDmaOdXexFnq4nAYU3fSLUa6WoccqTHe8bFuJoAv1gbnx09Js8YcVMD96mpTJ3V/MK5YfIv10dbtrDhGug3IS1V2J+0BB9orbQja554N+4S0I9rFBgVCpvPmQqddDHd/AdGkLv/zjEfGytjnvp68bEfDinkQkPfuxw01yd5MbcvLv39VVICWtKbqW263HT5LvSxwKorR7 me@me.com"
# => "---- BEGIN SSH2 PUBLIC KEY ----\nComment: me@me.com\nAAAAB3NzaC1yc2EAAAADAQABAAABAQC9HuXvYJPtQE/o/7TYi63yAopsrJ6TP+lDGdyQ+n\nVVp+5ojAIy9h8/h99UlNxjkiFT2YhI3Fl/pgNDRO4PVo6tlgb3CwiAZjSdeE5RnF79Dkj5\nXsM4j+FLMoXtbRw0K9ok9RKjz6ygIs1JDmaOdXexFnq4nAYU3fSLUa6WoccqTHe8bFuJoA\nv1gbnx09Js8YcVMD96mpTJ3V/MK5YfIv10dbtrDhGug3IS1V2J+0BB9orbQja554N+4S0I\n9rFBgVCpvPmQqddDHd/AdGkLv/zjEfGytjnvp68bEfDinkQkPfuxw01yd5MbcvLv39VVIC\nWtKbqW263HT5LvSxwKorR7\n---- END SSH2 PUBLIC KEY ----"
```

### Errors

All errors raised by SSHKey inherit from `SSHKey::Error`:

* `SSHKey::PrivateKeyError` - a private key could not be read (malformed, or an incorrect or missing passphrase)
* `SSHKey::PublicKeyError` - an SSH public key could not be parsed
* `SSHKey::UnsupportedError` - the key or operation is not supported (e.g. Ed448 keys, passphrase-protected OpenSSH format keys)

Invalid arguments, such as an unknown key type or bit length, raise `ArgumentError`.

## Copyright

Copyright (c) 2011-2026 James Miller
