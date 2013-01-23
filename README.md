# SSHKey

Generate private and public SSH keys (RSA and DSA supported) using pure Ruby.

	gem install sshkey

Tested on the following Rubies: MRI 1.8.7, 1.9.2, 1.9.3, 2.0.0, REE, JRuby (1.7.2 or later), Rubinius. Ruby must be compiled with OpenSSL support.

[![Build Status](https://secure.travis-ci.org/bensie/sshkey.png)](http://travis-ci.org/bensie/sshkey)

## Usage

### Generate a new key

When generating a new keypair the default key type is 2048-bit RSA, but you can supply the `type` (RSA or DSA) and `bits` in the options.
You can also (optionally) supply a `comment` or `passphrase`:

```ruby
k = SSHKey.generate

k = SSHKey.generate(:type => "DSA", :bits => 1024, :comment => "foo@bar.com", :passphrase => "foobar")
```

### Use your existing key

Return an SSHKey object from an existing RSA or DSA private key (provided as a string)

```ruby
k = SSHKey.new(File.read("~/.ssh/id_rsa"), :comment => "foo@bar.com")
```

### The SSHKey object

#### Private and public keys

Fetch the private and public keys as strings. Note that the `public_key` is the RSA or DSA public key, not an SSH public key.

```ruby
k.private_key
# => "-----BEGIN RSA PRIVATE KEY-----\nMIIEowI..."

k.public_key
# => "-----BEGIN RSA PUBLIC KEY-----\nMIIBCg..."
```

Fetch the SSH public key as a string.

```ruby
k.ssh_public_key
# => "ssh-rsa AAAAB3NzaC1yc2EA...."
```

#### Encryption

If a password is set when a key is generated or by setting the `password` accessor, you can
fetch the encrypted version of the private key.

```ruby
k.encrypted_private_key
# => "-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED..."
```

#### Comments

Keys can optionally have a comment that is shown as part of the public SSH key. Get or
set the key's comment with the `comment` accessor.

```ruby
k.comment
# => "foo@bar.com"

k.comment = "me@me.com"
# => "me@me.com"
```

#### Fingerprints

It is often helpful to use a fingerprint to visually or programmatically check if one key
matches another. Fetch either an MD5 (OpenSSH default) or SHA1 fingerprint of the SSH public key.

```ruby
k.md5_fingerprint
# => "2a:89:84:c9:29:05:d1:f8:49:79:1c:ba:73:99:eb:af"

k.sha1_fingerprint
# => "e4:f9:79:f2:fe:d6:be:2d:ef:2e:c2:fa:aa:f8:b0:17:34:fe:0d:c0"
```

#### Randomart

Generate OpenSSH compatible ASCII art fingerprints - see http://www.opensource.apple.com/source/OpenSSH/OpenSSH-175/openssh/key.c (key_fingerprint_randomart function)

```ruby
puts k.randomart
+--[ RSA 2048]----+
|o+ o..           |
|..+.o            |
| ooo             |
|.++. o           |
|+o+ +   S        |
|.. + o .         |
|  . + .          |
|   . .           |
|    Eo.          |
+-----------------+
```

#### Original OpenSSL key object

Return the original `OpenSSL::PKey::RSA` or `OpenSSL::PKey::DSA` object.

http://www.ruby-doc.org/stdlib/libdoc/openssl/rdoc/classes/OpenSSL/PKey/RSA.html
http://www.ruby-doc.org/stdlib/libdoc/openssl/rdoc/classes/OpenSSL/PKey/DSA.html

```ruby
k.key_object
# => -----BEGIN RSA PRIVATE KEY-----\nMIIEowI...
```

### Validate existing SSH public keys

Determine if a given SSH public key is valid. Very useful to test user input of public keys to make sure they accurately copy/pasted the key. Just pass the SSH public key as a string.

```ruby
SSHKey.valid_ssh_public_key? "ssh-rsa AAAAB3NzaC1yc2EA...."
# => true
```

## Copyright

Copyright (c) 2011-2013 James Miller
