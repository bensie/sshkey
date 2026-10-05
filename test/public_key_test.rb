require_relative "test_helper"

class PublicKeyTest < Test::Unit::TestCase
  include Fixtures

  def test_ssh_public_key_validation
    expected1 = "ssh-rsa #{SSH_PUBLIC_KEY1} me@example.com"
    expected2 = "ssh-rsa #{SSH_PUBLIC_KEY2} me@example.com"
    expected3 = "ssh-dss #{SSH_PUBLIC_KEY3} me@example.com"
    expected4 = "ssh-rsa #{SSH_PUBLIC_KEY1}"
    expected5 = %(from="trusted.eng.cam.ac.uk",no-port-forwarding,no-pty ssh-rsa #{SSH_PUBLIC_KEY1})
    invalid1 = "ssh-rsa #{SSH_PUBLIC_KEY1}= me@example.com"
    invalid2 = "ssh-rsa #{SSH_PUBLIC_KEY2}= me@example.com"
    invalid3 = "ssh-dss #{SSH_PUBLIC_KEY3}= me@example.com"
    invalid4 = "ssh-rsa A#{SSH_PUBLIC_KEY1}"
    invalid5 = "ssh-rsa #{SSH_PUBLIC_KEY3} me@example.com"

    assert SSHKey.valid_ssh_public_key?(expected1)
    assert SSHKey.valid_ssh_public_key?(expected2)
    assert SSHKey.valid_ssh_public_key?(expected3)
    assert SSHKey.valid_ssh_public_key?(expected4)
    assert SSHKey.valid_ssh_public_key?(expected5)

    assert !SSHKey.valid_ssh_public_key?(invalid1)
    assert !SSHKey.valid_ssh_public_key?(invalid2)
    assert !SSHKey.valid_ssh_public_key?(invalid3)
    assert !SSHKey.valid_ssh_public_key?(invalid4)
    assert !SSHKey.valid_ssh_public_key?(invalid5)
  end

  def test_ssh_public_key_validation_elliptic
    assert SSHKey.valid_ssh_public_key?("ssh-ed25519 #{SSH_PUBLIC_KEY_ED25519} me@example.com")
    assert SSHKey.valid_ssh_public_key?("ssh-ed25519 #{SSH_PUBLIC_KEY_ED25519_0_BYTE} me@example.com")
    assert SSHKey.valid_ssh_public_key?("ecdsa-sha2-nistp256 #{SSH_PUBLIC_KEY_ECDSA_256}")
    assert SSHKey.valid_ssh_public_key?("ecdsa-sha2-nistp384 #{SSH_PUBLIC_KEY_ECDSA_384} me@example.com")
    assert SSHKey.valid_ssh_public_key?(%(from="trusted.eng.cam.ac.uk",no-port-forwarding,no-pty ecdsa-sha2-nistp521 #{SSH_PUBLIC_KEY_ECDSA_521} me@example.com))

    assert !SSHKey.valid_ssh_public_key?("ssh-ed25519 #{SSH_PUBLIC_KEY_ED25519}= me@example.com") # bad base64
    assert !SSHKey.valid_ssh_public_key?("ssh-ed25519 #{SSH_PUBLIC_KEY_ECDSA_384} me@example.com") # mismatched key format
    assert !SSHKey.valid_ssh_public_key?("ecdsa-sha2-nistp256 #{SSH_PUBLIC_KEY_ECDSA_384} me@example.com") # mismatched key format
    assert !SSHKey.valid_ssh_public_key?("ssh-ed25519 asdf me@example.com") # gibberish key data
    assert !SSHKey.valid_ssh_public_key?("ecdsa-sha2-nistp256 asdf me@example.com") # gibberish key data
  end

  def test_ssh_public_key_validation_with_newlines
    expected1 = "ssh-rsa #{SSH_PUBLIC_KEY1}\n"
    expected2 = "ssh-ed25519 #{SSH_PUBLIC_KEY_ED25519} me@example.com\n"
    invalid1 = "ssh-rsa #{SSH_PUBLIC_KEY1}\nme@example.com"
    invalid2 = "ssh-rsa #{SSH_PUBLIC_KEY1}\n me@example.com"
    invalid3 = "ssh-rsa #{SSH_PUBLIC_KEY1} \nme@example.com"
    invalid4 = "ecdsa-sha2-nistp256 #{SSH_PUBLIC_KEY_ECDSA_256}\nme@example.com"

    assert SSHKey.valid_ssh_public_key?(expected1)
    assert SSHKey.valid_ssh_public_key?(expected2)

    assert !SSHKey.valid_ssh_public_key?(invalid1)
    assert !SSHKey.valid_ssh_public_key?(invalid2)
    assert !SSHKey.valid_ssh_public_key?(invalid3)
    assert !SSHKey.valid_ssh_public_key?(invalid4)
  end

  def test_ssh_public_key_validation_with_comments
    expected1 = "# Comment\nssh-rsa #{SSH_PUBLIC_KEY1}"
    expected2 = "# First comment\n\n# Second comment\n\nssh-ed25519 #{SSH_PUBLIC_KEY_ED25519} me@example.com"
    invalid1 = "No starting hash # Valid comment\nssh-rsa #{SSH_PUBLIC_KEY1} me@example.com"
    invalid2 = "# First comment\n\nSecond comment without hash\n\necdsa-sha2-nistp256 #{SSH_PUBLIC_KEY_ECDSA_256}\nme@example.com"

    assert SSHKey.valid_ssh_public_key?(expected1)
    assert SSHKey.valid_ssh_public_key?(expected2)

    assert !SSHKey.valid_ssh_public_key?(invalid1)
    assert !SSHKey.valid_ssh_public_key?(invalid2)
  end

  def test_ssh_public_key_sshfp
    assert_equal KEY1_SSHFP, SSHKey.sshfp("localhost", "ssh-rsa #{SSH_PUBLIC_KEY1}\n")
    assert_equal KEY2_SSHFP, SSHKey.sshfp("localhost", "ssh-rsa #{SSH_PUBLIC_KEY2}\n")
    assert_equal KEY3_SSHFP, SSHKey.sshfp("localhost", "ssh-dss #{SSH_PUBLIC_KEY3}\n")
    assert_equal KEY1_SSHFP, SSHKey.sshfp("localhost", SSH_PRIVATE_KEY1)
    assert_equal KEY2_SSHFP, SSHKey.sshfp("localhost", SSH_PRIVATE_KEY2)
    assert_equal KEY3_SSHFP, SSHKey.sshfp("localhost", SSH_PRIVATE_KEY3)
  end

  def test_ssh_public_key_bits
    expected1 = "ssh-rsa #{SSH_PUBLIC_KEY1} me@example.com"
    expected2 = "ssh-rsa #{SSH_PUBLIC_KEY2} me@example.com"
    expected3 = "ssh-dss #{SSH_PUBLIC_KEY3} me@example.com"
    expected4 = "ssh-rsa #{SSH_PUBLIC_KEY1}"
    expected5 = %(from="trusted.eng.cam.ac.uk",no-port-forwarding,no-pty ssh-rsa #{SSH_PUBLIC_KEY1})
    invalid1 = "#{SSH_PUBLIC_KEY1} me@example.com"
    ecdsa256 = "ecdsa-sha2-nistp256 #{SSH_PUBLIC_KEY_ECDSA_256}"
    ecdsa384 = "ecdsa-sha2-nistp384 #{SSH_PUBLIC_KEY_ECDSA_384}"
    ecdsa521 = "ecdsa-sha2-nistp521 #{SSH_PUBLIC_KEY_ECDSA_521}"
    ecdsa256_compressed = "ecdsa-sha2-nistp256 #{SSH_PUBLIC_KEY_ECDSA_256_COMPRESSED}"
    ecdsa384_compressed = "ecdsa-sha2-nistp384 #{SSH_PUBLIC_KEY_ECDSA_384_COMPRESSED}"
    ecdsa521_compressed = "ecdsa-sha2-nistp521 #{SSH_PUBLIC_KEY_ECDSA_521_COMPRESSED}"

    assert_equal 2048, SSHKey.ssh_public_key_bits(expected1)
    assert_equal 2048, SSHKey.ssh_public_key_bits(expected2)
    assert_equal 1024, SSHKey.ssh_public_key_bits(expected3)
    assert_equal 2048, SSHKey.ssh_public_key_bits(expected4)
    assert_equal 2048, SSHKey.ssh_public_key_bits(expected5)
    assert_equal 1024, SSHKey.ssh_public_key_bits(SSHKey.generate(type: "rsa", bits: 1024).ssh_public_key)
    assert_equal 256, SSHKey.ssh_public_key_bits(ecdsa256)
    assert_equal 384, SSHKey.ssh_public_key_bits(ecdsa384)
    assert_equal 521, SSHKey.ssh_public_key_bits(ecdsa521)
    assert_equal 256, SSHKey.ssh_public_key_bits(ecdsa256_compressed)
    assert_equal 384, SSHKey.ssh_public_key_bits(ecdsa384_compressed)
    assert_equal 521, SSHKey.ssh_public_key_bits(ecdsa521_compressed)

    exception1 = assert_raises(SSHKey::PublicKeyError) { SSHKey.ssh_public_key_bits(expected1.tr("A", ".")) }
    exception2 = assert_raises(SSHKey::PublicKeyError) { SSHKey.ssh_public_key_bits(expected1[0..-20]) }
    exception3 = assert_raises(SSHKey::PublicKeyError) { SSHKey.ssh_public_key_bits(invalid1) }

    assert_equal("validation error", exception1.message)
    assert_equal("byte array too short", exception2.message)
    assert_equal("cannot determine key type", exception3.message)
  end

  def test_ssh_public_key_to_ssh2_public_key
    public_key1 = "ssh-rsa #{SSH_PUBLIC_KEY1} me@example.com"
    public_key2 = "ssh-rsa #{SSH_PUBLIC_KEY2}"
    public_key3 = "ssh-dss #{SSH_PUBLIC_KEY3} 1024-bit DSA with provided comment"

    assert_equal(SSH2_PUBLIC_KEY1, SSHKey.ssh_public_key_to_ssh2_public_key(public_key1))
    assert_equal(SSH2_PUBLIC_KEY2, SSHKey.ssh_public_key_to_ssh2_public_key(public_key2))
    assert_equal(SSH2_PUBLIC_KEY2, SSHKey.ssh_public_key_to_ssh2_public_key(public_key2, {}))
    assert_equal(SSH2_PUBLIC_KEY3, SSHKey.ssh_public_key_to_ssh2_public_key(public_key3, {"Comment" => "1024-bit DSA with provided comment", "x-private-use-header" => "some value that is long enough to go to wrap around to a new line."}))
  end

  def test_dsa_bits_use_p_not_public_value
    # Same p, q and g as SSH_PUBLIC_KEY3 but a small public value, as happens when it has leading zero bytes
    p, q, g, _y = parse_sections(SSH_PUBLIC_KEY3, "ssh-dss")
    blob = ssh_string("ssh-dss") + [p, q, g, OpenSSL::BN.new(5)].map { |bn| bn.to_s(0) }.join
    assert_equal 1024, SSHKey.ssh_public_key_bits("ssh-dss #{[blob].pack("m0")}")
  end

  def test_fingerprints
    {
      "ssh-rsa #{SSH_PUBLIC_KEY1}" => [KEY1_MD5_FINGERPRINT, KEY1_SHA1_FINGERPRINT, KEY1_SHA256_FINGERPRINT],
      "ssh-rsa #{SSH_PUBLIC_KEY2} me@me.com" => [KEY2_MD5_FINGERPRINT, KEY2_SHA1_FINGERPRINT, KEY2_SHA256_FINGERPRINT],
      "ssh-dss #{SSH_PUBLIC_KEY3}" => [KEY3_MD5_FINGERPRINT, KEY3_SHA1_FINGERPRINT, KEY3_SHA256_FINGERPRINT],
      "ecdsa-sha2-nistp256 #{SSH_PUBLIC_KEY4}" => [KEY4_MD5_FINGERPRINT, KEY4_SHA1_FINGERPRINT, KEY4_SHA256_FINGERPRINT],
      "ssh-ed25519 #{SSH_PUBLIC_KEY_ED25519}" => [ED25519_MD5_FINGERPRINT, ED25519_SHA1_FINGERPRINT, ED25519_SHA256_FINGERPRINT],
      "ecdsa-sha2-nistp256 #{SSH_PUBLIC_KEY_ECDSA_256} me@me.com" => [ECDSA_256_MD5_FINGERPRINT, ECDSA_256_SHA1_FINGERPRINT, ECDSA_256_SHA256_FINGERPRINT],
      "ecdsa-sha2-nistp384 #{SSH_PUBLIC_KEY_ECDSA_384} me@me.com" => [ECDSA_384_MD5_FINGERPRINT, ECDSA_384_SHA1_FINGERPRINT, ECDSA_384_SHA256_FINGERPRINT],
      "ecdsa-sha2-nistp521 #{SSH_PUBLIC_KEY_ECDSA_521} me@me.com" => [ECDSA_521_MD5_FINGERPRINT, ECDSA_521_SHA1_FINGERPRINT, ECDSA_521_SHA256_FINGERPRINT]
    }.each do |public_key, (md5, sha1, sha256)|
      assert_equal md5, SSHKey.md5_fingerprint(public_key)
      assert_equal sha1, SSHKey.sha1_fingerprint(public_key)
      assert_equal sha256, SSHKey.sha256_fingerprint(public_key)
    end
  end

  def test_fingerprints_of_private_keys
    {SSH_PRIVATE_KEY1 => KEY1_SHA256_FINGERPRINT, SSH_PRIVATE_KEY3 => KEY3_SHA256_FINGERPRINT, SSH_PRIVATE_KEY4 => KEY4_SHA256_FINGERPRINT}.each do |private_key, sha256|
      assert_equal sha256, SSHKey.sha256_fingerprint(private_key)
    end
    assert_equal KEY2_MD5_FINGERPRINT, SSHKey.md5_fingerprint(SSH_PRIVATE_KEY2)
    assert_equal KEY2_SHA1_FINGERPRINT, SSHKey.sha1_fingerprint(SSH_PRIVATE_KEY2)
  end

  def test_fingerprint_of_public_key_with_private_in_comment
    assert_equal KEY1_SHA256_FINGERPRINT, SSHKey.sha256_fingerprint("ssh-rsa #{SSH_PUBLIC_KEY1} PRIVATE-build-server")
    assert_equal KEY1_SSHFP, SSHKey.sshfp("localhost", "ssh-rsa #{SSH_PUBLIC_KEY1} PRIVATE-build-server")
  end

  private

  def ssh_string(str)
    [str.bytesize].pack("N") + str.b
  end

  def parse_sections(encoded, type)
    data = encoded.unpack1("m").byteslice((4 + type.bytesize)..)
    sections = []
    until data.empty?
      size = data.unpack1("N")
      sections << OpenSSL::BN.new(data.byteslice(4, size), 2)
      data = data.byteslice((4 + size)..)
    end
    sections
  end
end
