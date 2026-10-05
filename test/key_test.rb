require_relative "test_helper"

class KeyTest < Test::Unit::TestCase
  include Fixtures

  def keys
    {
      @key1 => {private_key: SSH_PRIVATE_KEY1, public_key: PUBLIC_KEY1, ssh_public_key: SSH_PUBLIC_KEY1, typestr: "ssh-rsa", bits: 2048,
                md5: KEY1_MD5_FINGERPRINT, sha1: KEY1_SHA1_FINGERPRINT, sha256: KEY1_SHA256_FINGERPRINT},
      @key2 => {private_key: SSH_PRIVATE_KEY2, public_key: PUBLIC_KEY2, ssh_public_key: SSH_PUBLIC_KEY2, typestr: "ssh-rsa", bits: 2048,
                md5: KEY2_MD5_FINGERPRINT, sha1: KEY2_SHA1_FINGERPRINT, sha256: KEY2_SHA256_FINGERPRINT},
      @key3 => {private_key: SSH_PRIVATE_KEY3, public_key: PUBLIC_KEY3, ssh_public_key: SSH_PUBLIC_KEY3, typestr: "ssh-dss", bits: 1024,
                md5: KEY3_MD5_FINGERPRINT, sha1: KEY3_SHA1_FINGERPRINT, sha256: KEY3_SHA256_FINGERPRINT},
      @key4 => {private_key: SSH_PRIVATE_KEY4, public_key: PUBLIC_KEY4, ssh_public_key: SSH_PUBLIC_KEY4, typestr: "ecdsa-sha2-nistp256", bits: 256,
                md5: KEY4_MD5_FINGERPRINT, sha1: KEY4_SHA1_FINGERPRINT, sha256: KEY4_SHA256_FINGERPRINT}
    }
  end

  def test_private_key
    keys.each { |key, expected| assert_equal expected[:private_key], key.private_key }
  end

  def test_public_key
    keys.each { |key, expected| assert_equal expected[:public_key], key.public_key }
  end

  def test_ssh_public_key
    keys.each do |key, expected|
      assert_equal "#{expected[:typestr]} #{expected[:ssh_public_key]} me@example.com", key.ssh_public_key
    end
    assert_equal "ssh-rsa #{SSH_PUBLIC_KEY1}", @key_without_comment.ssh_public_key
  end

  def test_bits
    keys.each { |key, expected| assert_equal expected[:bits], key.bits }
  end

  def test_fingerprints
    keys.each do |key, expected|
      assert_equal expected[:md5], key.md5_fingerprint
      assert_equal expected[:sha1], key.sha1_fingerprint
      assert_equal expected[:sha256], key.sha256_fingerprint
    end
  end

  def test_fingerprint_alias_removed
    assert_false @key1.respond_to?(:fingerprint)
    assert_false SSHKey.respond_to?(:fingerprint)
  end

  def test_sshfp
    assert_equal KEY1_SSHFP, @key1.sshfp("localhost")
    assert_equal KEY2_SSHFP, @key2.sshfp("localhost")
    assert_equal KEY3_SSHFP, @key3.sshfp("localhost")
  end

  def test_public_key_object
    assert_equal PUBLIC_KEY1, @key1.public_key_object.public_to_pem
    assert_equal PUBLIC_KEY4, @key4.public_key_object.public_to_pem
    assert_false @key4.public_key_object.private?
  end

  def test_key_object
    assert_equal 35, @key1.key_object.e.to_i
    assert_equal 21959919395955180268707532246136630338880737002345156586705317733493418045367765414088155418090419238250026039981229751319343545922377196559932805781226688384973919515037364518167604848468288361633800200593870224270802677578686553567598208927704479575929054501425347794297979215349516030584575472280923909378896367886007339003194417496761108245404573433556449606964806956220743380296147376168499567508629678037211105349574822849913423806275470761711930875368363589001630573570236600319099783704171412637535837916991323769813598516411655563604244942820475880695152610674934239619752487880623016350579174487901241422633, @key1.key_object.n.to_i
  end

  def test_ssh2_public_key
    assert_equal SSH2_PUBLIC_KEY1, @key1.ssh2_public_key
    assert_equal SSH2_PUBLIC_KEY2, @key2.ssh2_public_key({})
    assert_equal SSH2_PUBLIC_KEY3, @key3.ssh2_public_key({"Comment" => "1024-bit DSA with provided comment",
      "x-private-use-header" => "some value that is long enough to go to wrap around to a new line."})
  end

  def test_directives
    assert_equal [], @key1.directives

    @key1.directives = "no-pty"
    assert_equal ["no-pty"], @key1.directives

    @key1.directives = ["no-pty"]
    assert_equal ["no-pty"], @key1.directives

    @key1.directives = [
      "no-port-forwarding",
      "no-X11-forwarding",
      "no-agent-forwarding",
      "no-pty",
      "command='/home/user/bin/authprogs'"
    ]
    expected1 = "no-port-forwarding,no-X11-forwarding,no-agent-forwarding,no-pty,command='/home/user/bin/authprogs' ssh-rsa #{SSH_PUBLIC_KEY1} me@example.com"
    assert_equal expected1, @key1.ssh_public_key
    assert SSHKey.valid_ssh_public_key?(expected1)

    key = SSHKey.new(SSH_PRIVATE_KEY2, comment: "me@example.com", directives: "no-pty")
    expected2 = "no-pty ssh-rsa #{SSH_PUBLIC_KEY2} me@example.com"
    assert_equal expected2, key.ssh_public_key
    assert SSHKey.valid_ssh_public_key?(expected2)
  end

  def test_new_from_openssl_pkey_object
    key = SSHKey.new(@key4.key_object, comment: "me@example.com")
    assert_equal @key4.ssh_public_key, key.ssh_public_key
  end

  def test_new_from_pkcs8_pem
    key = SSHKey.new(@key1.key_object.private_to_pem, comment: "me@example.com")
    assert_equal @key1.ssh_public_key, key.ssh_public_key
  end

  def test_new_with_unknown_option
    assert_raises(ArgumentError) { SSHKey.new(SSH_PRIVATE_KEY1, commnet: "typo") }
  end

  def test_new_with_unsupported_key_type
    ed448 = <<~EOF
      -----BEGIN PRIVATE KEY-----
      MEcCAQAwBQYDK2VxBDsEOWJvW9C6Mp1k8gXi3l4EwtgQOHV+rXfFfwVXED2Jadbd
      Pz2VU714rzAPK/SA+zsAk2EFsVILnX5m6w==
      -----END PRIVATE KEY-----
    EOF
    assert_raises(SSHKey::UnsupportedError) { SSHKey.new(ed448) }
  end

  def test_new_with_invalid_key
    error = assert_raises(SSHKey::PrivateKeyError) { SSHKey.new("not a key") }
    assert_kind_of SSHKey::Error, error
  end

  def test_ed25519_key
    key = SSHKey.new(ED25519_PRIVATE_KEY)
    assert_equal "ed25519", key.type
    assert_equal "ssh-ed25519", key.typestr
    assert_equal 256, key.bits
    assert_equal "odFNduUZOov1HfgS5iy8PQtbD9uyu3++vZgot7fHsUk", key.sha256_fingerprint
    assert_equal "ef:8d:9f:2a:23:71:00:c4:0e:0f:98:5d:a0:f8:ec:52", key.md5_fingerprint
    assert_equal "h IN SSHFP 4 1 81c6ca94b65120daa794c428835eaff6f8613438\n" \
                 "h IN SSHFP 4 2 a1d14d76e5193a8bf51df812e62cbc3d0b5b0fdbb2bb7fbebd9828b7b7c7b149", key.sshfp("h")
    assert_match(/\A-----BEGIN OPENSSH PRIVATE KEY-----\n/, key.private_key)
    assert_equal ED25519_PUBLIC_KEY, SSHKey.new(key.private_key).ssh_public_key
    assert_equal key.public_key, SSHKey.new(key.key_object.private_to_pem).public_key
  end
end
