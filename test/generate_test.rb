require_relative "test_helper"

class GenerateTest < Test::Unit::TestCase
  def test_generate_requires_type
    error = assert_raises(ArgumentError) { SSHKey.generate }
    assert_match(/type: is required/, error.message)
    assert_raises(ArgumentError) { SSHKey.generate(comment: "foo") }
  end

  def test_generate_rsa_defaults
    key = SSHKey.generate(type: "rsa")
    assert_equal "rsa", key.type
    assert_equal 3072, key.bits
    assert_equal "", key.comment
  end

  def test_generate_with_comment
    assert_equal "foo", SSHKey.generate(type: "ed25519", comment: "foo").comment
  end

  def test_generate_with_directives
    assert_equal ["no-pty"], SSHKey.generate(type: "ed25519", directives: "no-pty").directives
  end

  def test_generate_with_type
    assert_equal "rsa", SSHKey.generate(type: "rsa", bits: 1024).type
    assert_equal "ecdsa", SSHKey.generate(type: "ecdsa").type
    assert_equal "ed25519", SSHKey.generate(type: "ed25519").type
  end

  def test_generate_with_symbol_or_uppercase_type
    assert_equal "ed25519", SSHKey.generate(type: :ed25519).type
    assert_equal "ecdsa", SSHKey.generate(type: "ECDSA").type
    assert_equal 256, SSHKey.generate(type: "ECDSA").bits
  end

  def test_generate_with_passphrase
    assert_equal "password", SSHKey.generate(type: "ecdsa", passphrase: "password").passphrase
  end

  def test_generate_rsa_with_bits
    assert_equal 1024, SSHKey.generate(type: "rsa", bits: 1024).bits
  end

  def test_generate_ecdsa_with_bits
    [256, 384, 521].each do |bits|
      key = SSHKey.generate(type: "ecdsa", bits: bits)
      assert_equal "ecdsa-sha2-nistp#{bits}", key.typestr
      assert_equal bits, key.bits
      assert SSHKey.valid_ssh_public_key?(key.ssh_public_key)
    end
    assert_raises(ArgumentError) { SSHKey.generate(type: "ecdsa", bits: 1024) }
  end

  def test_generate_ed25519
    key = SSHKey.generate(type: "ed25519", comment: "me@example.com")
    assert_equal "ed25519", key.type
    assert_equal 256, key.bits
    assert_match(/\Assh-ed25519 \S+ me@example.com\z/, key.ssh_public_key)
    assert SSHKey.valid_ssh_public_key?(key.ssh_public_key)
    assert_raises(ArgumentError) { SSHKey.generate(type: "ed25519", bits: 512) }
  end

  def test_generate_dsa_not_supported
    error = assert_raises(ArgumentError) { SSHKey.generate(type: "dsa") }
    assert_match(/DSA/, error.message)
  end

  def test_generate_with_unknown_type
    assert_raises(ArgumentError) { SSHKey.generate(type: "foo") }
  end

  def test_generate_with_unknown_option
    assert_raises(ArgumentError) { SSHKey.generate(type: "rsa", commnet: "typo") }
  end

  def test_generated_keys_round_trip
    [["rsa", 1024], ["ecdsa", 384], ["ed25519", nil]].each do |type, bits|
      key = SSHKey.generate(type: type, bits: bits, comment: "#{type} key")
      reloaded = SSHKey.new(key.private_key)
      assert_equal "#{key.typestr} #{key.ssh_public_key.split[1]} #{type} key", key.ssh_public_key
      assert_equal key.ssh_public_key.split[0, 2], reloaded.ssh_public_key.split[0, 2]
      assert_equal key.sha256_fingerprint, SSHKey.sha256_fingerprint(key.ssh_public_key)
    end
  end
end
