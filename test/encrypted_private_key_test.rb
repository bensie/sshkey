require_relative "test_helper"

class EncryptedPrivateKeyTest < Test::Unit::TestCase
  include Fixtures

  def setup
    super
    @key_encrypted = SSHKey.new(ENCRYPTED_PRIVATE_KEY, passphrase: "password")
  end

  def test_encrypted_private_key_can_be_decrypted
    assert_equal DECRYPTED_PRIVATE_KEY, @key_encrypted.private_key
  end

  def test_encrypted_private_key_matches_when_reencrypted
    key = SSHKey.new(@key_encrypted.encrypted_private_key, passphrase: "password")
    assert_equal DECRYPTED_PRIVATE_KEY, key.private_key
    assert_equal DECRYPTED_KEY_FINGERPRINT, key.md5_fingerprint
  end

  def test_encrypted_private_key_is_pkcs8
    pem = @key_encrypted.encrypted_private_key
    assert_match(/\A-----BEGIN ENCRYPTED PRIVATE KEY-----\n/, pem)
    algorithms = OpenSSL::ASN1.decode(pem.lines[1..-2].join.unpack1("m"))
    assert_equal "PBES2", algorithms.value[0].value[0].value
  end

  def test_encrypted_private_key_without_passphrase
    assert_equal DECRYPTED_PRIVATE_KEY, SSHKey.new(DECRYPTED_PRIVATE_KEY).encrypted_private_key
  end

  def test_missing_passphrase_raises_instead_of_prompting
    error = assert_raises(SSHKey::PrivateKeyError) { SSHKey.new(ENCRYPTED_PRIVATE_KEY) }
    assert_match(/passphrase/, error.message)
  end

  def test_incorrect_passphrase
    assert_raises(SSHKey::PrivateKeyError) { SSHKey.new(ENCRYPTED_PRIVATE_KEY, passphrase: "wrong") }
  end

  def test_ed25519_encryption_not_supported
    key = SSHKey.generate(type: "ed25519", passphrase: "password")
    assert_raises(SSHKey::UnsupportedError) { key.encrypted_private_key }
  end
end
