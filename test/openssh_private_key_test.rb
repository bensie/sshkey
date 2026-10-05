require_relative "test_helper"

class OpenSSHPrivateKeyTest < Test::Unit::TestCase
  include Fixtures

  def test_load_openssh_private_keys
    {
      ED25519_PRIVATE_KEY  => ED25519_PUBLIC_KEY,
      ECDSA384_PRIVATE_KEY => ECDSA384_PUBLIC_KEY,
      RSA_PRIVATE_KEY      => RSA_PUBLIC_KEY,
    }.each do |private_key, public_key|
      key = SSHKey.new(private_key)
      assert_equal public_key, key.ssh_public_key # includes the comment stored in the key
      assert_equal SSHKey.sha256_fingerprint(public_key), key.sha256_fingerprint
      assert_equal SSHKey.ssh_public_key_bits(public_key), key.bits
    end
  end

  def test_comment_option_overrides_stored_comment
    assert_equal "override", SSHKey.new(ED25519_PRIVATE_KEY, comment: "override").comment
  end

  def test_encrypted_openssh_private_key_not_supported
    error = assert_raises(SSHKey::UnsupportedError) { SSHKey.new(ED25519_ENCRYPTED_PRIVATE_KEY, passphrase: "password") }
    assert_match(/passphrase-protected/, error.message)
  end

  def test_openssh_private_key_round_trip
    keys = %w[rsa ecdsa ed25519].map { |type| SSHKey.generate(type: type, bits: (1024 if type == "rsa"), comment: "#{type}@example.com") }
    keys << SSHKey.new(SSH_PRIVATE_KEY3, comment: "dsa@example.com")
    keys.each do |key|
      type = key.type
      reloaded = SSHKey.new(key.openssh_private_key)
      assert_equal key.ssh_public_key, reloaded.ssh_public_key
      if type == "ed25519"
        assert_equal key.key_object.raw_private_key, reloaded.key_object.raw_private_key
      else
        assert_equal key.private_key, reloaded.private_key
      end
    end
  end

  def test_malformed_openssh_private_key
    truncated = ED25519_PRIVATE_KEY.lines.values_at(0, 1, -1).join
    assert_raises(SSHKey::PrivateKeyError) { SSHKey.new(truncated) }
  end

  def test_openssh_private_key_is_readable_by_ssh_keygen
    ssh_keygen = ENV.fetch("PATH", "").split(File::PATH_SEPARATOR).any? { |dir| File.executable?(File.join(dir, "ssh-keygen")) }
    omit("ssh-keygen not available") unless ssh_keygen

    %w[rsa ecdsa ed25519].each do |type|
      key = SSHKey.generate(type: type, comment: "#{type}@example.com")
      Tempfile.create("sshkey") do |file|
        file.write(key.openssh_private_key)
        file.close
        File.chmod(0600, file.path)
        assert_equal key.ssh_public_key, `ssh-keygen -y -f #{file.path}`.strip
      end
    end
  end
end
