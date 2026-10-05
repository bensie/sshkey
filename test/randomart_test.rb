require_relative "test_helper"

class RandomartTest < Test::Unit::TestCase
  include Fixtures

  def test_randomart_defaults_to_sha256
    assert_equal KEY4_RANDOMART_USING_SHA256_DIGEST, @key4.randomart
    assert_equal ED25519_RANDOMART_USING_SHA256_DIGEST, SSHKey.new(ED25519_PRIVATE_KEY).randomart
  end

  def test_randomart_md5
    assert_equal KEY1_RANDOMART, @key1.randomart("MD5")
    assert_equal KEY2_RANDOMART, @key2.randomart("MD5")
    assert_equal KEY3_RANDOMART, @key3.randomart("MD5")
    assert_equal KEY4_RANDOMART, @key4.randomart(:md5)
  end

  def test_randomart_other_digests
    assert_equal KEY4_RANDOMART_USING_SHA384_DIGEST, @key4.randomart("SHA384")
    assert_equal KEY4_RANDOMART_USING_SHA512_DIGEST, @key4.randomart("SHA512")
  end

  def test_randomart_unknown_digest
    assert_raises(ArgumentError) { @key1.randomart("SHA1") }
  end
end
