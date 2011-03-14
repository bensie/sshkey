require 'openssl'
require 'base64'
require 'digest/md5'

class SSHKey

  def self.generate(options = {})
    SSHKey.new(OpenSSL::PKey::RSA.generate(2048).to_pem, options)
  end

  attr_reader :key_object, :comment, :rsa_private_key, :rsa_public_key, :ssh_public_key, :fingerprint

  def initialize(private_key, options = {})
    @key_object        = OpenSSL::PKey::RSA.new(private_key)
    @comment           = options[:comment] || ""
    @rsa_private_key   = @key_object.to_pem
    @rsa_public_key    = @key_object.public_key.to_pem
    raw_ssh_public_key = ssh_public_key_conversion
    @ssh_public_key    = ["ssh-rsa", Base64.strict_encode64(raw_ssh_public_key), @comment].join(" ").strip
    @fingerprint       = Digest::MD5.hexdigest(raw_ssh_public_key).gsub(/(.{2})(?=.)/, '\1:\2')
  end

  private

  # All data type encoding is defined in the section #5 of RFC #4251.
  # String and mpint (multiple precision integer) types are encoded this way :
  # 4-bytes word: data length (unsigned big-endian 32 bits integer)
  # n bytes     : binary representation of the data

  # For instance, the "ssh-rsa" string is encoded as the following byte array
  # [0, 0, 0, 7, 's', 's', 'h', '-', 'r', 's', 'a']
  def ssh_public_key_conversion
    e = @key_object.public_key.e.to_i
    n = @key_object.public_key.n.to_i

    out = [0,0,0,7].pack("c*")
    out += "ssh-rsa"
    out += encode_unsigned_int_32(to_byte_array(e).length).pack("c*")
    out += to_byte_array(e).pack("c*")
    out += encode_unsigned_int_32(to_byte_array(n).length).pack("c*")
    out += to_byte_array(n).pack("c*")

    return out
  end

  def encode_unsigned_int_32(value)
    out = []
    out[0] = value >> 24 & 0xff
    out[1] = value >> 16 & 0xff
    out[2] = value >> 8 & 0xff
    out[3] = value & 0xff
    return out
  end

  def to_byte_array(num)
    result = []
    begin
      result << (num & 0xff)
      num >>= 8
    end until (num == 0 || num == -1) && (result.last[7] == num[7])
    result.reverse
  end
end
