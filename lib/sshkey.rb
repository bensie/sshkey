require 'openssl'
require 'base64'
require 'digest/md5'

class SSHKey
  SSH_TYPES      = {"rsa" => "ssh-rsa", "dsa" => "ssh-dss"}
  SSH_CONVERSION = {"rsa" => ["e", "n"], "dsa" => ["p", "q", "g", "pub_key"]}

  attr_reader :key_object, :comment, :type

  def self.generate(options = {})
    type = options[:type] || "rsa"
    case type
    when "rsa" then SSHKey.new(OpenSSL::PKey::RSA.generate(2048).to_pem, options)
    when "dsa" then SSHKey.new(OpenSSL::PKey::DSA.generate(2048).to_pem, options)
    else
      raise "Unknown key type #{type}"
    end
  end

  def self.valid?(ssh_key)
    ssh_type, encoded_key = ssh_key.split(" ")
    type = SSH_TYPES.invert[ssh_type]
    prefix = [0,0,0,7].pack("C*")
    decoded = Base64.decode64(encoded_key)

    # Base64 decoding is too permissive, so we should validate if encoding is correct
    return false unless Base64.encode64(decoded).gsub("\n", "") == encoded_key
    return false unless decoded.sub!(/^#{prefix}#{ssh_type}/, "")

    unpacked = decoded.unpack("C*")
    data = []
    index = 0
    until unpacked[index].nil?
      datum_size = from_byte_array unpacked[index..index+4-1], 4
      index = index + 4
      datum = from_byte_array unpacked[index..index+datum_size-1], datum_size
      data << datum
      index = index + datum_size
    end

    SSH_CONVERSION[type].size == data.size
  rescue
    false
  end

  def self.from_byte_array(byte_array, expected_size = nil)
    num = 0
    raise "Byte array too short" if !expected_size.nil? && expected_size != byte_array.size
    byte_array.reverse.each_with_index do |item, index|
      num += item * 256**(index)
    end
    num
  end

  def initialize(private_key, options = {})
    begin
      @key_object = OpenSSL::PKey::RSA.new(private_key)
      @type = "rsa"
    rescue
      @key_object = OpenSSL::PKey::DSA.new(private_key)
      @type = "dsa"
    end

    @comment = options[:comment] || ""
  end

  def private_key
    key_object.to_pem
  end

  def public_key
    key_object.public_key.to_pem
  end

  def ssh_public_key
    [SSH_TYPES[type], Base64.encode64(ssh_public_key_conversion).gsub("\n", ""), comment].join(" ").strip
  end

  def fingerprint
    Digest::MD5.hexdigest(ssh_public_key_conversion).gsub(/(.{2})(?=.)/, '\1:\2')
  end

  private

  # All data type encoding is defined in the section #5 of RFC #4251.
  # String and mpint (multiple precision integer) types are encoded this way :
  # 4-bytes word: data length (unsigned big-endian 32 bits integer)
  # n bytes     : binary representation of the data

  # For instance, the "ssh-rsa" string is encoded as the following byte array
  # [0, 0, 0, 7, 's', 's', 'h', '-', 'r', 's', 'a']
  def ssh_public_key_conversion
    out = [0,0,0,7].pack("C*")
    out += SSH_TYPES[type]

    SSH_CONVERSION[type].each do |method|
      byte_array = to_byte_array(key_object.public_key.send(method).to_i)
      out += encode_unsigned_int_32(byte_array.length).pack("c*")
      out += byte_array.pack("C*")
    end

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
