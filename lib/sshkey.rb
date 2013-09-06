$:.unshift File.dirname(__FILE__)

require 'openssl'
require 'base64'
require 'digest/md5'
require 'digest/sha1'
require 'sshkey/exception'

class SSHKey
  SSH_TYPES      = {"rsa" => "ssh-rsa", "dsa" => "ssh-dss"}
  SSH_CONVERSION = {"rsa" => ["e", "n"], "dsa" => ["p", "q", "g", "pub_key"]}

  class << self
    # Generate a new keypair and return an SSHKey object
    #
    # The default behavior when providing no options will generate a 2048-bit RSA
    # keypair.
    #
    # ==== Parameters
    # * options<~Hash>:
    #   * :type<~String> - "rsa" or "dsa", "rsa" by default
    #   * :bits<~Integer> - Bit length
    #   * :comment<~String> - Comment to use for the public key, defaults to ""
    #   * :passphrase<~String> - Encrypt the key with this passphrase
    #
    def generate(options = {})
      type   = options[:type] || "rsa"

      # JRuby modulus size must range from 512 to 1024
      default_bits = type == "rsa" ? 2048 : 1024

      bits   = options[:bits] || default_bits
      cipher = OpenSSL::Cipher::Cipher.new("AES-128-CBC") if options[:passphrase]

      case type.downcase
      when "rsa" then new(OpenSSL::PKey::RSA.generate(bits).to_pem(cipher, options[:passphrase]), options)
      when "dsa" then new(OpenSSL::PKey::DSA.generate(bits).to_pem(cipher, options[:passphrase]), options)
      else
        raise "Unknown key type: #{type}"
      end
    end

    # Validate an existing SSH public key
    #
    # Returns true or false depending on the validity of the public key provided
    #
    # ==== Parameters
    # * ssh_public_key<~String> - "ssh-rsa AAAAB3NzaC1yc2EA...."
    #
    def valid_ssh_public_key?(ssh_public_key)
      ssh_type, encoded_key = parse_ssh_public_key(ssh_public_key)
      SSH_CONVERSION[SSH_TYPES.invert[ssh_type]].size == unpacked_byte_array(ssh_type, encoded_key).size
    rescue
      false
    end

    # Bits
    #
    # Returns ssh public key bits or false depending on the validity of the public key provided
    #
    # ==== Parameters
    # * ssh_public_key<~String> - "ssh-rsa AAAAB3NzaC1yc2EA...."
    #
    def ssh_public_key_bits(ssh_public_key)
      unpacked_byte_array( *parse_ssh_public_key(ssh_public_key) ).last.size * 8
    end

    # Fingerprints
    #
    # Accepts either a public or private key
    #
    # MD5 fingerprint for the given SSH key
    def md5_fingerprint(key)
      if key.match(/PRIVATE/)
        new(key).md5_fingerprint
      else
        Digest::MD5.hexdigest(decoded_key(key)).gsub(fingerprint_regex, '\1:\2')
      end
    end
    alias_method :fingerprint, :md5_fingerprint

    # SHA1 fingerprint for the given SSH key
    def sha1_fingerprint(key)
      if key.match(/PRIVATE/)
        new(key).sha1_fingerprint
      else
        Digest::SHA1.hexdigest(decoded_key(key)).gsub(fingerprint_regex, '\1:\2')
      end
    end

    private

    def unpacked_byte_array(ssh_type, encoded_key)
      prefix = [0,0,0,7].pack("C*")
      decoded = Base64.decode64(encoded_key)

      # Base64 decoding is too permissive, so we should validate if encoding is correct
      if Base64.encode64(decoded).gsub("\n", "") != encoded_key || decoded.sub!(/^#{prefix}#{ssh_type}/, "").nil?
        raise PublicKeyError, "validation error"
      end

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
      return data
    end

    def from_byte_array(byte_array, expected_size = nil)
      raise PublicKeyError, "byte array too short" if !expected_size.nil? && expected_size != byte_array.size
      num = 0
      byte_array.reverse.each_with_index do |item, index|
        num += item * 256**(index)
      end
      num
    end

    def decoded_key(key)
      Base64.decode64(key.gsub(/^(ssh-[dr]s[as]\s+)|(\s+.+\@.+)|\n/, ''))
    end

    def fingerprint_regex
      /(.{2})(?=.)/
    end

    def parse_ssh_public_key(public_key)
      parsed = public_key.split(" ")
      parsed.each_with_index do |el, index|
        return parsed[index..(index+1)] if SSH_TYPES.invert[el]
      end
      raise PublicKeyError, "cannot determine key type"
    end
  end

  attr_reader :key_object, :type
  attr_accessor :passphrase, :comment

  # Create a new SSHKey object
  #
  # ==== Parameters
  # * private_key - Existing RSA or DSA private key
  # * options<~Hash>
  #   * :comment<~String> - Comment to use for the public key, defaults to ""
  #   * :passphrase<~String> - If the key is encrypted, supply the passphrase
  #   * :directives<~Array> - Options prefixed to the public key
  #
  def initialize(private_key, options = {})
    @passphrase = options[:passphrase]
    @comment    = options[:comment] || ""
    self.directives = options[:directives] || []
    begin
      @key_object = OpenSSL::PKey::RSA.new(private_key, passphrase)
      @type = "rsa"
    rescue
      @key_object = OpenSSL::PKey::DSA.new(private_key, passphrase)
      @type = "dsa"
    end
  end

  # Fetch the RSA/DSA private key
  #
  # rsa_private_key and dsa_private_key are aliased for backward compatibility
  def private_key
    key_object.to_pem
  end
  alias_method :rsa_private_key, :private_key
  alias_method :dsa_private_key, :private_key

  # Fetch the encrypted RSA/DSA private key using the passphrase provided
  #
  # If no passphrase is set, returns the unencrypted private key
  def encrypted_private_key
    return private_key unless passphrase
    key_object.to_pem(OpenSSL::Cipher::Cipher.new("AES-128-CBC"), passphrase)
  end

  # Fetch the RSA/DSA public key
  #
  # rsa_public_key and dsa_public_key are aliased for backward compatibility
  def public_key
    key_object.public_key.to_pem
  end
  alias_method :rsa_public_key, :public_key
  alias_method :dsa_public_key, :public_key

  # SSH public key
  def ssh_public_key
    [directives.join(",").strip, SSH_TYPES[type], Base64.encode64(ssh_public_key_conversion).gsub("\n", ""), comment].join(" ").strip
  end

  # Fingerprints
  #
  # MD5 fingerprint for the given SSH public key
  def md5_fingerprint
    Digest::MD5.hexdigest(ssh_public_key_conversion).gsub(/(.{2})(?=.)/, '\1:\2')
  end
  alias_method :fingerprint, :md5_fingerprint

  # SHA1 fingerprint for the given SSH public key
  def sha1_fingerprint
    Digest::SHA1.hexdigest(ssh_public_key_conversion).gsub(/(.{2})(?=.)/, '\1:\2')
  end

  # Determine the length (bits) of the key as an integer
  def bits
    self.class.ssh_public_key_bits(ssh_public_key)
  end

  # Randomart
  #
  # Generate OpenSSH compatible ASCII art fingerprints
  # See http://www.opensource.apple.com/source/OpenSSH/OpenSSH-175/openssh/key.c (key_fingerprint_randomart function)
  #
  # Example:
  # +--[ RSA 2048]----+
  # |o+ o..           |
  # |..+.o            |
  # | ooo             |
  # |.++. o           |
  # |+o+ +   S        |
  # |.. + o .         |
  # |  . + .          |
  # |   . .           |
  # |    Eo.          |
  # +-----------------+
  def randomart
    fieldsize_x = 17
    fieldsize_y = 9
    x = fieldsize_x / 2
    y = fieldsize_y / 2
    raw_digest = Digest::MD5.digest(ssh_public_key_conversion)
    num_bytes = raw_digest.bytesize

    field = Array.new(fieldsize_x) { Array.new(fieldsize_y) {0} }

    raw_digest.bytes.each do |byte|
      4.times do
        x += (byte & 0x1 != 0) ? 1 : -1
        y += (byte & 0x2 != 0) ? 1 : -1

        x = [[x, 0].max, fieldsize_x - 1].min
        y = [[y, 0].max, fieldsize_y - 1].min

        field[x][y] += 1 if (field[x][y] < num_bytes - 2)

        byte >>= 2
      end
    end

    field[fieldsize_x / 2][fieldsize_y / 2] = num_bytes - 1
    field[x][y] = num_bytes
    augmentation_string = " .o+=*BOX@%&#/^SE"
    output = "+--#{sprintf("[%4s %4u]", type.upcase, bits)}----+\n"
    fieldsize_y.times do |y|
      output << "|"
      fieldsize_x.times do |x|
        output << augmentation_string[[field[x][y], num_bytes].min]
      end
      output << "|"
      output << "\n"
    end
    output << "+#{"-" * fieldsize_x}+"
    output
  end

  def directives=(directives)
    @directives = Array[directives].flatten.compact
  end
  attr_reader :directives

  private

  # SSH Public Key Conversion
  #
  # All data type encoding is defined in the section #5 of RFC #4251.
  # String and mpint (multiple precision integer) types are encoded this way:
  # 4-bytes word: data length (unsigned big-endian 32 bits integer)
  # n bytes: binary representation of the data

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
