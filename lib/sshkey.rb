require 'openssl'
require 'base64'
require 'digest/md5'
require 'digest/sha1'
require 'digest/sha2'

def jruby_not_implemented(msg)
  raise NotImplementedError.new "jruby-openssl #{JOpenSSL::VERSION}: #{msg}" if RUBY_PLATFORM == "java"
end

# Monkey patch OpenSSL::PKey::EC to provide convenience methods usable in this gem
class OpenSSL::PKey::EC
  def identifier
    # NOTE: Unable to find these constants within OpenSSL, so hardcode them here.
    # Analogous to net-ssh OpenSSL::PKey::EC::CurveNameAliasInv
    # https://github.com/net-ssh/net-ssh/blob/master/lib/net/ssh/transport/openssl.rb#L147-L151
    case group.curve_name
    when "prime256v1" then "nistp256"  # https://stackoverflow.com/a/41953717
    when "secp256r1"  then "nistp256"  # JRuby
    when "secp384r1"  then "nistp384"
    when "secp521r1"  then "nistp521"
    else
      raise "Unknown curve name: #{public_key.group.curve_name}"
    end
  end

  def q
    # jruby-openssl does not currently support to_octet_string
    # https://github.com/jruby/jruby-openssl/issues/226
    jruby_not_implemented("to_octet_string is not implemented")

    public_key.to_octet_string(group.point_conversion_form)
  end
end

class SSHKey
  SSH_TYPES = {
    "ssh-rsa" => "rsa",
    "ssh-dss" => "dsa",
    "ssh-ed25519" => "ed25519",
    "ecdsa-sha2-nistp256" => "ecdsa",
    "ecdsa-sha2-nistp384" => "ecdsa",
    "ecdsa-sha2-nistp521" => "ecdsa",
  }

  SSHFP_TYPES = {
    "rsa"     => 1,
    "dsa"     => 2,
    "ecdsa"   => 3,
    "ed25519" => 4,
  }

  ECDSA_CURVES = {
    256 => "prime256v1",  # https://stackoverflow.com/a/41953717
    384 => "secp384r1",
    521 => "secp521r1",
  }

  VALID_BITS = {
    "ecdsa" => ECDSA_CURVES.keys,
  }

  # Accessor methods are defined in:
  # - RSA:   https://github.com/ruby/openssl/blob/master/ext/openssl/ossl_pkey_rsa.c
  # - DSA:   https://github.com/ruby/openssl/blob/master/ext/openssl/ossl_pkey_dsa.c
  # - ECDSA: monkey patch OpenSSL::PKey::EC above
  SSH_CONVERSION = {"rsa" => ["e", "n"], "dsa" => ["p", "q", "g", "pub_key"], "ecdsa" => ["identifier", "q"]}

  SSH2_LINE_LENGTH = 70 # +1 (for line wrap '/' character) must be <= 72

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
      case type
      when "rsa"   then default_bits = 2048
      when "ecdsa" then default_bits = 256
      else
        default_bits = 1024
      end

      bits   = options[:bits] || default_bits
      cipher = OpenSSL::Cipher.new("AES-128-CBC") if options[:passphrase]

      raise "Bits must either: #{VALID_BITS[type.downcase].join(', ')}" unless VALID_BITS[type.downcase].nil? || VALID_BITS[type.downcase].include?(bits)

      case type.downcase
      when "rsa"
        key_object = OpenSSL::PKey::RSA.generate(bits)

      when "dsa"
        key_object = OpenSSL::PKey::DSA.generate(bits)

      when "ecdsa"
        # jruby-openssl OpenSSL::PKey::EC support isn't complete
        # https://github.com/jruby/jruby-openssl/issues/189
        jruby_not_implemented("OpenSSL::PKey::EC is not fully implemented")

        if OpenSSL::OPENSSL_VERSION_NUMBER >= 0x30000000
          # https://github.com/ruby/openssl/pull/480
          key_object = OpenSSL::PKey::EC.generate(ECDSA_CURVES[bits])
        else
          key_pkey = OpenSSL::PKey::EC.new(ECDSA_CURVES[bits])
          key_object = key_pkey.generate_key
        end

      else
        raise "Unknown key type: #{type}"
      end

      key_pem = key_object.to_pem(cipher, options[:passphrase])
      new(key_pem, options)
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
      sections = unpacked_byte_array(ssh_type, encoded_key)
      case ssh_type
        when "ssh-rsa", "ssh-dss"
          sections.size == SSH_CONVERSION[SSH_TYPES[ssh_type]].size
        when "ssh-ed25519"
          sections.size == 1                                # https://tools.ietf.org/id/draft-bjh21-ssh-ed25519-00.html#rfc.section.4
        when "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521"
          sections.size == 2                                # https://tools.ietf.org/html/rfc5656#section-3.1
        else
          false
      end
    rescue
      false
    end

    # Bits
    #
    # Returns ssh public key bits or false depending on the validity of the public key provided
    #
    # ==== Parameters
    # * ssh_public_key<~String> - "ssh-rsa AAAAB3NzaC1yc2EA...."
    # * ssh_public_key<~String> - "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTY...."
    #
    def ssh_public_key_bits(ssh_public_key)
      ssh_type, encoded_key = parse_ssh_public_key(ssh_public_key)
      sections = unpacked_byte_array(ssh_type, encoded_key)

      case ssh_type
      when "ssh-rsa", "ssh-dss", "ssh-ed25519"
        sections.last.num_bytes * 8

      when "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521"
        raise PublicKeyError, "invalid ECDSA key" unless sections.count == 2

        # https://tools.ietf.org/html/rfc5656#section-3.1
        identifier = sections[0].to_s(2)
        q = sections[1].to_s(2)
        ecdsa_bits(ssh_type, identifier, q)

      else
        raise PublicKeyError, "unsupported key type #{ssh_type}"
      end
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

    # SHA256 fingerprint for the given SSH key
    def sha256_fingerprint(key)
      if key.match(/PRIVATE/)
        new(key).sha256_fingerprint
      else
        Base64.encode64(Digest::SHA256.digest(decoded_key(key))).gsub("\n", "")
      end
    end

    # SSHFP records for the given SSH key
    def sshfp(hostname, key)
      if key.match(/PRIVATE/)
        new(key).sshfp hostname
      else
        type, encoded_key = parse_ssh_public_key(key)
        format_sshfp_record(hostname, SSH_TYPES[type], Base64.decode64(encoded_key))
      end
    end

    # Convert an existing SSH public key to SSH2 (RFC4716) public key
    #
    # ==== Parameters
    # * ssh_public_key<~String> - "ssh-rsa AAAAB3NzaC1yc2EA...."
    # * headers<~Hash> - The Key will be used as the header-tag and the value as the header-value
    #
    def ssh_public_key_to_ssh2_public_key(ssh_public_key, headers = nil)
      raise PublicKeyError, "invalid ssh public key" unless SSHKey.valid_ssh_public_key?(ssh_public_key)

      _source_format, source_key = parse_ssh_public_key(ssh_public_key)

      # Add a 'Comment' Header Field unless others are explicitly passed in
      if source_comment = ssh_public_key.split(source_key)[1]
        headers = {'Comment' => source_comment.strip} if headers.nil? && !source_comment.empty?
      end
      header_fields = build_ssh2_headers(headers)

      ssh2_key = "---- BEGIN SSH2 PUBLIC KEY ----\n"
      ssh2_key << header_fields unless header_fields.nil?
      ssh2_key << source_key.scan(/.{1,#{SSH2_LINE_LENGTH}}/).join("\n")
      ssh2_key << "\n---- END SSH2 PUBLIC KEY ----"
    end

    def format_sshfp_record(hostname, type, key)
      [[Digest::SHA1, 1], [Digest::SHA256, 2]].map { |f, num|
        fpr = f.hexdigest(key)
        "#{hostname} IN SSHFP #{SSHFP_TYPES[type]} #{num} #{fpr}"
      }.join("\n")
    end

    private

    def unpacked_byte_array(ssh_type, encoded_key)
      prefix = [ssh_type.length].pack("N") + ssh_type
      decoded = Base64.decode64(encoded_key)

      # Base64 decoding is too permissive, so we should validate if encoding is correct
      unless Base64.encode64(decoded).gsub("\n", "") == encoded_key && decoded.slice!(0, prefix.length) == prefix
        raise PublicKeyError, "validation error"
      end

      byte_count = 0
      data = []
      until decoded.empty?
        front = decoded.slice!(0,4)
        size = front.unpack("N").first
        segment = decoded.slice!(0, size)
        byte_count += segment.length
        unless front.length == 4 && segment.length == size
          raise PublicKeyError, "byte array too short"
        end
        data << OpenSSL::BN.new(segment, 2)
      end


      if ssh_type == "ssh-ed25519"
        unless byte_count == 32
          raise PublicKeyError, "validation error, ed25519 key length not OK"
        end
      end

      return data
    end

    def ecdsa_bits(ssh_type, identifier, q)
      raise PublicKeyError, "invalid ssh type" unless ssh_type == "ecdsa-sha2-#{identifier}"

      len_q = q.length

      compression_octet = q.slice(0, 1)
      if compression_octet == "\x04"
        # Point compression is off
        # Summary from https://www.secg.org/sec1-v2.pdf "2.3.3  Elliptic-Curve-Point-to-Octet-String Conversion"
        # - the leftmost octet indicates that point compression is off
        #   (first octet 0x04 as specified in "3.3. Output M = 04 base 16 ‖ X ‖ Y.")
        # - the remainder of the octet string contains the x-coordinate followed by the y-coordinate.
        len_x = (len_q - 1) / 2

      else
        # Point compression is on
        # Summary from https://www.secg.org/sec1-v2.pdf "2.3.3  Elliptic-Curve-Point-to-Octet-String Conversion"
        # - the compressed y-coordinate is recovered from the leftmost octet
        # - the x-coordinate is recovered from the remainder of the octet string
        raise PublicKeyError, "invalid compression octet" unless compression_octet == "\x02" || compression_octet == "\x03"
        len_x = len_q - 1
      end

      # https://www.secg.org/sec2-v2.pdf "2.1  Properties of Elliptic Curve Domain Parameters over Fp" defines
      # five discrete bit lengths: 192, 224, 256, 384, 521
      # These bit lengths can be ascertained from the length of the packed x-coordinate.
      # Alternatively, these bit lengths can be derived from their associated prime constants using Math.log2(prime).ceil
      # against the prime constants defined in https://www.secg.org/sec2-v2.pdf
      case len_x
      when 24 then bits = 192
      when 28 then bits = 224
      when 32 then bits = 256
      when 48 then bits = 384
      when 66 then bits = 521
      else
        raise PublicKeyError, "invalid x-coordinate length #{len_x}"
      end

      raise PublicKeyError, "invalid identifier #{identifier}" unless identifier =~ /#{bits}/
      return bits
    end

    def decoded_key(key)
      Base64.decode64(parse_ssh_public_key(key).last)
    end

    def fingerprint_regex
      /(.{2})(?=.)/
    end

    def parse_ssh_public_key(public_key)
      # lines starting with a '#' and empty lines are ignored as comments (as in ssh AuthorizedKeysFile)
      public_key = public_key.gsub(/^#.*$/, '')
      public_key = public_key.strip # leading and trailing whitespaces wiped out

      raise PublicKeyError, "newlines are not permitted between key data" if public_key =~ /\n(?!$)/

      parsed = public_key.split(" ")
      parsed.each_with_index do |el, index|
        return parsed[index..(index+1)] if SSH_TYPES[el]
      end
      raise PublicKeyError, "cannot determine key type"
    end

    def build_ssh2_headers(headers = {})
      return nil if headers.nil? || headers.empty?

      headers.keys.sort.collect do |header_tag|
        # header-tag must be us-ascii & <= 64 bytes and header-data must be UTF-8 & <= 1024 bytes
        raise PublicKeyError, "SSH2 header-tag '#{header_tag}' must be US-ASCII" unless header_tag.each_byte.all? {|b| b < 128 }
        raise PublicKeyError, "SSH2 header-tag '#{header_tag}' must be <= 64 bytes" unless header_tag.size <= 64
        raise PublicKeyError, "SSH2 header-value for '#{header_tag}' must be <= 1024 bytes" unless headers[header_tag].size <= 1024

        header_field = "#{header_tag}: #{headers[header_tag]}"
        header_field.scan(/.{1,#{SSH2_LINE_LENGTH}}/).join("\\\n")
      end.join("\n") << "\n"
    end
  end

  attr_reader :key_object, :type, :typestr
  attr_accessor :passphrase, :comment

  # Create a new SSHKey object
  #
  # ==== Parameters
  # * private_key - Existing RSA or DSA or ECDSA private key
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
      @typestr = "ssh-rsa"
    rescue OpenSSL::PKey::RSAError
      @type = nil
    end

    return if @type

    begin
      @key_object = OpenSSL::PKey::DSA.new(private_key, passphrase)
      @type = "dsa"
      @typestr = "ssh-dss"
    rescue OpenSSL::PKey::DSAError
      @type = nil
    end

    return if @type

    @key_object = OpenSSL::PKey::EC.new(private_key, passphrase)
    @type = "ecdsa"
    bits = ECDSA_CURVES.invert[@key_object.group.curve_name]
    @typestr = "ecdsa-sha2-nistp#{bits}"
  end

  # Fetch the private key (PEM format)
  #
  # rsa_private_key and dsa_private_key are aliased for backward compatibility
  def private_key
    # jruby-openssl OpenSSL::PKey::EC support isn't complete
    # https://github.com/jruby/jruby-openssl/issues/189
    jruby_not_implemented("OpenSSL::PKey::EC is not fully implemented") if type == "ecdsa"

    key_object.to_pem
  end
  alias_method :rsa_private_key, :private_key
  alias_method :dsa_private_key, :private_key

  # Fetch the encrypted RSA/DSA private key using the passphrase provided
  #
  # If no passphrase is set, returns the unencrypted private key
  def encrypted_private_key
    return private_key unless passphrase
    key_object.to_pem(OpenSSL::Cipher.new("AES-128-CBC"), passphrase)
  end

  # Fetch the public key (PEM format)
  #
  # rsa_public_key and dsa_public_key are aliased for backward compatibility
  def public_key
    public_key_object.to_pem
  end
  alias_method :rsa_public_key, :public_key
  alias_method :dsa_public_key, :public_key

  def public_key_object
    if type == "ecdsa"
      return nil unless key_object
      return nil unless key_object.group

      if OpenSSL::OPENSSL_VERSION_NUMBER >= 0x30000000 && RUBY_PLATFORM != "java"

        # jruby-openssl does not currently support point_conversion_form
        # (futureproofing for if/when JRuby requires this technique to determine public key)
        jruby_not_implemented("point_conversion_form is not implemented")

        # Avoid "OpenSSL::PKey::PKeyError: pkeys are immutable on OpenSSL 3.0"
        # https://github.com/ruby/openssl/blob/master/History.md#version-300
        # https://github.com/ruby/openssl/issues/498
        # https://github.com/net-ssh/net-ssh/commit/4de6831dea4e922bf3052192eec143af015a3486
        # https://github.com/ClearlyClaire/cose-ruby/commit/28ee497fa7d9d49e72d5a5e97a567c0b58fdd822

        curve_name = key_object.group.curve_name
        return nil unless curve_name

        # Map to different curve_name for JRuby
        # (futureproofing for if/when JRuby requires this technique to determine public key)
        # https://github.com/jwt/ruby-jwt/issues/362#issuecomment-722938409
        curve_name = "prime256v1" if curve_name == "secp256r1" && RUBY_PLATFORM == "java"

        # Construct public key OpenSSL::PKey::EC from OpenSSL::PKey::EC::Point
        public_key_point = key_object.public_key  # => OpenSSL::PKey::EC::Point
        return nil unless public_key_point

        asn1 = OpenSSL::ASN1::Sequence(
          [
            OpenSSL::ASN1::Sequence(
              [
                OpenSSL::ASN1::ObjectId("id-ecPublicKey"),
                OpenSSL::ASN1::ObjectId(curve_name)
              ]
            ),
            OpenSSL::ASN1::BitString(public_key_point.to_octet_string(key_object.group.point_conversion_form))
          ]
        )

        pub = OpenSSL::PKey::EC.new(asn1.to_der)
        pub

      else
        pub = OpenSSL::PKey::EC.new(key_object.group)
        pub.public_key = key_object.public_key
        pub
      end

    else
      key_object.public_key
    end
  end

  # SSH public key
  def ssh_public_key
    [directives.join(",").strip, typestr, Base64.encode64(ssh_public_key_conversion).gsub("\n", ""), comment].join(" ").strip
  end

  # SSH2 public key (RFC4716)
  #
  # ==== Parameters
  # * headers<~Hash> - Keys will be used as header-tags and values as header-values.
  #
  # ==== Examples
  # {'Comment' => '2048-bit RSA created by user@example'}
  # {'x-private-use-tag' => 'Private Use Value'}
  #
  def ssh2_public_key(headers = nil)
    self.class.ssh_public_key_to_ssh2_public_key(ssh_public_key, headers)
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

  # SHA256 fingerprint for the given SSH public key
  def sha256_fingerprint
    Base64.encode64(Digest::SHA256.digest(ssh_public_key_conversion)).gsub("\n", "")
  end

  # Determine the length (bits) of the key as an integer
  def bits
    self.class.ssh_public_key_bits(ssh_public_key)
  end

  # Randomart
  #
  # Generate OpenSSH compatible ASCII art fingerprints
  # See http://www.opensource.apple.com/source/OpenSSH/OpenSSH-175/openssh/key.c (key_fingerprint_randomart function)
  # or https://mirrors.mit.edu/pub/OpenBSD/OpenSSH/ (sshkey.c fingerprint_randomart function)
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
  def randomart(dgst_alg = "MD5")
    fieldsize_x = 17
    fieldsize_y = 9
    x = fieldsize_x / 2
    y = fieldsize_y / 2

    case dgst_alg
      when "MD5"    then raw_digest = Digest::MD5.digest(ssh_public_key_conversion)
      when "SHA256" then raw_digest = Digest::SHA2.new(256).digest(ssh_public_key_conversion)
      when "SHA384" then raw_digest = Digest::SHA2.new(384).digest(ssh_public_key_conversion)
      when "SHA512" then raw_digest = Digest::SHA2.new(512).digest(ssh_public_key_conversion)
    else
      raise "Unknown digest algorithm: #{digest}"
    end

    augmentation_string = " .o+=*BOX@%&#/^SE"
    len = augmentation_string.length - 1

    field = Array.new(fieldsize_x) { Array.new(fieldsize_y) {0} }

    raw_digest.bytes.each do |byte|
      4.times do
        x += (byte & 0x1 != 0) ? 1 : -1
        y += (byte & 0x2 != 0) ? 1 : -1

        x = [[x, 0].max, fieldsize_x - 1].min
        y = [[y, 0].max, fieldsize_y - 1].min

        field[x][y] += 1 if (field[x][y] < len - 2)

        byte >>= 2
      end
    end

    fieldsize_x_halved = fieldsize_x / 2
    fieldsize_y_halved = fieldsize_y / 2

    field[fieldsize_x_halved][fieldsize_y_halved] = len - 1
    field[x][y] = len

    type_name_length_max = 4  # Note: this will need to be extended to accomodate ed25519
    bits_number_length_max = (bits < 1000 ? 3 : 4)
    formatstr = "[%#{type_name_length_max}s %#{bits_number_length_max}u]"
    output = "+--#{sprintf(formatstr, type.upcase, bits)}----+\n"

    fieldsize_y.times do |y|
      output << "|"
      fieldsize_x.times do |x|
        output << augmentation_string[[field[x][y], len].min]
      end
      output << "|"
      output << "\n"
    end
    output << "+#{"-" * fieldsize_x}+"
    output
  end

  def sshfp(hostname)
    self.class.format_sshfp_record(hostname, @type, ssh_public_key_conversion)
  end

  def directives=(directives)
    @directives = Array[directives].flatten.compact
  end
  attr_reader :directives

  private

  def self.ssh_public_key_data_dsarsa(val)
    # Get byte-representation of absolute value of val
    data = val.to_s(2)

    first_byte = data[0,1].unpack("c").first
    if val < 0
      # For negative values, highest bit must be set
      data[0] = [0x80 & first_byte].pack("c")
    elsif first_byte < 0
      # For positive values where highest bit would be set, prefix with \0
      data = "\0" + data
    end

    data
  end

  def self.ssh_public_key_data_ecdsa(val)
    val
  end

  # SSH Public Key Conversion
  #
  # All data type encoding is defined in the section #5 of RFC #4251.
  # String and mpint (multiple precision integer) types are encoded this way:
  # 4-bytes word: data length (unsigned big-endian 32 bits integer)
  # n bytes: binary representation of the data

  # For instance, the "ssh-rsa" string is encoded as the following byte array
  # [0, 0, 0, 7, 's', 's', 'h', '-', 'r', 's', 'a']
  def ssh_public_key_conversion
    methods = SSH_CONVERSION[type]
    methods.inject([typestr.length].pack("N") + typestr) do |pubkeystr, m|
      # Given public_key_object.class == OpenSSL::BN, public_key_object.to_s(0)
      # returns an MPI formatted string (length prefixed bytes). This is not
      # supported by JRuby, so we still have to deal with length and data separately.
      val = public_key_object.send(m)

      case type
      when "dsa","rsa" then data = self.class.ssh_public_key_data_dsarsa(val)
      when "ecdsa"     then data = self.class.ssh_public_key_data_ecdsa(val)
      else
        raise "Unknown key type: #{type}"
      end

      pubkeystr + [data.length].pack("N") + data
    end
  end

  class PublicKeyError < StandardError; end
end
