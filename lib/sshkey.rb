# frozen_string_literal: true

require "openssl"
require "digest"
require_relative "sshkey/version"
require_relative "sshkey/openssh_private_key"

class SSHKey
  class Error < StandardError; end
  class PublicKeyError < Error; end
  class PrivateKeyError < Error; end
  class UnsupportedError < Error; end

  SSH_TYPES = {
    "ssh-rsa" => "rsa",
    "ssh-dss" => "dsa",
    "ssh-ed25519" => "ed25519",
    "ecdsa-sha2-nistp256" => "ecdsa",
    "ecdsa-sha2-nistp384" => "ecdsa",
    "ecdsa-sha2-nistp521" => "ecdsa",
  }.freeze

  SSHFP_TYPES = {
    "rsa"     => 1,
    "dsa"     => 2,
    "ecdsa"   => 3,
    "ed25519" => 4,
  }.freeze

  ECDSA_CURVES = {
    256 => "prime256v1",  # https://stackoverflow.com/a/41953717
    384 => "secp384r1",
    521 => "secp521r1",
  }.freeze

  # OpenSSL curve name => SSH curve identifier (RFC 5656 section 10.1)
  ECDSA_IDENTIFIERS = {
    "prime256v1" => "nistp256",
    "secp256r1"  => "nistp256",
    "secp384r1"  => "nistp384",
    "secp521r1"  => "nistp521",
  }.freeze

  VALID_BITS = {
    "ecdsa"   => ECDSA_CURVES.keys,
    "ed25519" => [256],
  }.freeze

  DEFAULT_BITS = {
    "rsa"     => 3072,
    "ecdsa"   => 256,
    "ed25519" => 256,
  }.freeze

  RANDOMART_DIGESTS = {
    "MD5"    => Digest::MD5,
    "SHA256" => Digest::SHA256,
    "SHA384" => Digest::SHA384,
    "SHA512" => Digest::SHA512,
  }.freeze

  SSH2_LINE_LENGTH = 70 # +1 (for line wrap '/' character) must be <= 72

  PRIVATE_KEY_PATTERN = /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----/

  private_constant :SSHFP_TYPES, :ECDSA_CURVES, :ECDSA_IDENTIFIERS, :VALID_BITS, :DEFAULT_BITS,
    :RANDOMART_DIGESTS, :SSH2_LINE_LENGTH, :PRIVATE_KEY_PATTERN

  # Fingerprint and SSHFP formatting shared by the class and instance methods
  module Fingerprint
    module_function

    def md5(blob)
      Digest::MD5.hexdigest(blob).scan(/../).join(":")
    end

    def sha1(blob)
      Digest::SHA1.hexdigest(blob).scan(/../).join(":")
    end

    def sha256(blob)
      [Digest::SHA256.digest(blob)].pack("m0").delete("=")
    end

    def sshfp(hostname, type, blob)
      [[Digest::SHA1, 1], [Digest::SHA256, 2]].map { |digest, num|
        "#{hostname} IN SSHFP #{SSHFP_TYPES[type]} #{num} #{digest.hexdigest(blob)}"
      }.join("\n")
    end
  end
  private_constant :Fingerprint

  class << self
    # Generate a new keypair and return an SSHKey object
    #
    # ==== Parameters
    # * type - "ed25519", "ecdsa" or "rsa" (or a Symbol), required
    # * bits - Bit length; RSA defaults to 3072, ECDSA to 256 (256, 384 or 521)
    # * comment - Comment to use for the public key, defaults to ""
    # * passphrase - Passphrase used by #encrypted_private_key
    # * directives - Options prefixed to the public key
    #
    def generate(type: nil, bits: nil, comment: nil, passphrase: nil, directives: nil)
      raise ArgumentError, 'type: is required: "ed25519" (the ssh-keygen default), "ecdsa" or "rsa"' if type.nil?

      type = type.to_s.downcase
      if type == "dsa"
        raise ArgumentError, "generating DSA keys is not supported: OpenSSH no longer supports DSA"
      end
      raise ArgumentError, "unknown key type: #{type}" unless DEFAULT_BITS.key?(type)

      bits ||= DEFAULT_BITS[type]
      if VALID_BITS[type] && !VALID_BITS[type].include?(bits)
        raise ArgumentError, "bits must be one of: #{VALID_BITS[type].join(', ')}"
      end

      key_object =
        case type
        when "rsa"     then OpenSSL::PKey::RSA.generate(bits)
        when "ecdsa"   then OpenSSL::PKey::EC.generate(ECDSA_CURVES[bits])
        when "ed25519" then OpenSSL::PKey.generate_key("ED25519")
        end

      new(key_object, comment: comment, passphrase: passphrase, directives: directives)
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
      when "ssh-rsa"
        sections.size == 2                                  # e, n
      when "ssh-dss"
        sections.size == 4                                  # p, q, g, pub_key
      when "ssh-ed25519"
        sections.size == 1                                  # https://tools.ietf.org/id/draft-bjh21-ssh-ed25519-00.html#rfc.section.4
      when "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521"
        sections.size == 2                                  # https://tools.ietf.org/html/rfc5656#section-3.1
      else
        false
      end
    rescue StandardError
      false
    end

    # Bits
    #
    # Returns the bit length of the SSH public key, or raises PublicKeyError if it is invalid
    #
    # ==== Parameters
    # * ssh_public_key<~String> - "ssh-rsa AAAAB3NzaC1yc2EA...."
    # * ssh_public_key<~String> - "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTY...."
    #
    def ssh_public_key_bits(ssh_public_key)
      ssh_type, encoded_key = parse_ssh_public_key(ssh_public_key)
      sections = unpacked_byte_array(ssh_type, encoded_key)

      case ssh_type
      when "ssh-rsa"
        sections.last.num_bits   # n

      when "ssh-dss"
        sections.first.num_bits  # p

      when "ssh-ed25519"
        256

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
      private_key?(key) ? new(key).md5_fingerprint : Fingerprint.md5(decoded_key(key))
    end

    # SHA1 fingerprint for the given SSH key
    def sha1_fingerprint(key)
      private_key?(key) ? new(key).sha1_fingerprint : Fingerprint.sha1(decoded_key(key))
    end

    # SHA256 fingerprint for the given SSH key
    def sha256_fingerprint(key)
      private_key?(key) ? new(key).sha256_fingerprint : Fingerprint.sha256(decoded_key(key))
    end

    # SSHFP records for the given SSH key
    def sshfp(hostname, key)
      if private_key?(key)
        new(key).sshfp hostname
      else
        type, encoded_key = parse_ssh_public_key(key)
        Fingerprint.sshfp(hostname, SSH_TYPES[type], encoded_key.unpack1("m"))
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
      if (source_comment = ssh_public_key.split(source_key)[1])
        headers = {"Comment" => source_comment.strip} if headers.nil? && !source_comment.empty?
      end

      [
        "---- BEGIN SSH2 PUBLIC KEY ----",
        *build_ssh2_headers(headers),
        *source_key.scan(/.{1,#{SSH2_LINE_LENGTH}}/o),
        "---- END SSH2 PUBLIC KEY ----",
      ].join("\n")
    end

    private

    def private_key?(key)
      key.match?(PRIVATE_KEY_PATTERN)
    end

    def unpacked_byte_array(ssh_type, encoded_key)
      prefix = [ssh_type.bytesize].pack("N") + ssh_type
      decoded = encoded_key.unpack1("m")

      # Base64 decoding is too permissive, so we should validate if encoding is correct
      unless [decoded].pack("m0") == encoded_key && decoded.start_with?(prefix)
        raise PublicKeyError, "validation error"
      end

      data = decoded.byteslice(prefix.bytesize..)
      byte_count = 0
      sections = []
      until data.empty?
        size = data.unpack1("N") if data.bytesize >= 4
        segment = data.byteslice(4, size) if size
        raise PublicKeyError, "byte array too short" unless segment && segment.bytesize == size

        byte_count += size
        sections << OpenSSL::BN.new(segment, 2)
        data = data.byteslice((4 + size)..)
      end

      if ssh_type == "ssh-ed25519" && byte_count != 32
        raise PublicKeyError, "validation error, ed25519 key length not OK"
      end

      sections
    end

    def ecdsa_bits(ssh_type, identifier, q)
      raise PublicKeyError, "invalid ssh type" unless ssh_type == "ecdsa-sha2-#{identifier}"

      len_q = q.bytesize

      compression_octet = q.getbyte(0)
      if compression_octet == 0x04
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
        raise PublicKeyError, "invalid compression octet" unless compression_octet == 0x02 || compression_octet == 0x03
        len_x = len_q - 1
      end

      # https://www.secg.org/sec2-v2.pdf "2.1  Properties of Elliptic Curve Domain Parameters over Fp" defines
      # five discrete bit lengths: 192, 224, 256, 384, 521
      # These bit lengths can be ascertained from the length of the packed x-coordinate.
      # Alternatively, these bit lengths can be derived from their associated prime constants using Math.log2(prime).ceil
      # against the prime constants defined in https://www.secg.org/sec2-v2.pdf
      bits =
        case len_x
        when 24 then 192
        when 28 then 224
        when 32 then 256
        when 48 then 384
        when 66 then 521
        else
          raise PublicKeyError, "invalid x-coordinate length #{len_x}"
        end

      raise PublicKeyError, "invalid identifier #{identifier}" unless identifier.include?(bits.to_s)
      bits
    end

    def decoded_key(key)
      parse_ssh_public_key(key).last.unpack1("m")
    end

    def parse_ssh_public_key(public_key)
      # lines starting with a '#' and empty lines are ignored as comments (as in ssh AuthorizedKeysFile)
      public_key = public_key.gsub(/^#.*$/, "").strip

      raise PublicKeyError, "newlines are not permitted between key data" if public_key.match?(/\n(?!$)/)

      parsed = public_key.split(" ")
      index = parsed.index { |el| SSH_TYPES.key?(el) }
      raise PublicKeyError, "cannot determine key type" unless index

      parsed[index, 2]
    end

    def build_ssh2_headers(headers)
      return [] if headers.nil? || headers.empty?

      headers.keys.sort.map do |header_tag|
        # header-tag must be us-ascii & <= 64 bytes and header-data must be UTF-8 & <= 1024 bytes
        raise PublicKeyError, "SSH2 header-tag '#{header_tag}' must be US-ASCII" unless header_tag.ascii_only?
        raise PublicKeyError, "SSH2 header-tag '#{header_tag}' must be <= 64 bytes" unless header_tag.size <= 64
        raise PublicKeyError, "SSH2 header-value for '#{header_tag}' must be <= 1024 bytes" unless headers[header_tag].size <= 1024

        "#{header_tag}: #{headers[header_tag]}".scan(/.{1,#{SSH2_LINE_LENGTH}}/o).join("\\\n")
      end
    end
  end

  attr_reader :key_object, :type, :typestr, :directives
  attr_accessor :passphrase, :comment

  # Create a new SSHKey object
  #
  # ==== Parameters
  # * private_key - Existing RSA, DSA, ECDSA or Ed25519 private key, as a PEM or OpenSSH
  #   format string, or as an OpenSSL::PKey object
  # * comment - Comment to use for the public key, defaults to the comment stored in
  #   an OpenSSH format key, or ""
  # * passphrase - Passphrase for an encrypted PEM key
  # * directives - Options prefixed to the public key
  #
  def initialize(private_key, comment: nil, passphrase: nil, directives: nil)
    @passphrase = passphrase
    self.directives = directives

    @key_object, stored_comment = load_private_key(private_key)
    @comment = comment || stored_comment || ""

    @type, @typestr =
      case @key_object
      when OpenSSL::PKey::RSA then ["rsa", "ssh-rsa"]
      when OpenSSL::PKey::DSA then ["dsa", "ssh-dss"]
      when OpenSSL::PKey::EC  then ["ecdsa", "ecdsa-sha2-#{ecdsa_identifier}"]
      else
        raise UnsupportedError, "unsupported key type: #{@key_object.oid}" unless @key_object.oid == "ED25519"
        ["ed25519", "ssh-ed25519"]
      end
  end

  # Fetch the private key
  #
  # RSA, DSA and ECDSA keys are returned in PEM format. Ed25519 keys are returned in
  # OpenSSH format, since OpenSSH does not read Ed25519 keys in PEM format.
  def private_key
    type == "ed25519" ? openssh_private_key : key_object.to_pem
  end

  # Fetch the private key encrypted with the passphrase, in PKCS#8 PEM format
  # ("-----BEGIN ENCRYPTED PRIVATE KEY-----", AES-256-CBC with a PBKDF2-derived key)
  #
  # If no passphrase is set, returns the unencrypted private key
  #
  # Encrypting Ed25519 keys is not supported: OpenSSH only reads them in OpenSSH format,
  # which is encrypted with bcrypt_pbkdf, and OpenSSL does not provide it.
  def encrypted_private_key
    return private_key unless passphrase
    raise UnsupportedError, "encrypting Ed25519 private keys is not supported" if type == "ed25519"
    key_object.private_to_pem(OpenSSL::Cipher.new("aes-256-cbc"), passphrase)
  end

  # Fetch the unencrypted private key in OpenSSH format ("-----BEGIN OPENSSH PRIVATE KEY-----"),
  # as written by ssh-keygen
  def openssh_private_key
    OpenSSHPrivateKey.encode(self, public_key_blob)
  end

  # Fetch the public key (PEM format)
  def public_key
    key_object.public_to_pem
  end

  # Public-only OpenSSL::PKey object for this key
  def public_key_object
    OpenSSL::PKey.read(key_object.public_to_der)
  end

  # SSH public key
  def ssh_public_key
    [directives.join(",").strip, typestr, [public_key_blob].pack("m0"), comment].join(" ").strip
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
    Fingerprint.md5(public_key_blob)
  end

  # SHA1 fingerprint for the given SSH public key
  def sha1_fingerprint
    Fingerprint.sha1(public_key_blob)
  end

  # SHA256 fingerprint for the given SSH public key
  def sha256_fingerprint
    Fingerprint.sha256(public_key_blob)
  end

  # Determine the length (bits) of the key as an integer
  def bits
    case type
    when "rsa"     then key_object.n.num_bits
    when "dsa"     then key_object.p.num_bits
    when "ecdsa"   then key_object.group.degree
    when "ed25519" then 256
    end
  end

  # Randomart
  #
  # Generate OpenSSH compatible ASCII art fingerprints, matching `ssh-keygen -lv`
  # See https://github.com/openssh/openssh-portable/blob/master/sshkey.c (fingerprint_randomart function)
  #
  # ==== Parameters
  # * digest - "SHA256" (default), "MD5", "SHA384" or "SHA512"
  #
  # Example:
  # +---[RSA 2048]----+
  # | ..              |
  # |.=.              |
  # |=+=   .          |
  # |#= . o .         |
  # |#*oo+ o S        |
  # |BB+o+o           |
  # |.*.=.            |
  # |o o.+o +E        |
  # |.. +o.*.         |
  # +----[SHA256]-----+
  def randomart(digest = "SHA256")
    digest = digest.to_s.upcase
    digest_class = RANDOMART_DIGESTS.fetch(digest) { raise ArgumentError, "unknown digest algorithm: #{digest}" }

    fieldsize_x = 17
    fieldsize_y = 9
    x = fieldsize_x / 2
    y = fieldsize_y / 2

    augmentation_string = " .o+=*BOX@%&#/^SE"
    len = augmentation_string.length - 1

    field = Array.new(fieldsize_x) { Array.new(fieldsize_y, 0) }

    digest_class.digest(public_key_blob).each_byte do |byte|
      4.times do
        x += (byte & 0x1 != 0) ? 1 : -1
        y += (byte & 0x2 != 0) ? 1 : -1

        x = x.clamp(0, fieldsize_x - 1)
        y = y.clamp(0, fieldsize_y - 1)

        field[x][y] += 1 if field[x][y] < len - 2

        byte >>= 2
      end
    end

    field[fieldsize_x / 2][fieldsize_y / 2] = len - 1
    field[x][y] = len

    rows = Array.new(fieldsize_y) do |row|
      "|" + Array.new(fieldsize_x) { |col| augmentation_string[[field[col][row], len].min] }.join + "|"
    end

    [
      "+#{"[#{type.upcase} #{bits}]".center(fieldsize_x, '-')}+",
      *rows,
      "+#{"[#{digest}]".center(fieldsize_x, '-')}+",
    ].join("\n")
  end

  # SSHFP records for the given hostname
  def sshfp(hostname)
    Fingerprint.sshfp(hostname, type, public_key_blob)
  end

  def directives=(directives)
    @directives = Array[directives].flatten.compact
  end

  private

  # Returns [OpenSSL::PKey, comment stored in the key or nil]
  def load_private_key(private_key)
    return private_key if private_key.is_a?(OpenSSL::PKey::PKey)
    return OpenSSHPrivateKey.decode(private_key) if OpenSSHPrivateKey.openssh_private_key?(private_key)

    # Always pass a passphrase: with nil, OpenSSL prompts for one on the terminal
    OpenSSL::PKey.read(private_key, passphrase || "")
  rescue OpenSSL::PKey::PKeyError => e
    hint = " (incorrect or missing passphrase?)" if private_key.include?("ENCRYPTED")
    raise PrivateKeyError, "could not read private key: #{e.message}#{hint}"
  end

  def ecdsa_identifier
    curve_name = key_object.group.curve_name
    ECDSA_IDENTIFIERS.fetch(curve_name) { raise UnsupportedError, "unsupported curve: #{curve_name}" }
  end

  # SSH Public Key Conversion
  #
  # All data type encoding is defined in the section #5 of RFC #4251.
  # String and mpint (multiple precision integer) types are encoded this way:
  # 4-bytes word: data length (unsigned big-endian 32 bits integer)
  # n bytes: binary representation of the data
  #
  # For instance, the "ssh-rsa" string is encoded as the following byte array
  # [0, 0, 0, 7, 's', 's', 'h', '-', 'r', 's', 'a']
  #
  # OpenSSL::BN#to_s(0) returns exactly this encoding for mpints.
  def public_key_blob
    @public_key_blob ||= begin
      fields =
        case type
        when "rsa"
          [key_object.e, key_object.n].map { |bn| bn.to_s(0) }
        when "dsa"
          [key_object.p, key_object.q, key_object.g, key_object.pub_key].map { |bn| bn.to_s(0) }
        when "ecdsa"
          point = key_object.public_key.to_octet_string(key_object.group.point_conversion_form)
          [ssh_string(ecdsa_identifier), ssh_string(point)]
        when "ed25519"
          [ssh_string(key_object.raw_public_key)]
        end

      ssh_string(typestr) + fields.join
    end
  end

  def ssh_string(str)
    [str.bytesize].pack("N") + str.b
  end
end
