# frozen_string_literal: true

class SSHKey
  # Reads and writes unencrypted private keys in the OpenSSH format
  # ("-----BEGIN OPENSSH PRIVATE KEY-----"), the default output of ssh-keygen.
  #
  # https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.key
  module OpenSSHPrivateKey
    BEGIN_LABEL = "-----BEGIN OPENSSH PRIVATE KEY-----"
    END_LABEL = "-----END OPENSSH PRIVATE KEY-----"
    MAGIC = "openssh-key-v1\0".b
    BLOCK_SIZE = 8   # cipher block size for "none"
    LINE_LENGTH = 70  # matches ssh-keygen

    # DER prefix for a PKCS#8 Ed25519 private key, followed by the 32-byte seed (RFC 8410)
    ED25519_PKCS8_PREFIX = ["302e020100300506032b657004220420"].pack("H*")

    class Reader
      def initialize(data)
        @data = data
        @pos = 0
      end

      def read(length)
        raise PrivateKeyError, "truncated OpenSSH private key" if @pos + length > @data.bytesize
        @data.byteslice(@pos, length).tap { @pos += length }
      end

      def uint32 = read(4).unpack1("N")
      def string = read(uint32)
      def mpint = OpenSSL::BN.new(string, 2)
    end
    private_constant :Reader

    module_function

    def openssh_private_key?(str)
      str.include?(BEGIN_LABEL)
    end

    # Returns [OpenSSL::PKey, comment]
    def decode(str)
      body = str[/#{BEGIN_LABEL}(.*?)#{END_LABEL}/mo, 1]
      raise PrivateKeyError, "malformed OpenSSH private key" unless body

      reader = Reader.new(body.unpack1("m"))
      raise PrivateKeyError, "malformed OpenSSH private key" unless reader.read(MAGIC.bytesize) == MAGIC

      unless reader.string == "none"
        raise UnsupportedError, "passphrase-protected OpenSSH private keys are not supported; " \
          "remove the passphrase with `ssh-keygen -p -N \"\" -f <file>`, or convert an RSA/ECDSA key " \
          "to PEM with `ssh-keygen -p -m PEM -f <file>`"
      end
      reader.string # kdfname
      reader.string # kdfoptions
      raise UnsupportedError, "multiple keys per file are not supported" unless reader.uint32 == 1
      reader.string # public key

      private_section = Reader.new(reader.string)
      checkint1 = private_section.uint32
      checkint2 = private_section.uint32
      raise PrivateKeyError, "corrupt OpenSSH private key" unless checkint1 == checkint2

      key = read_private_key(private_section)
      comment = private_section.string.force_encoding(Encoding::UTF_8)
      [key, comment]
    end

    # Unencrypted OpenSSH private key for an SSHKey
    def encode(sshkey, public_blob)
      key = sshkey.key_object
      # ECDSA and Ed25519 private sections repeat the public key fields
      public_fields = public_blob.byteslice((4 + sshkey.typestr.bytesize)..)

      fields =
        case sshkey.type
        when "rsa" then [key.n, key.e, key.d, key.iqmp, key.p, key.q].map { |bn| bn.to_s(0) }.join
        when "dsa" then [key.p, key.q, key.g, key.pub_key, key.priv_key].map { |bn| bn.to_s(0) }.join
        when "ecdsa" then public_fields + key.private_key.to_s(0)
        when "ed25519" then public_fields + ssh_string(key.raw_private_key + key.raw_public_key)
        end

      checkint = OpenSSL::Random.random_bytes(4)
      private_section = checkint + checkint + ssh_string(sshkey.typestr) + fields + ssh_string(sshkey.comment)
      padding = (BLOCK_SIZE - private_section.bytesize % BLOCK_SIZE) % BLOCK_SIZE
      private_section += (1..padding).to_a.pack("C*")

      blob = MAGIC +
        ssh_string("none") + # ciphername
        ssh_string("none") + # kdfname
        ssh_string("") +     # kdfoptions
        [1].pack("N") +      # number of keys
        ssh_string(public_blob) +
        ssh_string(private_section)

      [BEGIN_LABEL, *[blob].pack("m0").scan(/.{1,#{LINE_LENGTH}}/o), END_LABEL, ""].join("\n")
    end

    # Rebuild the OpenSSL key from its OpenSSH private key fields
    def read_private_key(reader)
      case (type = reader.string)
      when "ssh-rsa"
        n, e, d, iqmp, p, q = Array.new(6) { reader.mpint }
        OpenSSL::PKey::RSA.new(der_integers(0, n, e, d, p, q, d % (p - 1), d % (q - 1), iqmp))
      when "ssh-dss"
        OpenSSL::PKey::DSA.new(der_integers(0, *Array.new(5) { reader.mpint }))
      when "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521"
        identifier = reader.string
        curve = ECDSA_IDENTIFIERS.key(identifier) or raise UnsupportedError, "unsupported curve: #{identifier}"
        point = reader.string
        d = reader.mpint
        field_bytes = (OpenSSL::PKey::EC::Group.new(curve).degree + 7) / 8
        # ECPrivateKey (RFC 5915)
        OpenSSL::PKey::EC.new(OpenSSL::ASN1::Sequence([
          OpenSSL::ASN1::Integer(1),
          OpenSSL::ASN1::OctetString(d.to_s(2).rjust(field_bytes, "\0".b)),
          OpenSSL::ASN1::ObjectId(curve, 0, :EXPLICIT),
          OpenSSL::ASN1::BitString(point, 1, :EXPLICIT)
        ]).to_der)
      when "ssh-ed25519"
        reader.string # public key
        OpenSSL::PKey.read(ED25519_PKCS8_PREFIX + reader.string.byteslice(0, 32))
      else
        raise UnsupportedError, "unsupported OpenSSH private key type: #{type}"
      end
    end

    def der_integers(*values)
      OpenSSL::ASN1::Sequence(values.map { |v| OpenSSL::ASN1::Integer(v) }).to_der
    end

    def ssh_string(str)
      [str.bytesize].pack("N") + str.b
    end
  end
  private_constant :OpenSSHPrivateKey
end
