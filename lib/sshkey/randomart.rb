class SSHKey
  # Number of bits in private key
  def size
    # TODO implement this correctly
    type == "rsa" ? 2048 : 1024
  end

  # Randomart fingerprint visualization compatible with OpenSSH
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
    output = "+--#{sprintf("[%4s %4u]", type.upcase, size)}----+\n"
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
end
