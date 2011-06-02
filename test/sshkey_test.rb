require 'test/unit'
require 'sshkey'

class SSHKeyTest < Test::Unit::TestCase
  SSH_PRIVATE_KEY1 = <<-EOF
-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEArfTA/lKVR84IMc9ZzXOCHr8DVtR8hzWuEVHF6KElavRHlk14
g0SZu3m908Ejm/XF3EfNHjX9wN+62IMA0QBxkBMFCuLF+U/oeUs0NoDdAEKxjj4n
6lq6Ss8aLct+anMy7D1jwvOLbcwV54w1d5JDdlZVdZ6AvHm9otwJq6rNpDgdmXY4
HgC2nM9csFpuy0cDpL6fdJx9lcNL2RnkRC4+RMsIB+PxDw0j3vDi04dYLBXMGYjy
eGH+mIFpL3PTPXGXwL2XDYXZ2H4SQX6bOoKmazTXq6QXuEB665njh1GxXldoIMcS
shoJL0hrk3WrTOG22N2CQA+IfHgrXJ+A+QUzKQIBIwKCAQBAnLy2O+5N3s/X/I8R
y9E+nrgY79Z7XRTEmrc5JelTnI+eOggwwbVxhP1dR7zE5kItPz2O4NqYGJXbY9u7
V++qiri65oQMJP6Tc7ROwiYzS/jObtugMFPSpLHzwJyrMho6fTOuz3zuRH0qHiJ8
3o4WAs9I8brJqY+UQxmI56t3gfHcX4nRhueyUvmEdDG+4Mob21wED1GD5ENh9ebX
UiuYkeROqd+lfBUkWoxUXi2fjRMSRt7n3bq59pyZQCwKiShIVaonciV8xAAlNvhI
RBzYvXbQ47YgsTmcW4Srlv0j/Oij2/RaDhkJtaXyPkqw9k4B8oCaX3C2x4sdhcwa
iLU7AoGBANb4Rmz1w4wfZSnu/HlW4G0Us+AWVEX+6zePoOartP5Pe5t3XhHW7vpi
YoB4ecqhz4Y1LoYZL07cSsQZHfntUV4eh/apuo/5slrhDkk0ewJkUh6SKLOFNv6Q
7iJnmtzzRovW1MQPa0NeInsUrZYe4B4iGZmK4yEr9+c7IQCPFQvVAoGBAM8ofVgb
gzDYY2uX1lvU9bGAHqA/qNJHcYZBu5AZr7bkZC1GlSKh93ppczdQhiZmj2FQr09R
Z5GgKIlSWk8MYC+kYq7l5r2O42g3Unp+i1Zc5KCYUWYpyeE/jfl5IFJFQJFVtdB1
JlsFxruQIF/HuTzY6D+zF8GzK/T5ZQwigBgFAoGAGJFnImU663FNY+DMZaOHXOxs
VB/PHfE/dBBqKP2uSPMkEcR/x4ZHMo7mr5i9dj5g3CNVxi7Dk/vrSZx4dFWi5i9f
/u7TfisqU4dvWNLMOsmi/C32BeNWvgHvVGOcq4mEZ8DH2+SBSYcZ4i4/uWKdRUW5
yGek7dkjpWXX4s6GD/sCgYEAiCHr+BIUYe1Ipcotx1FuQXFzNhs0bO0et0/EZgJA
RPx8WERTX+bHMy9aV4yv7VlW6C21CDzPB+zncC7NoakMAgzwZE3vZp+6AqgDAAoD
ywnYEcMuLTFnaCJzPYocjdW8t0bz0iEZNIAjgpHpY4M/Np0q6Af5qyyZOpVCZw9b
fX8CgYEAqFpBwetp78UfwvWyKkfN56cY8EaC7gMkwE4gnXsByrqW0f/Shf5ofpO1
kCMav5GhplRYcF3mUO9xiAPx1FxWj/MjeevkmmugIrcYi5OpGu70KoaBmCmb5uV6
zJLsX4h3i0JFdIOaECZEOXhPA7btQT8Vvznj8cHFeeronqdFWf0=
-----END RSA PRIVATE KEY-----
EOF
  SSH_PRIVATE_KEY2 = <<-EOF
-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAxl6TpN7uFiY/JZ8qDnD7UrxDP+ABeh2PVg8Du1LEgXNk0+YW
CeP5S6oHklqaWeDlbmAs1oHsBwCMAVpMa5tgONOLvz4JgwgkiqQEbKR8ofWJ+LAD
UElvqRVGmGiNEMLI6GJWeneL4sjmbb8d6U+M53c6iWG0si9XE5m7teBQSsCl0Tk3
qMIkQGw5zpJeCXjZ8KpJhIJRYgexFkGgPlYRV+UYIhxpUW90t0Ra5i6JOFYwq98k
5S/6SJIZQ/A9F4JNzwLw3eVxZj0yVHWxkGz1+TyELNY1kOyMxnZaqSfGzSQJTrnI
XpdweVHuYh1LtOgedRQhCyiELeSMGwio1vRPKwIBIwKCAQEAiAZWnPCjQmNegDKg
fu5jMWsmzLbccP5TqLnWrFYDFvAKn+46/3fA421HBUVxJ7AoS6+pt6mL54tYsHhu
6rOvsfAlT/AGhbxw1Biyk6P9sOLiRCDsVE+dBjp5jRR9/N1WkLh10FH5hZETCW0b
0y88DG8DkWeR2UUIgngLr+pFr5jV/e4nvA5QpvbNscOwoiR7sFsMGLcMgM2fT4Hj
ZZovcGQMrDr6AG+y0/Vdf9wX22j+XKj7huIqM3GZvyqGPqJnP9sOKkPcuTck8Wx3
55BX675RVdoW9OTcHbUh3qHcCND4d9WZqHarW/a7XBdIiuRmC2kBX5WBmVXnm/RF
bvxoCwKBgQDqyVNWwm98gIw7LS8dR6Ec7t3kOeLNo/rtNTszo631yZ4hqdwgYR3Q
q6rhjufsVVRLVzfTDXucbhZ5h+UB9wXAM49ZPxKNw+ddHsRbhCuIWUl/iO8E/Aub
H3eZupo73N9JGa4STFw056ejOQrTTCMf0M316V4wgFAXOZeHEErxSQKBgQDYSuqR
nr3Hdw1n/iXfKrfd9fJI++nm14uQ4mkA+9HrtQpj/RTxr66/QSj7p3r6GF4dDYY4
XaqK+iCfhUKMr8+3CP7NoS/saZAUqvMnL+RCvX14sV55xRMwplaaNIwqDhQAhkmL
UeOBq40kmBsunjfp06JedmWhWKHYc1eR2iPw0wKBgA1qlwxFn/h8X8jeArE3Swj3
tOh4VhphJEgRq5yNAqBUqfNLiOvoSti5WjjGVmVGtFwTnMo7SOReD+mv/nUkDvUK
QrSkhLeky2RoKHpCER279ZJCVs0Vt4U0/4UgmxldFBLORHYS/fRlAkPXX7RNflmW
5zKfnvt1C+QR62bNuyO7AoGBAI4imiUtzStOPAKCcKiYajLGMYBrB2vPePjPTFEa
gqI1JBXSMlWt9n2uegR1X3El9LQBkrdTfrMZZeUrr2PD/Ybop3EvaKKrxRTlXfUu
GagzYRTMVAbgl5T/l/7vVMst0qFCTZYRPbucnpRj9Jr6QgAOuygh6wOgpN6yMjtG
NOAVAoGACIdfR5oZ4tvNIeqjtLF83HmUJARv86eMmjqgiQTFcZS3A8vk5y05STxX
HU3kTCfT6sypRi9zDQafIIyqYFgaOezr2eRRFRojQZqzHjtuFUeKLrKf7R9bzwwx
DPlNgYq8p4FOY5ZOL/ZOxUHW4vKRewURJttnxzw+LEy0T1FyAE0=
-----END RSA PRIVATE KEY-----
EOF
  SSH_PRIVATE_KEY3 = <<-EOF
-----BEGIN DSA PRIVATE KEY-----
MIIBvAIBAAKBgQC8lcuXcFcIC9wsV87L6PAwYefKgK0CwTSD1v3/aabZsu4w+UF8
zsPtdsNP8+JWfOp3KFbrUTH+ODgAXF/aL4UZfpbsQe446ZFV8v6dmWqj23sk0FLX
U5l2tsuJ9OdyXetVXjBvoiz+/r4k/iG/esvWlVGEHwq5eYXgQ1GfXABY3QIVAMVe
c7skmkUrCR6iivgZYYe3PQPZAoGBAKnpdEVATtDGOW9w2evSf5kc1InzdTurcJOH
q9qYdCaa8rlMGaIS6XFWcKqBlpj0Mv2R5ldW90bU/RllGvh1KinTIRVTsf4qtZIV
Xy4vN8IYzDL1493nKndMsxsRh50rI1Snn2tssAix64eJ5VFSGlyOYEKYDMlWzHK6
Jg3tVmc6AoGBAIwTRPAEcroqOzaebiVspFcmsXxDQ4wXQZQdho1ExW6FKS8s7/6p
ItmZYXTvJDwLXgq2/iK1fRRcKk2PJEaSuJR7WeNGsJKfWmQ2UbOhqA3wWLDazIZt
cMKjFzD0hM4E8qgjHjMvKDE6WgT6SFP+tqx3nnh7pJWwsbGjSMQexpyRAhQLhz0l
GzM8qwTcXd06uIZAJdTHIQ==
-----END DSA PRIVATE KEY-----
EOF

  SSH_PUBLIC_KEY1 = 'AAAAB3NzaC1yc2EAAAABIwAAAQEArfTA/lKVR84IMc9ZzXOCHr8DVtR8hzWuEVHF6KElavRHlk14g0SZu3m908Ejm/XF3EfNHjX9wN+62IMA0QBxkBMFCuLF+U/oeUs0NoDdAEKxjj4n6lq6Ss8aLct+anMy7D1jwvOLbcwV54w1d5JDdlZVdZ6AvHm9otwJq6rNpDgdmXY4HgC2nM9csFpuy0cDpL6fdJx9lcNL2RnkRC4+RMsIB+PxDw0j3vDi04dYLBXMGYjyeGH+mIFpL3PTPXGXwL2XDYXZ2H4SQX6bOoKmazTXq6QXuEB665njh1GxXldoIMcSshoJL0hrk3WrTOG22N2CQA+IfHgrXJ+A+QUzKQ=='
  SSH_PUBLIC_KEY2 = 'AAAAB3NzaC1yc2EAAAABIwAAAQEAxl6TpN7uFiY/JZ8qDnD7UrxDP+ABeh2PVg8Du1LEgXNk0+YWCeP5S6oHklqaWeDlbmAs1oHsBwCMAVpMa5tgONOLvz4JgwgkiqQEbKR8ofWJ+LADUElvqRVGmGiNEMLI6GJWeneL4sjmbb8d6U+M53c6iWG0si9XE5m7teBQSsCl0Tk3qMIkQGw5zpJeCXjZ8KpJhIJRYgexFkGgPlYRV+UYIhxpUW90t0Ra5i6JOFYwq98k5S/6SJIZQ/A9F4JNzwLw3eVxZj0yVHWxkGz1+TyELNY1kOyMxnZaqSfGzSQJTrnIXpdweVHuYh1LtOgedRQhCyiELeSMGwio1vRPKw=='
  SSH_PUBLIC_KEY3 = 'AAAAB3NzaC1kc3MAAACBALyVy5dwVwgL3CxXzsvo8DBh58qArQLBNIPW/f9pptmy7jD5QXzOw+12w0/z4lZ86ncoVutRMf44OABcX9ovhRl+luxB7jjpkVXy/p2ZaqPbeyTQUtdTmXa2y4n053Jd61VeMG+iLP7+viT+Ib96y9aVUYQfCrl5heBDUZ9cAFjdAAAAFQDFXnO7JJpFKwkeoor4GWGHtz0D2QAAAIEAqel0RUBO0MY5b3DZ69J/mRzUifN1O6twk4er2ph0JpryuUwZohLpcVZwqoGWmPQy/ZHmV1b3RtT9GWUa+HUqKdMhFVOx/iq1khVfLi83whjMMvXj3ecqd0yzGxGHnSsjVKefa2ywCLHrh4nlUVIaXI5gQpgMyVbMcromDe1WZzoAAACBAIwTRPAEcroqOzaebiVspFcmsXxDQ4wXQZQdho1ExW6FKS8s7/6pItmZYXTvJDwLXgq2/iK1fRRcKk2PJEaSuJR7WeNGsJKfWmQ2UbOhqA3wWLDazIZtcMKjFzD0hM4E8qgjHjMvKDE6WgT6SFP+tqx3nnh7pJWwsbGjSMQexpyR'

  KEY1_FINGERPRINT = "2a:89:84:c9:29:05:d1:f8:49:79:1c:ba:73:99:eb:af"
  KEY2_FINGERPRINT = "3c:af:74:87:cc:cc:a1:12:05:1a:09:b7:7b:ce:ed:ce"
  KEY3_FINGERPRINT = "14:f6:6a:12:96:be:44:32:e6:3c:77:43:94:52:f5:7a"

  def setup
    @key1 = SSHKey.new(SSH_PRIVATE_KEY1, :comment => "me@example.com")
    @key2 = SSHKey.new(SSH_PRIVATE_KEY2, :comment => "me@example.com")
    @key3 = SSHKey.new(SSH_PRIVATE_KEY3, :comment => "me@example.com")
    @key_without_comment = SSHKey.new(SSH_PRIVATE_KEY1)
  end

  def test_private_key1
    assert_equal SSH_PRIVATE_KEY1, @key1.private_key
  end

  def test_private_key2
    assert_equal SSH_PRIVATE_KEY2, @key2.private_key
  end

  def test_private_key3
    assert_equal SSH_PRIVATE_KEY3, @key3.private_key
  end

  def test_ssh_public_key_decoded1
    assert_equal Base64.decode64(SSH_PUBLIC_KEY1), @key1.send(:ssh_public_key_conversion)
  end

  def test_ssh_public_key_decoded2
    assert_equal Base64.decode64(SSH_PUBLIC_KEY2), @key2.send(:ssh_public_key_conversion)
  end

  def test_ssh_public_key_decoded3
    assert_equal Base64.decode64(SSH_PUBLIC_KEY3), @key3.send(:ssh_public_key_conversion)
  end

  def test_ssh_public_key_encoded1
    assert_equal SSH_PUBLIC_KEY1, Base64.encode64(@key1.send(:ssh_public_key_conversion)).gsub("\n", "")
  end

  def test_ssh_public_key_encoded2
    assert_equal SSH_PUBLIC_KEY2, Base64.encode64(@key2.send(:ssh_public_key_conversion)).gsub("\n", "")
  end

  def test_ssh_public_key_encoded3
    assert_equal SSH_PUBLIC_KEY3, Base64.encode64(@key3.send(:ssh_public_key_conversion)).gsub("\n", "")
  end

  def test_ssh_public_key_output
    expected1 = "ssh-rsa #{SSH_PUBLIC_KEY1} me@example.com"
    expected2 = "ssh-rsa #{SSH_PUBLIC_KEY2} me@example.com"
    expected3 = "ssh-dss #{SSH_PUBLIC_KEY3} me@example.com"
    expected4 = "ssh-rsa #{SSH_PUBLIC_KEY1}"
    assert_equal expected1, @key1.ssh_public_key
    assert_equal expected2, @key2.ssh_public_key
    assert_equal expected3, @key3.ssh_public_key
    assert_equal expected4, @key_without_comment.ssh_public_key
  end

  def test_ssh_public_key_validation
    expected1 = "ssh-rsa #{SSH_PUBLIC_KEY1} me@example.com"
    expected2 = "ssh-rsa #{SSH_PUBLIC_KEY2} me@example.com"
    expected3 = "ssh-dss #{SSH_PUBLIC_KEY3} me@example.com"
    expected4 = "ssh-rsa #{SSH_PUBLIC_KEY1}"
    invalid1 = "ssh-rsa #{SSH_PUBLIC_KEY1}= me@example.com"
    invalid2 = "ssh-rsa #{SSH_PUBLIC_KEY2}= me@example.com"
    invalid3 = "ssh-dss #{SSH_PUBLIC_KEY3}= me@example.com"
    invalid4 = "ssh-rsa A#{SSH_PUBLIC_KEY1}"
    invalid5 = "ssh-rsa #{SSH_PUBLIC_KEY3} me@example.com"

    assert SSHKey.valid?(expected1)
    assert SSHKey.valid?(expected2)
    assert SSHKey.valid?(expected3)
    assert SSHKey.valid?(expected4)

    assert !SSHKey.valid?(invalid1)
    assert !SSHKey.valid?(invalid2)
    assert !SSHKey.valid?(invalid3)
    assert !SSHKey.valid?(invalid4)
    assert !SSHKey.valid?(invalid5)
  end

  def test_exponent
    assert_equal 35, @key1.key_object.e.to_i
    assert_equal 35, @key2.key_object.e.to_i
  end

  def test_modulus
    assert_equal 21959919395955180268707532246136630338880737002345156586705317733493418045367765414088155418090419238250026039981229751319343545922377196559932805781226688384973919515037364518167604848468288361633800200593870224270802677578686553567598208927704479575929054501425347794297979215349516030584575472280923909378896367886007339003194417496761108245404573433556449606964806956220743380296147376168499567508629678037211105349574822849913423806275470761711930875368363589001630573570236600319099783704171412637535837916991323769813598516411655563604244942820475880695152610674934239619752487880623016350579174487901241422633, @key1.key_object.n.to_i
    assert_equal 25041821909255634338594631709409930006900629565221199423527442992482865961613864019776541767273966885435978473182530882048894721263421597979360058644777295324028381353356143013803778109979347540540538361684778724178534886189535456555760676722894784592989232554962714835255398111716791175503010379276254975882143986862239829255392231575481418297073759441882528318940783011390002193682320028951031205422825662402426266933458263786546846123394508656926946338411182471843223455365249418245551220933173115037201835242811305615780499842939975996344432437312062643436832423359634116147870328774728910949553186982115987967787, @key2.key_object.n.to_i
  end

  def test_fingerprint
    assert_equal KEY1_FINGERPRINT, @key1.fingerprint
    assert_equal KEY2_FINGERPRINT, @key2.fingerprint
    assert_equal KEY3_FINGERPRINT, @key3.fingerprint
  end

  def test_to_byte_array
    ba1 = @key1.send(:to_byte_array, 35)
    ba2 = @key1.send(:to_byte_array, 65537)
    ba3 = [0, 1, 255, 256, -1, -128, -256].map{|i| @key1.send(:to_byte_array, i)}
    assert_equal [35], ba1
    assert_equal [1, 0, 1], ba2
    assert_equal [[0], [1], [0, 255], [1, 0], [255], [128], [255, 0]], ba3
  end
end
