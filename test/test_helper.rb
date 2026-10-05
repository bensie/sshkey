require "tempfile"
require "test/unit"
require "sshkey"

module Fixtures
  SSH_PRIVATE_KEY1 = <<~EOF
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

  SSH_PRIVATE_KEY2 = <<~EOF
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

  SSH_PRIVATE_KEY3 = <<~EOF
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

  SSH_PRIVATE_KEY4 = <<~EOF
    -----BEGIN EC PRIVATE KEY-----
    MHcCAQEEIByjVCRawGxEd/L/VblGjnJTJeOgk6vGFYnolYWHg+JkoAoGCCqGSM49
    AwEHoUQDQgAEQOAmNzXT3XN5DQdHBYCgflosVlHd6MUB1n9n6CCijvVJCQGJAA0p
    6+3o91ccyA0zHXuUno2eMzBUDghfNZYnHg==
    -----END EC PRIVATE KEY-----
  EOF

  PUBLIC_KEY1 = <<~EOF
    -----BEGIN PUBLIC KEY-----
    MIIBIDANBgkqhkiG9w0BAQEFAAOCAQ0AMIIBCAKCAQEArfTA/lKVR84IMc9ZzXOC
    Hr8DVtR8hzWuEVHF6KElavRHlk14g0SZu3m908Ejm/XF3EfNHjX9wN+62IMA0QBx
    kBMFCuLF+U/oeUs0NoDdAEKxjj4n6lq6Ss8aLct+anMy7D1jwvOLbcwV54w1d5JD
    dlZVdZ6AvHm9otwJq6rNpDgdmXY4HgC2nM9csFpuy0cDpL6fdJx9lcNL2RnkRC4+
    RMsIB+PxDw0j3vDi04dYLBXMGYjyeGH+mIFpL3PTPXGXwL2XDYXZ2H4SQX6bOoKm
    azTXq6QXuEB665njh1GxXldoIMcSshoJL0hrk3WrTOG22N2CQA+IfHgrXJ+A+QUz
    KQIBIw==
    -----END PUBLIC KEY-----
  EOF

  PUBLIC_KEY2 = <<~EOF
    -----BEGIN PUBLIC KEY-----
    MIIBIDANBgkqhkiG9w0BAQEFAAOCAQ0AMIIBCAKCAQEAxl6TpN7uFiY/JZ8qDnD7
    UrxDP+ABeh2PVg8Du1LEgXNk0+YWCeP5S6oHklqaWeDlbmAs1oHsBwCMAVpMa5tg
    ONOLvz4JgwgkiqQEbKR8ofWJ+LADUElvqRVGmGiNEMLI6GJWeneL4sjmbb8d6U+M
    53c6iWG0si9XE5m7teBQSsCl0Tk3qMIkQGw5zpJeCXjZ8KpJhIJRYgexFkGgPlYR
    V+UYIhxpUW90t0Ra5i6JOFYwq98k5S/6SJIZQ/A9F4JNzwLw3eVxZj0yVHWxkGz1
    +TyELNY1kOyMxnZaqSfGzSQJTrnIXpdweVHuYh1LtOgedRQhCyiELeSMGwio1vRP
    KwIBIw==
    -----END PUBLIC KEY-----
  EOF

  PUBLIC_KEY3 = <<~EOF
    -----BEGIN PUBLIC KEY-----
    MIIBuDCCASwGByqGSM44BAEwggEfAoGBALyVy5dwVwgL3CxXzsvo8DBh58qArQLB
    NIPW/f9pptmy7jD5QXzOw+12w0/z4lZ86ncoVutRMf44OABcX9ovhRl+luxB7jjp
    kVXy/p2ZaqPbeyTQUtdTmXa2y4n053Jd61VeMG+iLP7+viT+Ib96y9aVUYQfCrl5
    heBDUZ9cAFjdAhUAxV5zuySaRSsJHqKK+Blhh7c9A9kCgYEAqel0RUBO0MY5b3DZ
    69J/mRzUifN1O6twk4er2ph0JpryuUwZohLpcVZwqoGWmPQy/ZHmV1b3RtT9GWUa
    +HUqKdMhFVOx/iq1khVfLi83whjMMvXj3ecqd0yzGxGHnSsjVKefa2ywCLHrh4nl
    UVIaXI5gQpgMyVbMcromDe1WZzoDgYUAAoGBAIwTRPAEcroqOzaebiVspFcmsXxD
    Q4wXQZQdho1ExW6FKS8s7/6pItmZYXTvJDwLXgq2/iK1fRRcKk2PJEaSuJR7WeNG
    sJKfWmQ2UbOhqA3wWLDazIZtcMKjFzD0hM4E8qgjHjMvKDE6WgT6SFP+tqx3nnh7
    pJWwsbGjSMQexpyR
    -----END PUBLIC KEY-----
  EOF

  PUBLIC_KEY4 = <<~EOF
    -----BEGIN PUBLIC KEY-----
    MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEQOAmNzXT3XN5DQdHBYCgflosVlHd
    6MUB1n9n6CCijvVJCQGJAA0p6+3o91ccyA0zHXuUno2eMzBUDghfNZYnHg==
    -----END PUBLIC KEY-----
  EOF

  SSH_PUBLIC_KEY1 = "AAAAB3NzaC1yc2EAAAABIwAAAQEArfTA/lKVR84IMc9ZzXOCHr8DVtR8hzWuEVHF6KElavRHlk14g0SZu3m908Ejm/XF3EfNHjX9wN+62IMA0QBxkBMFCuLF+U/oeUs0NoDdAEKxjj4n6lq6Ss8aLct+anMy7D1jwvOLbcwV54w1d5JDdlZVdZ6AvHm9otwJq6rNpDgdmXY4HgC2nM9csFpuy0cDpL6fdJx9lcNL2RnkRC4+RMsIB+PxDw0j3vDi04dYLBXMGYjyeGH+mIFpL3PTPXGXwL2XDYXZ2H4SQX6bOoKmazTXq6QXuEB665njh1GxXldoIMcSshoJL0hrk3WrTOG22N2CQA+IfHgrXJ+A+QUzKQ=="

  SSH_PUBLIC_KEY2 = "AAAAB3NzaC1yc2EAAAABIwAAAQEAxl6TpN7uFiY/JZ8qDnD7UrxDP+ABeh2PVg8Du1LEgXNk0+YWCeP5S6oHklqaWeDlbmAs1oHsBwCMAVpMa5tgONOLvz4JgwgkiqQEbKR8ofWJ+LADUElvqRVGmGiNEMLI6GJWeneL4sjmbb8d6U+M53c6iWG0si9XE5m7teBQSsCl0Tk3qMIkQGw5zpJeCXjZ8KpJhIJRYgexFkGgPlYRV+UYIhxpUW90t0Ra5i6JOFYwq98k5S/6SJIZQ/A9F4JNzwLw3eVxZj0yVHWxkGz1+TyELNY1kOyMxnZaqSfGzSQJTrnIXpdweVHuYh1LtOgedRQhCyiELeSMGwio1vRPKw=="

  SSH_PUBLIC_KEY3 = "AAAAB3NzaC1kc3MAAACBALyVy5dwVwgL3CxXzsvo8DBh58qArQLBNIPW/f9pptmy7jD5QXzOw+12w0/z4lZ86ncoVutRMf44OABcX9ovhRl+luxB7jjpkVXy/p2ZaqPbeyTQUtdTmXa2y4n053Jd61VeMG+iLP7+viT+Ib96y9aVUYQfCrl5heBDUZ9cAFjdAAAAFQDFXnO7JJpFKwkeoor4GWGHtz0D2QAAAIEAqel0RUBO0MY5b3DZ69J/mRzUifN1O6twk4er2ph0JpryuUwZohLpcVZwqoGWmPQy/ZHmV1b3RtT9GWUa+HUqKdMhFVOx/iq1khVfLi83whjMMvXj3ecqd0yzGxGHnSsjVKefa2ywCLHrh4nlUVIaXI5gQpgMyVbMcromDe1WZzoAAACBAIwTRPAEcroqOzaebiVspFcmsXxDQ4wXQZQdho1ExW6FKS8s7/6pItmZYXTvJDwLXgq2/iK1fRRcKk2PJEaSuJR7WeNGsJKfWmQ2UbOhqA3wWLDazIZtcMKjFzD0hM4E8qgjHjMvKDE6WgT6SFP+tqx3nnh7pJWwsbGjSMQexpyR"

  SSH_PUBLIC_KEY4 = "AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEDgJjc1091zeQ0HRwWAoH5aLFZR3ejFAdZ/Z+ggoo71SQkBiQANKevt6PdXHMgNMx17lJ6NnjMwVA4IXzWWJx4="

  SSH_PUBLIC_KEY_ED25519 = "AAAAC3NzaC1lZDI1NTE5AAAAIBrNsRCISAtKXV5OVxqV6unVcdis5Uh3oiC6B7CMB7HQ"

  SSH_PUBLIC_KEY_ED25519_0_BYTE = "AAAAC3NzaC1lZDI1NTE5AAAAIADK9x9t3yQQH7h4OEJpUa7l2j7mcmKf4LAsNXHxNbSm"

  SSH_PUBLIC_KEY_ECDSA_256 = "AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBHJFDZ5qymZfIzoJcxYeu3C9HjJ08QAbqR28C2zSMLwcb3ZzWdRApnj6wEgRvizsBmr9zyPKb2u5Rp0vjJtQcZo="

  SSH_PUBLIC_KEY_ECDSA_384 = "AAAAE2VjZHNhLXNoYTItbmlzdHAzODQAAAAIbmlzdHAzODQAAABhBP+GtUCOR8aW7xTtpkbJS0qqNZ98PgbUNtTFhE+Oe+khgoFMX+o0JG5bckVuvtkRl8dr+63kUK0QPTtzP9O5yixB9CYnB8CgCgYo1FCXZuJIImf12wW5nWKglrCH4kV1Qg=="

  SSH_PUBLIC_KEY_ECDSA_521 = "AAAAE2VjZHNhLXNoYTItbmlzdHA1MjEAAAAIbmlzdHA1MjEAAACFBACsunidnIZ77AjCHSDp/xknLGDW3M0Ia7nxLdImmp0XGbxtbwYm2ga5XUzV9dMO9wF9ICC3OuH6g9DtGOBNPru1PwFDjaPISGgm0vniEzWazLsvjJVLThOA3VyYLxmtjm0WfS+/DfxgWVS6oeCTnDjjoVVpwU/fDbUbYPPRZI84/hOGNA=="

  SSH_PUBLIC_KEY_ECDSA_256_COMPRESSED = "AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAAAhA+YNpJJrrUsu5OLLvqGX5pAH3+x6/yEFU2AYdxb54Jk8"

  SSH_PUBLIC_KEY_ECDSA_384_COMPRESSED = "AAAAE2VjZHNhLXNoYTItbmlzdHAzODQAAAAIbmlzdHAzODQAAAAxAgMhp0cNvtzncxXF0W5nrkBCTrxJIcYqUTX4RcKWIM74FfxizmWJqP/C+looEz6dLQ=="

  SSH_PUBLIC_KEY_ECDSA_521_COMPRESSED = "AAAAE2VjZHNhLXNoYTItbmlzdHA1MjEAAAAIbmlzdHA1MjEAAABDAgDoeNR4bndT24BosNaTKCLOALjL6tXrpNHn0HJzHO5z30L4SvH0Gz9jvAiqehNHOgmK3/bFbwLVW1W4TJbNsp8BVA=="

  KEY1_MD5_FINGERPRINT = "2a:89:84:c9:29:05:d1:f8:49:79:1c:ba:73:99:eb:af"

  KEY2_MD5_FINGERPRINT = "3c:af:74:87:cc:cc:a1:12:05:1a:09:b7:7b:ce:ed:ce"

  KEY3_MD5_FINGERPRINT = "14:f6:6a:12:96:be:44:32:e6:3c:77:43:94:52:f5:7a"

  KEY4_MD5_FINGERPRINT = "38:0b:0f:63:36:64:b6:f0:43:94:de:32:75:eb:57:68"

  ED25519_MD5_FINGERPRINT = "6f:1a:8a:c1:4f:13:5c:36:6e:3f:be:eb:49:3b:8e:3e"

  ECDSA_256_MD5_FINGERPRINT = "d9:3a:7f:de:b2:65:04:ac:62:05:1a:1e:97:e9:2b:9d"

  ECDSA_384_MD5_FINGERPRINT = "b5:bb:3e:f6:eb:3b:0f:1e:18:37:1f:36:ac:7c:87:0d"

  ECDSA_521_MD5_FINGERPRINT = "98:8e:a9:4c:b9:aa:58:35:d1:42:65:c3:41:dd:04:e1"

  KEY1_SHA1_FINGERPRINT = "e4:f9:79:f2:fe:d6:be:2d:ef:2e:c2:fa:aa:f8:b0:17:34:fe:0d:c0"

  KEY2_SHA1_FINGERPRINT = "9a:52:78:2b:6b:cb:39:b7:85:ed:90:8a:28:62:aa:b3:98:88:e6:07"

  KEY3_SHA1_FINGERPRINT = "15:68:c6:72:ac:18:d1:fc:ab:a2:b7:b5:8c:d1:fe:8f:b9:ae:a9:47"

  KEY4_SHA1_FINGERPRINT = "aa:b5:e6:62:27:87:b8:05:f6:d6:8f:31:dc:83:81:d9:8f:f8:71:29"

  ED25519_SHA1_FINGERPRINT = "57:41:7c:d0:e2:53:28:87:7e:87:53:d4:69:ef:ef:63:ec:c0:0e:5e"

  ECDSA_256_SHA1_FINGERPRINT = "94:e8:92:2b:1b:ec:49:de:ff:85:ea:6e:10:d6:8d:87:7a:67:40:ee"

  ECDSA_384_SHA1_FINGERPRINT = "cc:fb:4c:d6:e9:d0:03:ae:2d:82:e1:fc:70:d8:47:98:25:e1:83:2b"

  ECDSA_521_SHA1_FINGERPRINT = "6b:2c:a2:6e:3a:82:6c:73:28:57:91:20:71:82:bc:8f:f8:9d:6c:41"

  KEY1_SHA256_FINGERPRINT = "js3llFehloxCfsVuDw5xu3NtS9AOAxcXY8WL6vkDIts"

  KEY2_SHA256_FINGERPRINT = "23f/6U/LdxIFx1CQFKHylw76n+LIHYoY4nRxKcFoos4"

  KEY3_SHA256_FINGERPRINT = "mPqEPQlOPGORrTJrU17sPax1jOqeutZja6MOsFIca+8"

  KEY4_SHA256_FINGERPRINT = "foUpf1ox3KfG3eKgJxGoSdZFRxHPsBYJgfD+CMYky6Y"

  ED25519_SHA256_FINGERPRINT = "gyzHUKl1eO8Bk1Cvn4joRgxRlXo1+1HJ3Vho/hAtKEg"

  ECDSA_256_SHA256_FINGERPRINT = "ncy2crhoL44R58GCZPQ5chPRrjlQKKgu07FDNelDmdk"

  ECDSA_384_SHA256_FINGERPRINT = "mrr4QcP6qD05DUS6Rwefb9f0uuvjyMcO28LSiq2283U"

  ECDSA_521_SHA256_FINGERPRINT = "QnaiGMIVDZyTG47hMWK6Y1z/yUzHIcTBGpNNuUwlhAk"

  KEY1_RANDOMART = <<~EOF.rstrip
    +---[RSA 2048]----+
    |o+ o..           |
    |..+.o            |
    | ooo             |
    |.++. o           |
    |+o+ +   S        |
    |.. + o .         |
    |  . + .          |
    |   . .           |
    |    Eo.          |
    +------[MD5]------+
  EOF

  KEY2_RANDOMART = <<~EOF.rstrip
    +---[RSA 2048]----+
    |  ..o..          |
    |   ..+ .         |
    |    o   .        |
    |     . o         |
    |    . o S .      |
    |     + o O o     |
    |      + + O .    |
    |       = o .     |
    |       .E        |
    +------[MD5]------+
  EOF

  KEY3_RANDOMART = <<~EOF.rstrip
    +---[DSA 1024]----+
    |       .=o.      |
    |      .+.o .     |
    |    + =.o . .    |
    |   + * + . .     |
    |    + = S . E    |
    |     + = . .     |
    |      .          |
    |                 |
    |                 |
    +------[MD5]------+
  EOF

  KEY4_RANDOMART = <<~EOF.rstrip
    +---[ECDSA 256]---+
    |    ..           |
    |   .. . .        |
    |  ..=o . . .     |
    |   B+.... E .    |
    |    @oo.S. .     |
    |   o B o. .      |
    |      o  .       |
    |                 |
    |                 |
    +------[MD5]------+
  EOF

  KEY4_RANDOMART_USING_SHA256_DIGEST = <<~EOF.rstrip
    +---[ECDSA 256]---+
    |      .. o++B+   |
    |       .. ...*   |
    |    . ...o  o o  |
    |   . =o.o .= .   |
    |    +o+oS o.= . .|
    |   o .oo =.. + +.|
    |  E     o +.+ = o|
    |         ..=.+ . |
    |          oo  .  |
    +----[SHA256]-----+
  EOF

  KEY4_RANDOMART_USING_SHA384_DIGEST = <<~EOF.rstrip
    +---[ECDSA 256]---+
    |           o++.  |
    | .        *oo. . |
    |o       .o+B.o.. |
    |+o      ooB+O *..|
    |.=+    .SB== ^.+.|
    |+  o    +o .O Xo.|
    | .  ...   .. + .o|
    |  . E. o +  + +..|
    |   .... . o..Bo..|
    +----[SHA384]-----+
  EOF

  KEY4_RANDOMART_USING_SHA512_DIGEST = <<~EOF.rstrip
    +---[ECDSA 256]---+
    |       +*+o    oo|
    |      . .o o  . +|
    |     . o.   oo oo|
    |.. .+ .    .*.o+ |
    |..Bo.*  S  ..=o..|
    | .+X+ Oo    ...+ |
    | +o.B*+=o    .+ +|
    |+=+O.+=+.+. +.o+.|
    |@**EB*O++=o+ =o.+|
    +----[SHA512]-----+
  EOF

  KEY1_SSHFP = <<~EOF.rstrip
    localhost IN SSHFP 1 1 e4f979f2fed6be2def2ec2faaaf8b01734fe0dc0
    localhost IN SSHFP 1 2 8ecde59457a1968c427ec56e0f0e71bb736d4bd00e03171763c58beaf90322db
  EOF

  KEY2_SSHFP = <<~EOF.rstrip
    localhost IN SSHFP 1 1 9a52782b6bcb39b785ed908a2862aab39888e607
    localhost IN SSHFP 1 2 db77ffe94fcb771205c7509014a1f2970efa9fe2c81d8a18e2747129c168a2ce
  EOF

  KEY3_SSHFP = <<~EOF.rstrip
    localhost IN SSHFP 2 1 1568c672ac18d1fcaba2b7b58cd1fe8fb9aea947
    localhost IN SSHFP 2 2 98fa843d094e3c6391ad326b535eec3dac758cea9ebad6636ba30eb0521c6bef
  EOF

  SSH2_PUBLIC_KEY1 = <<~EOF.rstrip
    ---- BEGIN SSH2 PUBLIC KEY ----
    Comment: me@example.com
    AAAAB3NzaC1yc2EAAAABIwAAAQEArfTA/lKVR84IMc9ZzXOCHr8DVtR8hzWuEVHF6KElav
    RHlk14g0SZu3m908Ejm/XF3EfNHjX9wN+62IMA0QBxkBMFCuLF+U/oeUs0NoDdAEKxjj4n
    6lq6Ss8aLct+anMy7D1jwvOLbcwV54w1d5JDdlZVdZ6AvHm9otwJq6rNpDgdmXY4HgC2nM
    9csFpuy0cDpL6fdJx9lcNL2RnkRC4+RMsIB+PxDw0j3vDi04dYLBXMGYjyeGH+mIFpL3PT
    PXGXwL2XDYXZ2H4SQX6bOoKmazTXq6QXuEB665njh1GxXldoIMcSshoJL0hrk3WrTOG22N
    2CQA+IfHgrXJ+A+QUzKQ==
    ---- END SSH2 PUBLIC KEY ----
  EOF

  SSH2_PUBLIC_KEY2 = <<~EOF.rstrip
    ---- BEGIN SSH2 PUBLIC KEY ----
    AAAAB3NzaC1yc2EAAAABIwAAAQEAxl6TpN7uFiY/JZ8qDnD7UrxDP+ABeh2PVg8Du1LEgX
    Nk0+YWCeP5S6oHklqaWeDlbmAs1oHsBwCMAVpMa5tgONOLvz4JgwgkiqQEbKR8ofWJ+LAD
    UElvqRVGmGiNEMLI6GJWeneL4sjmbb8d6U+M53c6iWG0si9XE5m7teBQSsCl0Tk3qMIkQG
    w5zpJeCXjZ8KpJhIJRYgexFkGgPlYRV+UYIhxpUW90t0Ra5i6JOFYwq98k5S/6SJIZQ/A9
    F4JNzwLw3eVxZj0yVHWxkGz1+TyELNY1kOyMxnZaqSfGzSQJTrnIXpdweVHuYh1LtOgedR
    QhCyiELeSMGwio1vRPKw==
    ---- END SSH2 PUBLIC KEY ----
  EOF

  SSH2_PUBLIC_KEY3 = <<~EOF.rstrip
    ---- BEGIN SSH2 PUBLIC KEY ----
    Comment: 1024-bit DSA with provided comment
    x-private-use-header: some value that is long enough to go to wrap aro\\
    und to a new line.
    AAAAB3NzaC1kc3MAAACBALyVy5dwVwgL3CxXzsvo8DBh58qArQLBNIPW/f9pptmy7jD5QX
    zOw+12w0/z4lZ86ncoVutRMf44OABcX9ovhRl+luxB7jjpkVXy/p2ZaqPbeyTQUtdTmXa2
    y4n053Jd61VeMG+iLP7+viT+Ib96y9aVUYQfCrl5heBDUZ9cAFjdAAAAFQDFXnO7JJpFKw
    keoor4GWGHtz0D2QAAAIEAqel0RUBO0MY5b3DZ69J/mRzUifN1O6twk4er2ph0JpryuUwZ
    ohLpcVZwqoGWmPQy/ZHmV1b3RtT9GWUa+HUqKdMhFVOx/iq1khVfLi83whjMMvXj3ecqd0
    yzGxGHnSsjVKefa2ywCLHrh4nlUVIaXI5gQpgMyVbMcromDe1WZzoAAACBAIwTRPAEcroq
    OzaebiVspFcmsXxDQ4wXQZQdho1ExW6FKS8s7/6pItmZYXTvJDwLXgq2/iK1fRRcKk2PJE
    aSuJR7WeNGsJKfWmQ2UbOhqA3wWLDazIZtcMKjFzD0hM4E8qgjHjMvKDE6WgT6SFP+tqx3
    nnh7pJWwsbGjSMQexpyR
    ---- END SSH2 PUBLIC KEY ----
  EOF

  ENCRYPTED_PRIVATE_KEY = <<~EOF
    -----BEGIN RSA PRIVATE KEY-----
    Proc-Type: 4,ENCRYPTED
    DEK-Info: AES-128-CBC,3514D8812B519059944A811726594515
    
    fSr1v51I65MZrSs7u12nype6RH6NS15xN5FDPaPKV++EBPxysEzicU5QHDt/aHa3
    t87nXkra1M400+zNgFcfi5Ga7w5SBmqEjdNgwhUV2/j1Yqqlr5c7l804OfIPxdE6
    ELoWH7pen72JnlZe6gXq495W96QTg3IzIWdiKEbKJlEwrNBligqT7GB2mup8nY1D
    o71R07dIrvfDy3xVgCoRjX4LKUilO6nRnwVCFRgVQTEVKclqt8NiSFGMjzv3iekR
    f1fJ8Wm6CiST8zdetIXgMnHEK1KELhNeMhI/42Tn/gHPDsckBiKLtM+85OOT92wh
    L9o/KUySdcsb/ld0yT/kAc99/wqNitHAqUEcLshIWDVhqoT1XK46hEuRN782AN2U
    shQKirF8QFopYF+u9K2Q0mr1EsYaBWOFFBR7EiwFvEYOx+ad6qGQGPcxWhbf6eCU
    D///9g1g5q8nWb80UH9Hw1aMhIA+VTlIasM6XJKmGr1LapxlrYsqRovPwkgOQg01
    jhSV1fy10bbaFBwd9qTdTTVqa368/e3/TxF2VKhDaqoy5lqvRqKzGJxi3ubzDuz9
    m3qRTCgy1v3XI5DgcjWt5xC5gZLHjKf79fQKRJjuEnWALahpDVWQ6PRCuqPfyph5
    /vVqGHqvA53HJ9pmXz4J9qtQQ2gkYRj1m2tlRJjtGRMqnAj7bpcDKIrdLudOiWB0
    FXwmsXljzPaf/SPUa+tGg7jbh+Jq+72vdpo1ijJtLXhWQAJasIbvSXOVHbZ6YhJj
    vES98gJPzevqemS//C1DMrr0ci6pM9ciT2szkrg71zRacnfqrjeZUI7qHKAsRbD5
    258Jj6BeFPeQSrUg8sqQdoPxVTNnVr2bOB5SNfh7gqLanPksi6Kr7XNIzsYP5Wzf
    ADAElPdcRRwYc2kLVqugZTMLSn1r8rQjEyQ8/TT2QefI4ma8mCrBKgqYX+SDbhMJ
    +KUrah0jCgj86z6fSNkNHaKuzvGCovZsJHXt2SoIWVYWVUz91IHPKXXycIqvf3Yj
    9HFpJRAPh30MYBgiImCJjmk8tqKGn0Tc80vOsrKMlVuMIIu2eNrddrnHUzSbjIHr
    tTtSDvsJ/Bn/6+Ox77U/FKg6s6/6PxOA1a+ffKkBXB/g4jS5CfGZl1owb3kX91C/
    a+bcNWp07DsaTaZd/0UEL2gIvaEuCULgyIvmnBPCOY6Pc5GGegWEJne/sk7j9W4I
    59YtVfcSXiovYR/QEywytfN/tfPxKfUoqNMIxLkukjFYz4Zzk5kXEeI+1lcry398
    UQSaOboSDKY6boX4rWgiiqyn5LN+47eAIZPO+zsWXky16F04JpT7V7XqZPXQn7vI
    pMAoPCkT4qE9Gp2CcSj2l2CoZ3ZA5lOs6Wvxuz0q1zd0uSe8O81/3rnw28DthDQO
    SuzrY0HinPEFomwMGbfhosB5kOmBXEk7XbSWWHhK0QG63CYqp5caUst2Mie21b0Y
    FgFTrS1VqUiqDjCmt8F8UCPQS89aFm096wqtmwDO+VWKanuHUUShtTPlYyLe1RTm
    wqh1BBa05ydM0Vf1NagFB4JNT1qSIL5x4XtkOFwqcdXWYvwYfT8PkZjX/kz+W7jb
    -----END RSA PRIVATE KEY-----
  EOF

  DECRYPTED_PRIVATE_KEY = <<~EOF
    -----BEGIN RSA PRIVATE KEY-----
    MIIEpAIBAAKCAQEA33H9u4rG0SVMzK8PFyIi30kVHvogmpKVOQL2g2tozi2GipkA
    imzoCW9jIx1jo6zo0kMKCbMdJCNUc93tQxkJAAWA07WYwE9z+J6MC/3urb4Q0UAZ
    orlNyN3pPP8ATFIQomd0wW/EHwbmknlJOIZY4MNUQpNJunnBAAzZyLef6+sbLzQZ
    wc0/vgtmatoCxh4mZWFuFMopkMqScYDKxL30xXXPRGfJvAVWZDnY3ErJSe7uyefI
    Zo/lp4tsH5XGMcFm+nLs++nJjYZ6Ud/ie1g+ZCJv5Qit1m7zCVjiJ4RVMC/4yTb7
    CO8n4PhX8gR9d1DRPVvlKa1sZfQeULEIXMniKQIDAQABAoIBAQDEXS74s5rJjhgS
    AP4n/E3dICK5mGMytAMDmUD+eVQfbQ7BmnhJLjA0qnjbESbRXlE1Bsk5gPjpG0tK
    kAvEXan1JOD0LLDSwIBQSzUUDNLGSTQKUGS3BlX/YlVoz0h5ydzofDa1D/2wrqXO
    r1vTmu1ciQvxffLbN8iOvLxfkk+uSMhqnhf/q3WVinu+VALPg8e/v3p4VbnSfP4D
    eClBiMKEKRFdsa9xBxShijcX1HxjIvp3zDgb127fo2iFw09PIHUZCUo6M77iGrQY
    mscoA+5q1qSyD6Btw0EkKK55ytNMC2T+KfGYV0ySwhadmM+5+G64etvNGCn/j7CU
    rhuRhMlpAoGBAPiJlcWaNVw3ttlea+jllxnaCEOmG29NGWxw080XRvjSIrltPAiE
    8e4FynAMx49aXKsaB8Df2WspdKBxHJgv1U0sapADwxlMO8erj2eDSRqy6bwnI4CT
    T+vvo2vdmkvkV0D9RskXCi5tgTO5FYnf7CjON6JLkg83V3vzyjsKlvDzAoGBAOYn
    iC50OdZ84U58wQUsvwXFuyzMQX9r+h0jL2tIDv/yYlMWg9tNt0HkGUOo7H1ZVhdL
    9Z1B0Ztl2qoJipcQvhzfwdo4XwuLk7D0bOAfZo9YMbU5Jqy+rqE5yv/P4wa7ba4S
    uUQYvSuv54CtiOZDFyK8dU7y9mm+no3Fvrd9RwdzAoGANzlLACctqBnxFQd37r3k
    /yeFIpLsEaUN+xxu02lSqcL3WEA/UJ1JrFu5CYCtbtrjMFmOU3rpsnf5pBS+B8rJ
    GGbAHtPXK+3Wcp1aNePkAHy0lswThWQ2I/SRWUxaFnbcNGKSsefeqUZHqRh9Aq+w
    p7h6gCNOhvcDB1W6H7hQpaUCgYEAyBRDygaWJUVI5N+FOUduBMmhb09d/TTUKTJm
    TcBF8fE30v12wVZtYqW15ODcPhhExFnverc2Tf6cukczKSKP8y/+KQPqdHHxgdrr
    L2d81E6aX+4AFhpqW5SPShXiSf70WWjDkFRlV65C9dVmdq6KVVM6M9j5qHHjCmKG
    6qLI9csCgYBuhFwwI9DiYvJPR1LJZnJtE0qZiTwpmCjU2LoBRsywvuBeyXtwpmIM
    5IgfgXXLK5qK/+cp9047T5rzT6ndu5fNZINPzynA8tNhTtHXK8l/GT/iq8Rd6AcM
    WJmIe8EnUDhHqg7Z2h5tGpX1QPMSA4G8RGPPyrcd3v0G/PZ6pFALlQ==
    -----END RSA PRIVATE KEY-----
  EOF

  DECRYPTED_KEY_FINGERPRINT = "2e:ba:06:b1:c7:13:37:24:6f:2d:3a:ba:45:e2:b4:78"

  ED25519_PRIVATE_KEY = <<~EOF
    -----BEGIN OPENSSH PRIVATE KEY-----
    b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
    QyNTUxOQAAACAYC+MM3xREmLYf+nOTY2fcJGCWNu6eHShXClSHja/oKQAAAJgHPX/vBz1/
    7wAAAAtzc2gtZWQyNTUxOQAAACAYC+MM3xREmLYf+nOTY2fcJGCWNu6eHShXClSHja/oKQ
    AAAEA0vbqjL+gkj67pk8Z0KA6qeKEBag6ydXxn8qcTn/bf8BgL4wzfFESYth/6c5NjZ9wk
    YJY27p4dKFcKVIeNr+gpAAAAE2VkMjU1MTlAZXhhbXBsZS5jb20BAg==
    -----END OPENSSH PRIVATE KEY-----
  EOF

  ED25519_ENCRYPTED_PRIVATE_KEY = <<~EOF
    -----BEGIN OPENSSH PRIVATE KEY-----
    b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABCMChJdyR
    OviMLssVnIiLq0AAAAGAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIGkHKF/Y3UBSrpNm
    boahZO736SV9N1xSaGkfgm2BY1sqAAAAoFDrAl2F4BZcvOTbnUr2Wnfmjf6YB68E5QiyJr
    InF5+Mvtmyj28nTWJnRIr0VW/k5gaEYry40+/4lS+VyYHmV7sHayPoLkWaRTrQoX2hwguM
    MLtAsNaVKuAbeb85fK3k6dVMiERHTKvmg/Sj6X+qzSq+AM6adhcclKg5/4KS/rEkIoF2Jz
    jKk9qONLhk6F7crhi3h7yVVE1fpOHPKtEYRx8=
    -----END OPENSSH PRIVATE KEY-----
  EOF

  ECDSA384_PRIVATE_KEY = <<~EOF
    -----BEGIN OPENSSH PRIVATE KEY-----
    b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAiAAAABNlY2RzYS
    1zaGEyLW5pc3RwMzg0AAAACG5pc3RwMzg0AAAAYQR6163npUtqOu5q8tmsO8wMtl3vq4QE
    VYeFa2RwKfQnwmpwxLMZmslx51SURwFivPr31MIV6bY76mEKAYeGKamK6NWcaiQp838CCO
    8ENW5waU6g6e9irtkzO2NCG5ljcrQAAADgxBgdIcQYHSEAAAATZWNkc2Etc2hhMi1uaXN0
    cDM4NAAAAAhuaXN0cDM4NAAAAGEEetet56VLajruavLZrDvMDLZd76uEBFWHhWtkcCn0J8
    JqcMSzGZrJcedUlEcBYrz699TCFem2O+phCgGHhimpiujVnGokKfN/AgjvBDVucGlOoOnv
    Yq7ZMztjQhuZY3K0AAAAMQCgkmcd0vmXe0c/gu+iKjMUjjW5jRyCk5jSD4BWDfv0toS+pk
    M3Usm7xJInqszNn9YAAAARZWNkc2FAZXhhbXBsZS5jb20BAgMEBQY=
    -----END OPENSSH PRIVATE KEY-----
  EOF

  RSA_PRIVATE_KEY = <<~EOF
    -----BEGIN OPENSSH PRIVATE KEY-----
    b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn
    NhAAAAAwEAAQAAAQEA81S4XwTcHhhz1g6uAtD0VIo1INl6L1bKRZo24FADAHaIlsk4HHfD
    pJLepMOltH0ovpQWHSmgMvf3Q08eCnUIvAqv5m6qVCExJw0uSwJYmzouD+7BWCFMQ0ARbz
    RYHoFH3AcaVyq6Fyljgl8r6wIyJfWG9qq/qM5Wpru7t4jide5J3QNSrv1egy7NVDElSnuS
    b4VBiDLcKFVaYAhbGA4yfxCgL+bWEnzIRbqsEz4R7kzaH81vIzla+b0mwaue2LUDZZzb1U
    0+hz/f3RaLWXEWloeMVhOeEwamgwnK1yLRyRnRrE3ZbYlMCZohDSCAcDQrKOL4KS113lpM
    ch5nsx/dZQAAA8iuCkrhrgpK4QAAAAdzc2gtcnNhAAABAQDzVLhfBNweGHPWDq4C0PRUij
    Ug2XovVspFmjbgUAMAdoiWyTgcd8Okkt6kw6W0fSi+lBYdKaAy9/dDTx4KdQi8Cq/mbqpU
    ITEnDS5LAlibOi4P7sFYIUxDQBFvNFgegUfcBxpXKroXKWOCXyvrAjIl9Yb2qr+ozlamu7
    u3iOJ17kndA1Ku/V6DLs1UMSVKe5JvhUGIMtwoVVpgCFsYDjJ/EKAv5tYSfMhFuqwTPhHu
    TNofzW8jOVr5vSbBq57YtQNlnNvVTT6HP9/dFotZcRaWh4xWE54TBqaDCcrXItHJGdGsTd
    ltiUwJmiENIIBwNCso4vgpLXXeWkxyHmezH91lAAAAAwEAAQAAAQBq07Lt5FBO1iVkwKUc
    j2f1BYg1l8TQq6W50O5upDHtLhzhNg3wUZQO2HvukgZZqukMYi8jNnciaUKgxkdGCAOBqp
    925vbYYIoXvu2n+Ku12mEGladEbbnxfFsrGyvkmJVXv7aMtjFkocMSJX4+eoRRre1GtcfW
    8F+Sa7EJ7oqdgti4OfrMdnCTVOj39zGuK4LvFxEk5R/WKHPrIfJdroqx3UYfZwUHZmuITM
    AHSx+zJqK0z0sB+uo22fdQOw+uuWrhORkjRTKnqb5NTp+s/RjG0kCA8jpZDjo3p7hZO3Bl
    nine0o+XqfQSUY3dQqKR80tistvDCMuspsc3RwARaV0xAAAAgHN1VfalXpxZ2fJXqkbUjA
    k5MPto8qhYjS/hkid4/4FqoDuGpqBVdKZ7Xd+d6m5/C1ti6bK/y3jG4PWP45tViBqrao3C
    Y0r9hwTX0nEcLu7bmLrJO8sFZl/950cQ6Dmh6MlItfR6TqbbsPv7im9CeZr+EmtLHSQpkI
    nGmveXYUE6AAAAgQD8vSi7tAAoMroajrKPQboEZsXaKcMNKtN20USgpKtLSxSbd/dA1UhM
    P8c737Rm2hailkBHa7Xcjbzw0HNzPU5NYdW35OUxvSkCdT9iZfSzNT9n/3DH3ARbFYhs7a
    15zZsii+gn54M+B01utD3TvdMlGw8bmyuRIX35DmtxNEEvswAAAIEA9nh8JGTb2t4OTYJ6
    DS2LsnSRa1Habh7IFv04RdM4+X4nlLXTbWRlCffazpYF9UOh96htBNPBT+zoIevJ4JEtU0
    y8566CHtNyK/YoQt08NBTXwRWo5LTZw5A5XjAtizkLBUgTkMLDJcfhtgYG8UYY3tn9BHhT
    +dRvYqzIEtt2cocAAAAPcnNhQGV4YW1wbGUuY29tAQIDBA==
    -----END OPENSSH PRIVATE KEY-----
  EOF

  ED25519_PUBLIC_KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBgL4wzfFESYth/6c5NjZ9wkYJY27p4dKFcKVIeNr+gp ed25519@example.com"

  ECDSA384_PUBLIC_KEY = "ecdsa-sha2-nistp384 AAAAE2VjZHNhLXNoYTItbmlzdHAzODQAAAAIbmlzdHAzODQAAABhBHrXreelS2o67mry2aw7zAy2Xe+rhARVh4VrZHAp9CfCanDEsxmayXHnVJRHAWK8+vfUwhXptjvqYQoBh4YpqYro1ZxqJCnzfwII7wQ1bnBpTqDp72Ku2TM7Y0IbmWNytA== ecdsa@example.com"

  RSA_PUBLIC_KEY = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDzVLhfBNweGHPWDq4C0PRUijUg2XovVspFmjbgUAMAdoiWyTgcd8Okkt6kw6W0fSi+lBYdKaAy9/dDTx4KdQi8Cq/mbqpUITEnDS5LAlibOi4P7sFYIUxDQBFvNFgegUfcBxpXKroXKWOCXyvrAjIl9Yb2qr+ozlamu7u3iOJ17kndA1Ku/V6DLs1UMSVKe5JvhUGIMtwoVVpgCFsYDjJ/EKAv5tYSfMhFuqwTPhHuTNofzW8jOVr5vSbBq57YtQNlnNvVTT6HP9/dFotZcRaWh4xWE54TBqaDCcrXItHJGdGsTdltiUwJmiENIIBwNCso4vgpLXXeWkxyHmezH91l rsa@example.com"

  ED25519_RANDOMART_USING_SHA256_DIGEST = <<~EOF.rstrip
    +--[ED25519 256]--+
    |          o ..o  |
    |       . + . o.o |
    |      . o . ++o. |
    |       o ..o++o..|
    |      . S .o.+...|
    |            + .E |
    |           o =o +|
    |         . .=oX=o|
    |          o+oXOB*|
    +----[SHA256]-----+
  EOF

  def setup
    @key1 = SSHKey.new(SSH_PRIVATE_KEY1, comment: "me@example.com")
    @key2 = SSHKey.new(SSH_PRIVATE_KEY2, comment: "me@example.com")
    @key3 = SSHKey.new(SSH_PRIVATE_KEY3, comment: "me@example.com")
    @key4 = SSHKey.new(SSH_PRIVATE_KEY4, comment: "me@example.com")
    @key_without_comment = SSHKey.new(SSH_PRIVATE_KEY1)
  end
end
