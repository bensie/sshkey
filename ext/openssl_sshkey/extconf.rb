require "mkmf"

if RUBY_PLATFORM != "java"
  extension_name = "openssl_sshkey/openssl_sshkey"
  dir_config(extension_name)

  have_header("openssl/ssl.h")

  create_makefile(extension_name)
end
