require_relative "lib/sshkey/version"

Gem::Specification.new do |s|
  s.name = "sshkey"
  s.version = SSHKey::VERSION
  s.authors = ["James Miller"]
  s.email = ["bensie@gmail.com"]
  s.homepage = "https://github.com/bensie/sshkey"
  s.summary = "SSH private/public key generator in Ruby"
  s.description = "Generate, load and inspect SSH keys (RSA, ECDSA, Ed25519) using pure Ruby"
  s.licenses = ["MIT"]
  s.metadata = {
    "source_code_uri" => "https://github.com/bensie/sshkey",
    "changelog_uri" => "https://github.com/bensie/sshkey/blob/main/CHANGELOG.md",
    "bug_tracker_uri" => "https://github.com/bensie/sshkey/issues",
    "rubygems_mfa_required" => "true"
  }

  s.required_ruby_version = ">= 3.3"

  s.files = Dir["lib/**/*.rb", "LICENSE", "README.md", "CHANGELOG.md"]
  s.require_paths = ["lib"]
end
