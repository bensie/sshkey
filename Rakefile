require "rake"
require "rake/testtask"
require "rake/extensiontask" unless RUBY_PLATFORM == "java"

Rake::ExtensionTask.new "openssl_sshkey" do |ext|
  ext.lib_dir = "lib/openssl_sshkey"
end unless RUBY_PLATFORM == "java"

# https://edgar.tumblr.com/post/52300664342/how-to-extend-an-existing-rake-task
desc "Run bundle install"
task :bundle do
  sh "bundle install"
end
Rake::Task["compile"].enhance [:bundle] unless RUBY_PLATFORM == "java"

# https://edgar.tumblr.com/post/52300664342/how-to-extend-an-existing-rake-task
desc "Generate a Makefile for openssl_sshkey"
task :mkmf => [:bundle] do
  FileUtils.cd("ext/openssl_sshkey") do
    ruby "extconf.rb"
  end
end
Rake::Task["compile"].enhance [:mkmf] unless RUBY_PLATFORM == "java"

# https://edgar.tumblr.com/post/52300664342/how-to-extend-an-existing-rake-task
# BETTER: https://ruby.github.io/rake/doc/rakefile_rdoc.html#label-Clean+and+Clobber+Tasks
task :rake_compile_clobber do
  clobber_files = ["Gemfile.lock", "ext/openssl_sshkey/Makefile", "ext/openssl_sshkey/mkmf.log"]
  clobber_files.each do |clobber_file|
    File.delete(clobber_file) if File.exists?(clobber_file)
  end
end

Rake::Task["clobber"].enhance do
  Rake::Task[:rake_compile_clobber].invoke
end unless RUBY_PLATFORM == "java"

if RUBY_PLATFORM == "java"
  task :compile
  task :clean
  task :clobber => [:clean, :rake_compile_clobber]
end

desc "Default: run unit tests."
task :default => :test

desc "Test the sshkey gem"
Rake::TestTask.new(:test => [:compile]) do |t|
  t.libs << "lib"
  t.libs << "ext"
  t.libs << "test"
  t.test_files = FileList['test/*_test.rb']
  t.verbose    = true
end
