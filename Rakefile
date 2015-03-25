require 'rake'

NGINX_VERSION = '1.7.11'

desc 'Bootstraps the local development environment'
task :bootstrap do
  sh "NGINX_VERSION=#{NGINX_VERSION} script/bootstrap.sh"
end

namespace :configure do

  desc 'Configures nginx build for development'
  task :development do
    sh "NGINX_VERSION=#{NGINX_VERSION} script/configure_build_dev.sh"
  end
end

desc 'Builds nginx'
task :build do
  sh "NGINX_VERSION=#{NGINX_VERSION} script/build.sh"
end


NGINX_PIDFILE = File.join File.dirname(__FILE__), 'build/nginx/logs/nginx.pid'

desc "Starts nginx"
task :start do
  raise 'Already running' if File.exist?(NGINX_PIDFILE)

  args = []
  args << "-c #{ENV['CONFIGFILE']}" if ENV['CONFIGFILE']
  `build/nginx/sbin/nginx #{args.join ' '}`
  sleep 1
end

desc "Stops nginx"
task :stop do
  `build/nginx/sbin/nginx -s stop` if File.exist?(NGINX_PIDFILE)
  sleep 1
end

desc "Restarts nginx"
task :restart => [:stop, :start]

desc "Runs all tests in ./test/*_test.rb"
task :test do
  $: << 'test'
  Dir[File.join(File.dirname(__FILE__), 'test/*_test.rb')].each do |test_file|
    load test_file
  end
end
