require 'rake'

NGINX_ENV = ENV['NGINX_ENV'] ||= 'development'


###############################################################################
# Building

NGINX_VERSION = '1.7.11'

desc 'Bootstraps the local development environment'
task :bootstrap do
  sh "NGINX_VERSION=#{NGINX_VERSION} script/bootstrap.sh"
end

desc 'Configures nginx build'
task :configure do
  sh "NGINX_VERSION=#{NGINX_VERSION} script/configure_build.sh"
end

desc 'Builds nginx'
task :build do
  sh "NGINX_VERSION=#{NGINX_VERSION} script/build.sh"
end



###############################################################################
# Running

NGINX_PIDFILE   = File.join File.dirname(__FILE__), 'build/nginx-query-server-proxy/logs/nginx-query-server-proxy.pid'
NGINX_CONF_FILE = File.join File.dirname(__FILE__), "config/#{ENV['NGINX_ENV']}.conf"

desc "Starts nginx"
task :start do
  raise 'Already running' if File.exist?(NGINX_PIDFILE)

  `build/nginx-query-server-proxy/bin/nginx-query-server-proxy -c #{NGINX_CONF_FILE}`
  sleep 1
end

desc "Stops nginx"
task :stop do
  `build/nginx-query-server-proxy/bin/nginx-query-server-proxy -s stop` if File.exist?(NGINX_PIDFILE)
  sleep 1
end

desc "Restarts nginx"
task :restart => [:stop, :start]



###############################################################################
# Tests

desc "Runs all tests in ./test/*_test.rb"
task :test do
  $: << 'test'
  Dir[File.join(File.dirname(__FILE__), 'test/*_test.rb')].each do |test_file|
    load test_file
  end
end
