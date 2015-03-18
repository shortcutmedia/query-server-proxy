require 'rake'

desc 'Bootstraps the local development environment'
task :bootstrap do
  sh 'script/bootstrap.sh'
end

namespace :configure do

  desc 'Configures nginx build for development'
  task :development do
    sh 'script/configure_build_dev.sh'
  end
end

desc 'Builds nginx'
task :build do
  sh 'script/build.sh'
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
end

desc "Restarts nginx"
task :restart => [:stop, :start]
