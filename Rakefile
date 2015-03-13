require 'rake'

desc 'Bootstraps the local development environment'
task :bootstrap do
  sh 'script/bootstrap.sh'
end

namespace :build do

  desc 'Compiles nginx with the module in a development configuration'
  task :development do
    sh 'script/build_dev.sh'
  end
end

task build: 'build:development'

desc "Starts nginx"
task :start do
  args = []
  args << "-c #{ENV['CONFIGFILE']}" if ENV['CONFIGFILE']
  `build/nginx/sbin/nginx #{args.join ' '}`
  sleep 1
end

desc "Stops nginx"
task :stop do
  `build/nginx/sbin/nginx -s stop`
end

desc "Restarts nginx"
task :restart => [:stop, :start]
