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
