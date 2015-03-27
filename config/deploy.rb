set :application, 'query-server-proxy'
set :repo_url, 'https://github.com/shortcutmedia/query-server-proxy.git'

# ask :branch, proc { `git rev-parse --abbrev-ref HEAD`.chomp }
set :branch, 'master'

set :deploy_to, '/srv/query-server-proxy'
set :scm, :git

# set :format, :pretty
# set :log_level, :debug
# set :pty, true

# set :linked_files, %w{config/database.yml}
set :linked_dirs, %w{build/nginx-query-server-proxy/logs} # TODO: share vendor dir as soon as bootstrap script can handle
                                                          #       vendor being a symlinked dir...

# set :default_env, { path: "/opt/ruby/bin:$PATH" }
# set :keep_releases, 5

set :rbenv_type, :system
set :rbenv_ruby, '2.0.0-p353'
set :rbenv_prefix, "RBENV_ROOT=#{fetch(:rbenv_path)} RBENV_VERSION=#{fetch(:rbenv_ruby)} #{fetch(:rbenv_path)}/bin/rbenv exec"
set :rbenv_map_bins, %w{rake gem bundle ruby}

namespace :deploy do

  after :updating, 'deploy:build'

  desc 'Build server'
  task :build do
    on roles(:app) do
      within release_path do
        execute :rake, 'bootstrap'
        execute :rake, 'configure'
        execute :rake, 'build'
      end
    end
  end

  desc 'Restart server'
  task :restart do
    on roles(:app), in: :sequence, wait: 5 do
      # Your restart mechanism here, for example:
      # execute :touch, release_path.join('tmp/restart.txt')

      within release_path do
        execute :rake, 'restart'
      end
    end
  end

  after :finishing, 'deploy:cleanup'
end
