require 'minitest/autorun'
require 'faraday'

class BackgroundProcess
  attr_reader :command, :args

  def initialize command, *args
    @command = command
    @args    = args
  end

  def start
    return if @io

    @io = IO.popen [command, args].flatten, err: log_file_name
    sleep 2
  end

  def stop
    return unless @io

    Process.kill 'TERM', @io.pid
    Process.wait @io.pid
    @io = nil
  end

  def running?
    !!@io
  end

  private

  def log_file_name
    @log_file_name ||= begin
      name = File.join(File.dirname(__FILE__), 'log/background_process.log')

      FileUtils.mkdir_p File.dirname(name)
      FileUtils.touch name

      name
    end
  end
end


class Nginx

  def self.ensure_running config_file

    return if instances[config_file] && instances[config_file].running?

    instances[config_file] = BackgroundProcess.new File.join(File.dirname(__FILE__), '../build/nginx/sbin/nginx'), '-c', config_file
    instances[config_file].start

    if instances[config_file].running?
      at_exit { instances[config_file].stop }
    else
      raise 'could not start Nginx'
    end
  end

  def self.instances
    @instances ||= Hash.new
  end
end


class AuthorizationHeaderEchoServer

  def self.ensure_running
    return if @instance && @instance.running?

    @instance = BackgroundProcess.new 'ruby', File.join(File.dirname(__FILE__), 'fixtures/authorization_header_echo_server.rb')
    @instance.start

    if @instance.running?
      at_exit { @instance.stop }
    else
      raise 'could not start AuthorizationHeaderEchoServer'
    end
  end
end
