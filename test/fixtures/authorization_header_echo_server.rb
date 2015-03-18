require 'sinatra'

configure do
  set :port, 8881
end

get '/' do
  authorization_header = env['HTTP_AUTHORIZATION']
  authorization_header
end
