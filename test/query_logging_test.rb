require 'test_helper'

class QueryLoggingTest < Minitest::Spec

  # must match the values in the nginx config file
  SCM_ACCESS_KEY      = '123'
  SCM_SECRET_TOKEN    = '456'
  KOOABA_ACCESS_KEY   = 'abc'
  KOOABA_SECRET_TOKEN = 'xyz'

  before do
    AuthorizationHeaderEchoServer.ensure_running

    Nginx.ensure_running File.join(File.dirname(__FILE__), 'fixtures/nginx_with_authorization_header_echo_server_as_backend.conf')
    QueryLog.clear
    Nginx.reopen_logs File.join(File.dirname(__FILE__), 'fixtures/nginx_with_authorization_header_echo_server_as_backend.conf')
  end

  def make_request_with method, path, headers
    response = Faraday.send method.to_s.downcase, "http://localhost:8880#{path}", nil, headers
    raise "Request failed with status #{response.status}" if response.status > 299
  end

  let(:verb)         { 'GET' }
  let(:content_md5)  { '1234567890abcdef' }
  let(:content_type) { 'multipart/form-data' }
  let(:date)         { DateTime.now.rfc822 }
  let(:uri)          { '/' }

  let(:digest) { "#{verb}\n#{content_md5}\n#{content_type}\n#{date}\n#{uri}" }

  let(:scm_signature)    { Base64.encode64(OpenSSL::HMAC.digest('sha1', SCM_SECRET_TOKEN, digest)).strip }
  let(:kooaba_signature) { Base64.encode64(OpenSSL::HMAC.digest('sha1', KOOABA_SECRET_TOKEN, digest)).strip }

  it 'must log the query when a valid Authorization header is present' do
    authorization = "SCMA #{SCM_ACCESS_KEY}:#{scm_signature}"

    make_request_with verb.to_s.downcase, uri, 'Content-MD5'   => content_md5,
                                               'Content-Type'  => content_type,
                                               'Date'          => date,
                                               'Authorization' => authorization
    QueryLog.lines.last.must_match %r{#{SCM_ACCESS_KEY}}
  end

  it 'must not log the query when a (legacy) kooaba Authorization header is present' do
    authorization = "KA #{KOOABA_ACCESS_KEY}:#{kooaba_signature}"

    make_request_with verb.to_s.downcase, uri, 'Content-MD5'   => content_md5,
                                               'Content-Type'  => content_type,
                                               'Date'          => date,
                                               'Authorization' => authorization
    QueryLog.lines.must_be :empty?
  end

  it 'must not log the query when an unknown Authorization header is present' do
    authorization = 'something unknown'

    make_request_with verb.to_s.downcase, uri, 'Content-MD5'   => content_md5,
                                               'Content-Type'  => content_type,
                                               'Date'          => date,
                                               'Authorization' => authorization
    QueryLog.lines.must_be :empty?
  end

end
