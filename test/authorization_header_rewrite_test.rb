require 'test_helper'

require 'openssl'
require 'base64'
require 'date'

describe "Authorization header rewrite" do

  # must match the values in the nginx config file
  SCM_ACCESS_KEY      = '123'
  SCM_SECRET_TOKEN    = '456'
  KOOABA_ACCESS_KEY   = 'abc'
  KOOABA_SECRET_TOKEN = 'xyz'

  before do
    Nginx.ensure_running File.join(File.dirname(__FILE__), 'fixtures/nginx_with_authorization_header_echo_server_as_backend.conf')
    AuthorizationHeaderEchoServer.ensure_running
  end

  def rewritten_authorization_header_for_request_with method, path, headers
    response = Faraday.send method.to_s.downcase, "http://localhost:8880#{path}", nil, headers
    raise "Request failed with status #{response.status}" if response.status > 299
    response.body
  end

  let(:verb)         { 'GET' }
  let(:content_md5)  { '1234567890abcdef' }
  let(:content_type) { 'multipart/form-data' }
  let(:date)         { DateTime.now.rfc822 }
  #let(:date)         { 'Wed, 18 Mar 2015 16:19:29 +0100' }
  let(:uri)          { '/' }

  let(:digest) { "#{verb}\n#{content_md5}\n#{content_type}\n#{date}\n#{uri}" }

  let(:scm_signature)    { Base64.encode64(OpenSSL::HMAC.digest('sha1', SCM_SECRET_TOKEN, digest)).strip }
  let(:kooaba_signature) { Base64.encode64(OpenSSL::HMAC.digest('sha1', KOOABA_SECRET_TOKEN, digest)).strip }

  it 'must rewrite valid, well-formed Authorization headers' do
    auth_header_in = "SCMA #{SCM_ACCESS_KEY}:#{scm_signature}"

    auth_header_out = rewritten_authorization_header_for_request_with verb, uri, 'Content-MD5'   => content_md5,
                                                                                 'Content-Type'  => content_type,
                                                                                 'Date'          => date,
                                                                                 'Authorization' => auth_header_in
    auth_header_out.must_equal "KA #{KOOABA_ACCESS_KEY}:#{kooaba_signature}"
  end

  it 'must not rewrite invalid Authorization headers' do
    auth_header_in = "SCMA #{SCM_ACCESS_KEY}:invalid_signature"

    auth_header_out = rewritten_authorization_header_for_request_with verb, uri, 'Content-MD5'   => content_md5,
                                                                                 'Content-Type'  => content_type,
                                                                                 'Date'          => date,
                                                                                 'Authorization' => auth_header_in
    auth_header_out.must_equal auth_header_in
  end

  it 'must rewrite Authorization headers when missing required headers' do
    auth_header_in = "SCMA #{SCM_ACCESS_KEY}:#{scm_signature}"

    auth_header_out = rewritten_authorization_header_for_request_with verb, uri, 'Authorization' => auth_header_in
    auth_header_out.must_equal auth_header_in
  end

  it 'must not rewrite (legacy) kooaba Authorization headers' do
    auth_header_in = "KA #{KOOABA_ACCESS_KEY}:#{kooaba_signature}"

    auth_header_out = rewritten_authorization_header_for_request_with verb, uri, 'Content-MD5'   => content_md5,
                                                                                 'Content-Type'  => content_type,
                                                                                 'Date'          => date,
                                                                                 'Authorization' => auth_header_in
    auth_header_out.must_equal auth_header_in
  end

  it 'must not rewrite unknown Authorization headers' do
    auth_header_in = 'something unknown'

    auth_header_out = rewritten_authorization_header_for_request_with verb, uri, 'Content-MD5'   => content_md5,
                                                                                 'Content-Type'  => content_type,
                                                                                 'Date'          => date,
                                                                                 'Authorization' => auth_header_in
    auth_header_out.must_equal auth_header_in
  end
end
