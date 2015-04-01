require 'test_helper'

class QueryProxyServerIntegrationTest < Minitest::Spec

  # must match the values in the nginx config file
  SCM_ACCESS_KEY      = '123'
  SCM_SECRET_TOKEN    = '456'
  KOOABA_ACCESS_KEY   = 'e09800f9-038d-4071-a0aa-7b64d47f28a5'
  KOOABA_SECRET_TOKEN = 'fLEFBenljgrcXM515tf7e9GFp2xNFsLHjFlHf45v'

  before do
    Nginx.ensure_running File.join(File.dirname(__FILE__), 'fixtures/nginx_with_real_backend.conf')
  end

  let(:file_name)    { File.join(File.dirname(__FILE__), 'fixtures/shortcut.jpg') }
  let(:payload)      { {image: Faraday::UploadIO.new(file_name, `file --mime-type --brief #{file_name}`.strip)} }
  let(:verb)         { 'POST' }
  let(:content_md5)  { '2d40292b72cb5252b7c73430f028729b' } # TODO: calculate instead of hardcode
  let(:content_type) { 'multipart/form-data' }
  let(:date)         { DateTime.now.rfc822 }
  let(:uri)          { '/v4/query' }

  let(:digest) { "#{verb}\n#{content_md5}\n#{content_type}\n#{date}\n#{uri}" }

  let(:scm_signature)    { Base64.encode64(OpenSSL::HMAC.digest('sha1', SCM_SECRET_TOKEN, digest)).strip }
  let(:kooaba_signature) { Base64.encode64(OpenSSL::HMAC.digest('sha1', KOOABA_SECRET_TOKEN, digest)).strip }

  let(:connection) do
    Faraday::Connection.new('http://localhost:8882') do |conn|
      conn.request :multipart
      conn.adapter Faraday.default_adapter
    end
  end

  it 'must work with a valid, well-formed request' do
    authorization = "SCMA #{SCM_ACCESS_KEY}:#{scm_signature}"

    response = connection.send verb.to_s.downcase, uri, payload, 'Content-MD5'   => content_md5,
                                                                 'Content-Type'  => content_type,
                                                                 'Date'          => date,
                                                                 'Authorization' => authorization
    response.status.must_equal 200

    begin
      json = JSON.parse response.body
      json['results'][0]['title'].must_equal 'query proxy server test item'
    rescue
      raise "unexpected response body: #{response.body}"
    end
  end

  it 'must work with a (legacy) kooaba Authorization header' do
    authorization = "KA #{KOOABA_ACCESS_KEY}:#{kooaba_signature}"

    response = connection.send verb.to_s.downcase, uri, payload, 'Content-MD5'   => content_md5,
                                                                 'Content-Type'  => content_type,
                                                                 'Date'          => date,
                                                                 'Authorization' => authorization
    response.status.must_equal 200

    begin
      json = JSON.parse response.body
      json['results'][0]['title'].must_equal 'query proxy server test item'
    rescue
      raise "unexpected response body: #{response.body}"
    end
  end

  it 'must return a 401 when missing the Authorization header' do
    response = connection.send verb.to_s.downcase, uri, payload, 'Content-MD5'   => content_md5,
                                                                 'Content-Type'  => content_type,
                                                                 'Date'          => date
    response.status.must_equal 401
  end

  it 'must return a 401 when the Authorization header is invalid' do
    authorization = "SCMA something:invalid"

    response = connection.send verb.to_s.downcase, uri, payload, 'Content-MD5'   => content_md5,
                                                                 'Content-Type'  => content_type,
                                                                 'Date'          => date,
                                                                 'Authorization' => authorization
    response.status.must_equal 401
  end
end
