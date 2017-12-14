
module Extractor
  class Session

    include HTTParty

    delegate :get, :post, :put, :delete, :options, to: :http

    attr_accessor :email, :password, :proxy, :user_agent, :signed_in, :cookies, :http, :profile_url_template

    def initialize(email:, password:, proxy: nil, user_agent:, cookies:{}, profile_url_template:)
      self.email = email
      self.password = password
      self.proxy = proxy
      self.user_agent = user_agent
      self.cookies = cookies
      self.profile_url_template = profile_url_template
    end

    def fetch_profile!(profile_url:)
      unless signed_in?
        sign_in!
      end
      if profile_url =~ %r{/pub/}
        raise InvalidProfileUrlError.new 'URLs matching /pub/ are not allowed'
      end

      uri = URI(profile_url)
      username = uri.path.split('/')[-1]

      data_url = profile_url_template % username
      response = get(data_url,
        headers: {
          'authority' => URI(http.base_uri).host,
          'accept-language' => 'en-US,en;q=0.8,zh-CN;q=0.6,zh;q=0.4',
          'upgrade-insecure-requests' => '1',
          'origin' => http.base_uri,
          'cookie' => (cookies.each.map{ |k,v| '%s="%s"' % [k,v] }.join('; ')),
          'csrf-token' => cookies['JSESSIONID'],
          'x-restli-protocol-version' => '2.0.0',
          'accept' => 'application/json',
          'referer' => 'https://' + URI(http.base_uri).host + '/'
        }
      )
      case response.code
      when 200
        return response.body
      else
        raise StandardError.new(response)
      end
    end

    def sign_in!
      uri = URI(profile_url_template % 'foo')
      base_uri = "#{uri.scheme}://#{uri.host}"
      http.base_uri base_uri
      http.debug_output
      http.headers 'User-Agent' => user_agent
      if proxy
        proxy_host, proxy_port = proxy.split(':')
        http.http_proxy proxy_host, proxy_port.to_i
      end

      get_login_page!
      get_auth_token!
      submit_login!
    end

    def to_h
      {
        email: email,
        password: password,
        proxy: proxy,
        user_agent: user_agent,
        cookies: cookies,
        profile_url_template: profile_url_template
      }
    end

    private

    def get_login_page!
      response = get('/')
      case response.code
      when 200
        self.cookies = parse_cookies(response)
      when 403
        raise Extractor::NotAuthorizedError.new(response)
      else
      end
      sleep 1
    end

    def get_auth_token!
      response = post('/lite/platformtelemetry',
        headers: {
          'content-type' => 'application/json',
          'content-encoding' => 'base64',
          'cookie' => (cookies.each.map{ |k,v| '%s="%s"' % [k,v] }.join('; '))
        },
        body: 'eyJcdTAwNzBcdTAwNzRcdTAwMmRcdTAwNzJcdTAwNjVcdTAwNzBcdTAwNmZcdTAwNzJcdTAwNzQiOnsiXHUwMDYzXHUwMDc2IjoiMFx1MDAyZTBcdTAwMmUwIn19'
      )
      case response.code
      when 200
        new_cookies = parse_cookies(response)
        self.cookies['leo_auth_token'] = new_cookies['leo_auth_token']
        self.cookies['visit'] = new_cookies['visit']
      when 403
        raise Extractor::NotAuthorizedError.new(response)
      else
      end
      sleep 1
    end

    def submit_login!
      response = post('/uas/login-submit',
        headers: {
          'content-type' => 'application/x-www-form-urlencoded',
          'authority' => URI(http.base_uri).host,
          'cookie' => (cookies.each.map{ |k,v| '%s="%s"' % [k,v] }.join('; ')),
        },
        body: URI.encode_www_form(session_key: email, session_password: password)
      )
      case response.code
      when 200
        new_cookies = parse_cookies(response)
        if new_cookies.key? 'leo_auth_token'
          self.cookies['leo_auth_token'] = new_cookies['leo_auth_token']
          self.signed_in = true
        end
      when 403
        raise Extractor::NotAuthorizedError.new(response)
      else
      end
      sleep 1
    end

    def http
      self.class
    end

    def signed_in?
      !!signed_in
    end

    def parse_cookies(resp)
      cookie_hash = {}
      resp.get_fields('Set-Cookie').each do |cookie|
        cookie = cookie.split(';').first
        name, value = %r{^(\w+)\="?(.+?)"?$}.match(cookie)[1,2]
        cookie_hash[name] = value
      end
      cookie_hash
    end
  end
end
