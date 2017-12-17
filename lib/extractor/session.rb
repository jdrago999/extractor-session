
module Extractor
  class Session

    include HTTParty

    delegate :get, :post, :put, :delete, :options, to: :http

    attr_accessor :email, :password, :proxy, :socks_proxy, :user_agent, :signed_in, :cookies, :http, :profile_url_template

    def initialize(email:, password:, proxy: nil, socks_proxy: nil, user_agent:, cookies:{}, profile_url_template:)
      self.email = email
      self.password = password
      self.proxy = proxy
      self.socks_proxy = socks_proxy
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

      profile_response = get_profile_page!(profile_url)
      li_page_instance = %r{urn\:li\:page\:d_flagship3_profile_view_base\;(.+?)\&\#61\;\&\#61\;\s*?\S}.match(profile_response.body)[1]
      uri = URI(profile_url)
      username = uri.path.split('/')[-1]

      data_url = profile_url_template % username
      response = get(data_url,
        headers: {
          'x-li-lang' => 'en_US',
          'dnt' => '1',
          'accept-language' => 'en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7',
          'x-requested-with' => 'XMLHttpRequest',
          'x-restli-protocol-version' => '2.0.0',
          'x-li-page-instance' => ('urn:li:page:d_flagship3_profile_view_base;vOmiO/%s==' % li_page_instance ),
          'x-li-track' => '{"clientVersion":"1.1.*","osName":"web","timezoneOffset":-8,"deviceFormFactor":"DESKTOP","mpName":"voyager-web"}',
          'authority' => URI(http.base_uri).host,
          'accept-language' => 'en-US,en;',
          'origin' => http.base_uri,
          'cookie' => (cookies.each.map{ |k,v| '%s="%s"' % [k,v] }.join('; ')),
          'csrf-token' => cookies['JSESSIONID'],
          'accept' => 'application/vnd.linkedin.normalized+json',
          'referer' => 'https://' + URI(http.base_uri).host + '/in/' + username
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
      elsif socks_proxy
        proxy_host, proxy_port = socks_proxy.split(':')
        http.socks_proxy proxy_host, proxy_port.to_i
      end

      login_response = get_login_page!
      sleep 1
      get_auth_token!
      submit_login!(login_response.body)
    end

    def to_h
      {
        email: email,
        password: password,
        proxy: proxy,
        socks_proxy: socks_proxy,
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
        response
      when 403
        raise Extractor::NotAuthorizedError.new(response)
      else
        raise StandardError.new(response)
      end
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
        self.cookies['visit'] = new_cookies.fetch('visit')
        self.cookies['lang'] = new_cookies.fetch('lang')
        self.cookies['liap'] = true
      when 403
        raise Extractor::NotAuthorizedError.new(response)
      else
        raise StandardError.new(response)
      end
      sleep 1
    end

    def submit_login!(body)
      login_csrf_param = %r{<input name="loginCsrfParam" id="loginCsrfParam-login" type="hidden" value="(.+?)"/>}.match(body)[1]
      response = post('/uas/login-submit',
        follow_redirects: false,
        headers: {
          'content-type' => 'application/x-www-form-urlencoded',
          'authority' => URI(http.base_uri).host,
          'cookie' => (cookies.each.map{ |k,v| '%s="%s"' % [k,v] }.join('; ')),
        },
        body: URI.encode_www_form(
          session_key: email,
          session_password: password,
          isJsEnabled: false,
          loginCsrfParam: login_csrf_param,
        )
      )
      case response.code
      when 302
        if response.header['location'] !~ %r{/feed/$}
          raise StandardError.new("Unespected location: header -- '#{response.header['location']}'")
        end
        new_cookies = parse_cookies(response)
        self.cookies.delete('leo_auth_token')
        self.cookies['li_at'] = new_cookies.fetch('li_at')
        self.cookies['liap'] = new_cookies.fetch('liap')
        self.signed_in = true
      when 403
        raise Extractor::NotAuthorizedError.new(response)
      else
        raise StandardError.new(response)
      end
      sleep 1
    end

    def get_profile_page!(profile_url)
      path = URI(profile_url).path
      response = get(path,
        headers: {
          'accept' => 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
          'accept-language' => 'en-US,en;',
          'cookie' => (cookies.each.map{ |k,v| '%s="%s"' % [k,v] }.join('; ')),
        }
      )
      case response.code
      when 200
        # yay
        response
      else
        raise StandardError.new(response)
      end
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
