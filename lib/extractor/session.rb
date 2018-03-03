
module Extractor
  class Session

    include HTTParty

    delegate :get, :post, :put, :delete, :options, to: :http

    attr_accessor :email, :password, :socks_proxy, :user_agent, :signed_in, :cookies, :http, :profile_url_template

    def initialize(email:, password:, socks_proxy: nil, user_agent:, cookies:{}, profile_url_template:, debug: false)
      self.email = email
      self.password = password
      self.socks_proxy = socks_proxy
      self.user_agent = user_agent
      self.cookies = cookies
      self.profile_url_template = profile_url_template

      uri = URI(profile_url_template % 'foo')
      base_uri = "#{uri.scheme}://#{uri.host}"
      http.base_uri base_uri
      if debug
        http.debug_output
      end
      http.headers 'User-Agent' => user_agent
      if socks_proxy
        proxy_host, proxy_port = socks_proxy.split(':')
        http.socks_proxy proxy_host, proxy_port.to_i
      end
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
      begin
        uri = URI.parse(profile_url)
      rescue URI::InvalidURIError
        uri = URI.parse(URI.escape(profile_url))
      end
      username = uri.path.split('/')[-1]

      data_url = profile_url_template % username
      response = get(data_url,
        headers: {
          'x-li-lang' => 'en_US',
          'dnt' => '1',
          'x-requested-with' => 'XMLHttpRequest',
          'x-restli-protocol-version' => '2.0.0',
          'x-li-page-instance' => ('urn:li:page:d_flagship3_profile_view_base;vOmiO/%s==' % li_page_instance ),
          'x-li-track' => '{"clientVersion":"1.1.*","osName":"web","timezoneOffset":-8,"deviceFormFactor":"DESKTOP","mpName":"voyager-web"}',
          'authority' => URI(http.base_uri).host,
          'accept-language' => 'en-US,en;',
          'origin' => http.base_uri,
          'cookie' => (cookies.each.map{ |k,v| '%s="%s"' % [k,v] }.join('; ')),
          'csrf-token' => cookies['JSESSIONID'],
          'accept' => ('application/vnd.%s.normalized+json' % ENV.fetch('PARTNERID')),
          'referer' => 'https://' + URI(http.base_uri).host + '/in/' + username
        }
      )
      case response.code
      when 200
        return response.body
      when 403
        # Expect: {"exceptionClass":"...UserVisibleException","message":"...can't be accessed","status":403}
        data = JSON.parse(response.body)
        if data['exceptionClass'].to_s =~ %r{UserVisibleException$}
          raise Extractor::UserVisibilityError.new(response)
        end
      when 503
        warn '///// RETRY(%s)...' % path
        sleep 10
        return fetch_profile!(profile_url)
      else
        raise StandardError.new(response)
      end
    end

    def fetch_directory_page!(url:)
      response = get(url,
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
      when 503
        warn '///// RETRY(%s)...' % path
        sleep 10
        return fetch_directory_page!(url)
      else
        raise StandardError.new(response)
      end
    end

    def fetch_pub_dir_page!(url:)
      response = get(url,
        follow_redirects: false,
        headers: {
          'accept' => 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
          'accept-language' => 'en-US,en;',
          'cookie' => (cookies.each.map{ |k,v| '%s="%s"' % [k,v] }.join('; ')),
        }
      )
      case response.code
      when 300..399
        # yay
        response
      when 503
        warn '///// RETRY(%s)...' % path
        sleep 10
        return fetch_pub_dir_page!(url)
      else
        raise StandardError.new(response)
      end
    end

    def fetch_results_page!(url:)
      response = get(url,
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
      when 503
        warn '///// RETRY(%s)...' % path
        sleep 10
        return fetch_results_page!(url)
      else
        raise StandardError.new(response)
      end
    end

    def sign_in!
      # Empty the mailbox in case we plan on receiving an email challenge later:
      pop3.delete_all
      login_response = get_login_page!
      sleep 1
      get_auth_token!
      submit_login!(login_response.body)
    end

    def to_h
      {
        email: email,
        password: password,
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
      when 503
        warn '///// RETRY(%s)...' % path
        sleep 10
        return get_login_page!
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
      when 503
        warn '///// RETRY(%s)...' % path
        sleep 10
        return get_auth_token!
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
        if response.header['location'] =~ %r{/uas/consumer-email-challenge$}
          handle_email_challenge(response)
        elsif response.header['location'] =~ %r{/uas/account-restricted}
          raise Extractor::NotAuthorizedError.new(response)
        else
          return handle_login_success_response(response)
        end
      when 403
        raise Extractor::NotAuthorizedError.new(response)
      when 503
        warn '///// RETRY(%s)...' % path
        sleep 10
        return submit_login!(body)
      else
        raise StandardError.new(response)
      end
    end

    def handle_email_challenge(response)
      warn "------------------ GOT EMAIL CHALLENGE --------------------"

      path = URI(response.header['location']).path
      @chp_token = parse_cookies(response)['chp_token']
      @rt = ('s=%d&r=%s' % [Time.now.to_i + 86353, 'https://' + URI(http.base_uri).host + '/'])
      response = get(path,
        headers: {
          'accept' => 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
          'accept-language' => 'en-US,en;',
          'cookie' => (cookies.each.map{ |k,v| '%s="%s"' % [k,v] }.join('; ')),
          'referer' => 'https://' + URI(http.base_uri).host + '/',
        }
      )
      @dts = %r{<input.+?name\="dts".+?value\="(.+?)"}.match(response.body)[1]
      new_cookies = parse_cookies(response)
      cookies['leo_auth_token'] = new_cookies['leo_auth_token']

      pin = get_latest_email_challenge_pin(response)
      warn "/////////////////// PIN(#{pin}) //////////////////////"
      response = post('/uas/ato-pin-challenge-submit',
        headers: {
          'content-type' => 'application/x-www-form-urlencoded',
          'authority' => URI(http.base_uri).host,
          'cookie' => (cookies.merge(
            'chp_token' => @chp_token,
            'RT' => @rt
          ).each.map{ |k,v| '%s="%s"' % [k,v] }.join('; ')),
          'referer' => 'https://' + URI(http.base_uri).host + '/',
        },
        follow_redirects: false,
        body: URI.encode_www_form(
          'PinVerificationForm_pinParam' => pin,
          'signin' => 'Submit',
          'security-challenge-id' => %r{<input type="hidden" name="security-challenge-id" value="(.+?)"}.match(response.body)[1],
          'dts' => @dts,
          'origSourceAlias' => '',
          'csrfToken' => cookies['JSESSIONID'],
          'sourceAlias' => %r{<input type="hidden" name="sourceAlias" value="(.+?)"}.match(response.body)[1],
        )
      )
      case response.code.to_i
      when 302
        if response.header['location'] =~ %r{(?:/feed/|/check/add-phone)$}
          return handle_login_success_response(response)
        else
          raise StandardError.new(response)
        end
      when 503
        warn '///// RETRY(%s)...' % path
        sleep 10
        return handle_email_challenge(response)
      else
        raise StandardError.new(response)
      end
    end

    def get_latest_email_challenge_pin(response)
      resend_pin_to_email(response)

      loop do
        last_message = pop3.last

        # pop3 has a weird behavior where .last returns an empty array instead of
        # a single item or nil:
        if last_message.is_a? Array
          sleep 5
          next
        end

        if last_message.subject =~ %r{, here's your PIN$}
          text =  last_message.parts.find{|x| x.content_type =~ %r{text/plain} }.body
          pin = %r{Please use this verification code to complete your sign in: (\d{6,6})}.match(text.to_s)[1] rescue nil
          if pin
            return pin
          end
        end

        # Wait a bit for the email to arrive
        sleep 5
      end
    end

    def resend_pin_to_email(response)

      pin_request_path = '/uas/ato-challenge-send-pin?csrfToken=%s&dts=%s&rnd=%d' % [
        cookies['JSESSIONID'].gsub(':', '%3A'),
        @dts,
        Time.now.to_i * 1000
      ]
      response = post(pin_request_path,
        headers: {
          'accept' => 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
          'accept-language' => 'en-US,en;',
          'cookie' => (cookies.merge(
            'chp_token' => @chp_token,
            'RT' => @rt
          ).each.map{ |k,v| '%s="%s"' % [k,v] }.join('; ')),
          'referer' => 'https://' + URI(http.base_uri).host + '/',
          'x-isajaxform' => '1',
          ('x-%s-tracedatacontext' % ENV.fetch('PARTNERID')) => ('X-LI-ORIGIN-UUID=%s' % response.headers['x-li-uuid']),
          'x-requested-with' => 'XMLHttpRequest'
        }
      )
      case response.code.to_i
      when 200
        # Yay
        true
      when 503
        warn '///// RETRY(%s)...' % path
        sleep 10
        return resend_pin_to_email(response)
      else
        warn 'Cannot resend email challenge PIN'
        raise StandardError.new(response)
      end
    end

    def handle_login_success_response(response)
      new_cookies = parse_cookies(response)
      self.cookies.delete('leo_auth_token')
      unless new_cookies.key?('li_at')
        puts "Cookie 'li_at' not found -- response:"
        pp cookies: cookies, response_code: response.code, location_header: response.header['location']
        raise NotAuthorizedError.new({resposne_code: response.code, location_header: response.header['location']}.to_json)
      end
      self.cookies['li_at'] = new_cookies.fetch('li_at')
      self.cookies['liap'] = new_cookies.fetch('liap')
      self.signed_in = true
      if response.header['location'] =~ %r{/check/add-phone$}
        dismiss_phone_check!
      elsif response.header['location'] !~ %r{/feed/$}
        raise StandardError.new("Unespected location: header -- '#{response.header['location']}'")
      end

      sleep 1
    end

    def dismiss_phone_check!
      response = post('/checkpoint/post-login/security/dismiss-phone-event',
        follow_redirects: false,
        headers: {
          'referer': 'https://%s/check/add-phone' % URI(http.base_uri).host,
          'authority' => URI(http.base_uri).host,
          'origin' => 'https://%s' % URI(http.base_uri).host,
          'cookie' => (cookies.each.map{ |k,v| '%s="%s"' % [k,v] }.join('; ')),
          'x-isajaxform' => '1',
          'x-requested-with' => 'XMLHttpRequest',
          'csrf-token' => cookies['JSESSIONID'],
        }
      )
      case response.code.to_i
      when 200..399
        # Phew
      when 503
        warn '///// RETRY(%s)...' % path
        sleep 10
        return dismiss_phone_check!
      else
        warn 'Cannot dismiss phone check'
        raise StandardError.new(response)
      end
    end

    def pop3
      @pop3 ||= Mail::POP3.new(
        address: 'pop.mail.ru',
        port: 995,
        user_name: email,
        password: password,
        enable_ssl: true
      )
    end

    def get_profile_page!(profile_url)
      begin
        path = URI(profile_url).path
      rescue
        path = URI.parse(URI.escape(profile_url)).path
      end
      response = get(path,
        headers: {
          'accept' => 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
          'accept-language' => 'en-US,en;',
          'cookie' => (cookies.each.map{ |k,v| '%s="%s"' % [k,v] }.join('; ')),
        }
      )
      warn '///// FETCH(%s) -> %d' % [path, response.code]
      case response.code
      when 200
        # yay
        response
      when 503
        warn '///// RETRY(%s)...' % path
        sleep 10
        return get_profile_page!(profile_url)
      else
        raise StandardError.new(response)
      end
    end

    def http
      self.class
    end

    def signed_in?
      self.cookies.key?('liap') && self.cookies.key?('liap')
    end

    def parse_cookies(resp)
      cookie_hash = {}
      (resp.get_fields('Set-Cookie') || []).each do |cookie|
        cookie = cookie.split(';').first
        name, value = %r{^(\w+)\="?(.+?)"?$}.match(cookie)[1,2]
        cookie_hash[name] = value
      end
      cookie_hash
    end
  end
end
