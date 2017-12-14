
# extractor_session

Extracts the data

## Usage

```ruby
gem 'extractor-session'
require 'extractor-session'

session = Extractor::Session.new(
  email: ENV.fetch('EMAIL'),
  password: ENV.fetch('PASSWORD'),
  user_agent: ENV.fetch('USER_AGENT'),
  proxy: ENV.fetch('PROXY_ADDR'),
  profile_url_template: 'https://www.example.com/profile/%s'
)

begin
  profile = session.fetch_profile!(url: 'https://example.com/some/profile')
rescue Extractor::ProxyError => e
  # Proxy blew up
  raise e
rescue Extractor::NotAuthorizedError => e
  # Burned the login
  raise e
rescue Extractor::InvalidProfileUrlError => e
  # Bad profile url
  raise e
rescue StandardError => e
  # Something unexpected
  raise e
end
```
