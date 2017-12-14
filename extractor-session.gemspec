Gem::Specification.new do |spec|
  spec.name        = 'extractor-session'
  spec.version     = '1.1.1'
  spec.authors     = ['x']
  spec.email       = 'user@example.com'
  spec.homepage    = 'https://www.example.com/'
  spec.summary     = 'Extracto do sesion'
  spec.description = 'Extracto do sesion'
  spec.required_rubygems_version = '>= 1.3'

  spec.files         = Dir['**/*'].keep_if { |file| File.file?(file) }
  spec.executables   = []
  spec.test_files    = spec.files.grep(%r{^spec/})
  spec.require_paths = ['lib']

  spec.add_dependency 'httparty'
  spec.add_dependency 'activesupport'

end
