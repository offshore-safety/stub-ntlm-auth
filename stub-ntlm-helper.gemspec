# -*- encoding: utf-8 -*-
$:.push File.expand_path '../lib', __FILE__
require 'stub-ntlm-helper/version'

Gem::Specification.new do |s| 
  s.name        = StubNTLMHelper::NAME
  s.version     = StubNTLMHelper::VERSION
  s.platform    = Gem::Platform::RUBY
  s.authors     = ['Scott Robinson']
  s.email       = ['sr@thoughtworks.com']
  s.summary     = %q{A stub for ntlm_helper}
  s.summary     = s.description

  s.files         = `git ls-files`.split "\n"
  s.test_files    = `git ls-files -- {test,spec,features}/*`.split "\n"
  s.executables   = `git ls-files -- bin/*`.split("\n").map { |f| File.basename(f) }
  s.require_paths = ['lib']

  s.add_development_dependency 'rspec'
  s.add_development_dependency 'rake'
end
