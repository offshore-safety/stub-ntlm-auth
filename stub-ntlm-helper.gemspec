# -*- encoding: utf-8 -*-
Gem::Specification.new do |s|
  s.name        = 'stub-ntlm-helper'
  s.version     = '0.0.1'
  s.platform    = Gem::Platform::RUBY
  s.authors     = ['Scott Robinson', 'Mustafa Sezgin']
  s.email       = ['sr@thoughtworks.com', 'msezgin@thoughtworks.com']
  s.description = 'A stub for ntlm_helper'
  s.summary     = s.description

  s.files         = `git ls-files`.split "\n"
  s.test_files    = `git ls-files -- {test,spec,features}/*`.split "\n"
  s.executables   = `git ls-files -- bin/*`.split("\n").map { |f| File.basename(f) }
  s.require_paths = ['lib']

  s.add_development_dependency 'rspec'
  s.add_development_dependency 'rake'

  s.add_dependency 'bindata'
end
