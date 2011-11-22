# -*- encoding: utf-8 -*-
Gem::Specification.new do |s|
  s.name        = 'stub-ntlm-auth'
  s.version     = '0.0.1'
  s.platform    = Gem::Platform::RUBY
  s.authors     = ['Scott Robinson', 'Mustafa Sezgin']
  s.email       = ['sr@thoughtworks.com', 'msezgin@thoughtworks.com']
  s.summary      = 'This is a stub ntlm_auth helper. It always authenticates.'
  s.description = <<-EOF
Using Apache or Squid or whatever with NTLM? Ever had Active Directory arbitrarily hate winbind?

I feel for you.

Sometimes, passwords and security and Kerberos just don't matter.

This is a stub ntlm_auth helper. It always authenticates.
  EOF
  s.homepage    = 'https://github.com/offshore-safety/stub-ntlm-auth'

  s.files         = `git ls-files`.split "\n"
  s.test_files    = `git ls-files -- {test,spec,features}/*`.split "\n"
  s.executables   = `git ls-files -- bin/*`.split("\n").map { |f| File.basename(f) }
  s.require_paths = ['lib']

  s.add_development_dependency 'rspec'
  s.add_development_dependency 'rake'

  s.add_dependency 'bindata'
end
