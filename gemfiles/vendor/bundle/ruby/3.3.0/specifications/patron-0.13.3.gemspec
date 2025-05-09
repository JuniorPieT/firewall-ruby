# -*- encoding: utf-8 -*-
# stub: patron 0.13.3 ruby lib ext
# stub: ext/patron/extconf.rb

Gem::Specification.new do |s|
  s.name = "patron".freeze
  s.version = "0.13.3".freeze

  s.required_rubygems_version = Gem::Requirement.new(">= 1.2.0".freeze) if s.respond_to? :required_rubygems_version=
  s.metadata = { "allowed_push_host" => "https://rubygems.org" } if s.respond_to? :metadata=
  s.require_paths = ["lib".freeze, "ext".freeze]
  s.authors = ["Phillip Toland".freeze]
  s.bindir = "exe".freeze
  s.date = "2019-05-22"
  s.description = "Ruby HTTP client library based on libcurl".freeze
  s.email = ["phil.toland@gmail.com".freeze]
  s.extensions = ["ext/patron/extconf.rb".freeze]
  s.files = ["ext/patron/extconf.rb".freeze]
  s.homepage = "https://github.com/toland/patron".freeze
  s.post_install_message = "\nThank you for installing Patron. On OSX, make sure you are using libCURL with OpenSSL.\nSecureTransport-based builds might cause crashes in forking environment.\n\nFor more info see https://github.com/curl/curl/issues/788\n".freeze
  s.rubygems_version = "2.7.6".freeze
  s.summary = "Patron HTTP Client".freeze

  s.installed_by_version = "3.5.22".freeze

  s.specification_version = 4

  s.add_development_dependency(%q<rake>.freeze, ["~> 10".freeze])
  s.add_development_dependency(%q<bundler>.freeze, [">= 0".freeze])
  s.add_development_dependency(%q<rspec>.freeze, [">= 2.3.0".freeze])
  s.add_development_dependency(%q<simplecov>.freeze, ["~> 0.10".freeze])
  s.add_development_dependency(%q<yard>.freeze, ["~> 0.9.11".freeze])
  s.add_development_dependency(%q<rack>.freeze, ["~> 1".freeze])
  s.add_development_dependency(%q<puma>.freeze, ["~> 3.11".freeze])
  s.add_development_dependency(%q<rake-compiler>.freeze, [">= 0".freeze])
end
