# -*- encoding: utf-8 -*-
# stub: standard-performance 1.4.0 ruby lib

Gem::Specification.new do |s|
  s.name = "standard-performance".freeze
  s.version = "1.4.0".freeze

  s.required_rubygems_version = Gem::Requirement.new(">= 0".freeze) if s.respond_to? :required_rubygems_version=
  s.metadata = { "changelog_uri" => "https://github.com/standardrb/standard-performance/blob/main/CHANGELOG.md", "default_lint_roller_plugin" => "Standard::Performance::Plugin", "homepage_uri" => "https://github.com/standardrb/standard-performance", "source_code_uri" => "https://github.com/standardrb/standard-performance" } if s.respond_to? :metadata=
  s.require_paths = ["lib".freeze]
  s.authors = ["Justin Searls".freeze]
  s.bindir = "exe".freeze
  s.date = "2024-05-14"
  s.email = ["searls@gmail.com".freeze]
  s.homepage = "https://github.com/standardrb/standard-performance".freeze
  s.licenses = ["MIT".freeze]
  s.required_ruby_version = Gem::Requirement.new(">= 2.7.0".freeze)
  s.rubygems_version = "3.1.6".freeze
  s.summary = "Standard Ruby Plugin providing configuration for rubocop-performance".freeze

  s.installed_by_version = "3.5.22".freeze

  s.specification_version = 4

  s.add_runtime_dependency(%q<lint_roller>.freeze, ["~> 1.1".freeze])
  s.add_runtime_dependency(%q<rubocop-performance>.freeze, ["~> 1.21.0".freeze])
end
