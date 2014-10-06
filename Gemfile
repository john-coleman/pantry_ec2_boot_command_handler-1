source 'https://rubygems.org'

gem 'activesupport'
gem 'aws-sdk', '~> 1.25'
gem 'daemons'
gem 'pantry_daemon_common', git: 'git@github.com:wongatech/pantry_daemon_common.git', tag: 'v0.2.6'

group :development do
  gem 'bundler-audit', require: false
  gem 'guard-rspec'
  gem 'guard-bundler'
end

group :test, :development do
  gem 'awesome_print'
  gem 'pry'
  gem 'rake'
  gem 'rspec', '~> 3.0'
  gem 'rubocop'
  gem 'simplecov', require: false
  gem 'simplecov-rcov', require: false
end
