source 'https://rubygems.org'

gem 'daemons'
gem 'aws-sdk', '~> 1.25'
gem 'pantry_daemon_common', git: 'git@github.com:wongatech/pantry_daemon_common.git', :tag => 'v0.2.6'
gem 'activesupport'

group :development do
  gem 'guard-rspec'
  gem 'guard-bundler'
end

group :test, :development do
  gem 'simplecov', require: false
  gem 'simplecov-rcov', require: false
  gem 'rspec', '~> 3.0'
  gem  'debugger', '>= 1.6.6'
  gem 'pry-debugger'
  gem 'rake'
end
