ENV['RAILS_ENV'] ||= 'test'
unless ENV['SKIP_COV']
  require 'simplecov'
  require 'simplecov-rcov'
  SimpleCov.formatter = SimpleCov::Formatter::MultiFormatter[
    SimpleCov::Formatter::HTMLFormatter,
    SimpleCov::Formatter::RcovFormatter
  ]
end
require 'spec_support/shared_daemons'
require 'aws-sdk-core'

RSpec.configure do |config|
  config.expect_with :rspec do |expectations|
    expectations.include_chain_clauses_in_custom_matcher_descriptions = true
    expectations.syntax = :expect
  end

  config.mock_with :rspec do |mocks|
    mocks.verify_partial_doubles = true
    mocks.syntax = :expect
  end

  config.disable_monkey_patching!
  config.default_formatter = 'doc' if config.files_to_run.one?

  config.filter_run focus: true
  config.run_all_when_everything_filtered = true
  config.order = :random
  config.before(:each) do
    Aws.config[:credentials] = Aws::Credentials.new 'test', 'test'
    Aws.config[:region] = 'eu-west-1'
    Aws.config[:stub_responses] = true
  end
end
