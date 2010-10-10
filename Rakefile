require 'bundler'
Bundler.setup

$LOAD_PATH.push "./lib"
require 'net/ldap'
require 'rspec/core/rake_task'

RSpec::Core::RakeTask.new('default') do |t|
  t.pattern = 'spec/ldap/**/*_spec.rb'
end

desc "Run specs that require a connection to a live test server"
RSpec::Core::RakeTask.new('live') do |t|
  t.pattern = 'spec/live/**/*_spec.rb'
end