include Rake::DSL

task :environment do
  require 'bundler/setup'
  lib = File.expand_path('../lib', __FILE__)
  $LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
  require 'extractor-session'
end

desc 'enter a REPL console within this project environment'
task :console => :environment do
  require 'irb'
  require 'irb/completion'
  ARGV.clear
  IRB.start
end
