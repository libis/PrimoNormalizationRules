#!/usr/bin/env ruby
$LOAD_PATH << './lib'
require 'rubygems'
require 'xml_rules_parser'
require 'pp'

#################################################
if ARGV.size != 1
  puts "USAGE #{__FILE__} RULES_NAME"
  exit 0
end

rules_conditions = {}
rules_store = {}
rule_parser = XmlRulesParser.new(ARGV[0])


#pp rule_parser.parse
rule_parser.to_csv