#! /usr/bin/env ruby
require 'nokogiri'
require 'logger'
require 'csv'
=begin

rules.xml consists of rules
each rule has following fields:
  RULE ATRUBUTES:

  disable       - attribute which indicates if rule should be currently used
  type        - attribute which indicates if rule is condition
  singleuse     - attribute which indicates if rule will be processed only once
  rulegroup     - attribute which indicates that there are few rules, that should be
              processed one after other on a specific datafield. It's rellevant
              when we have 2 or more datafields with the same tag Y and X rules which
              create output by merging output of rule i to output of rule i-1 when processed
              on the same datafield, so it will be wrong to process rule i-1 on each datafield
              and after that process rule i on each datafield, this will bring us to get
              a-a-b-b instead of a-b-a-b


  TAGS OF TARGET PART:

  sectionTag      - the section name in the output file (optional),
              may appear several times in the same rule
  groupTag      - tag name for a group of identic tags(today is used in search section)
  targetTag     - the name of the tag in the output (mandatory),
              may appear several times in the same rule


  TAGS OF SOURCE PART:

  FOR MARC SOURCE:

  tagField      - source tag from MARC21 (optional),
              may appear several times in the same rule
  tagFieldRange   - range of source tags from MARC21 (optional),contains "first" and "last" tags
              there is possibility to define "step" and then only filtered tags numbers
              will be taken
  ind1        - indicates if we should consider ind1 value in MARC21 (optional)
              ind1 has the attribute "desc" (optionally) that can be
              setted only to "-" which means: rule is relevant only for
              input where ind1 is not equal to the one in the rule, if
              ind1 is defined without "desc": rule is relevant only for
              input where ind1 is equal to the one in the rule
              when "sparam" attribute of indicator is set to true, it's (indicator's) value will
              be passed to the routines as parameter
  ind2        - identic to ind1
  subFieldStart   - defines upper border for subfields (as appears in the source) to be processed
  subFieldEnd     - defines lower border for subfields (as appears in the source) to be processed
  subfieldDesc    - indicates that subcodes defined in the rule should not be
              processed, subfieldDesc can be set only to "-" (optional)
  subFieldCode    - subfield that should be processed by the rule (optional),
              imited to length of one character,
              may appear several times in the same rule

  TAGS FOR NON-MARC XML SOURCE:

  sourceTag     - define xpath of the tag in the source xml
  attribute     - defines expected attribute name and attribute value of the sourceTag
              in the source xml (optional)

  TAGS FOR ADDITIONAL TYPES OF SOURCES:
  valueSource     -   defines source value or it's key for additional types of source

  SOURCE PART ATTRIBUTES:

  type        - defines the type of the source. Default value: "record".
              Wnen set to "constant" the source value will be the string that defined in the valueSource
              When set to "config" the source value will be taken from mapping table according
              to the key specified in the valueSource
              When set to "pnx" the source value will be taken from pnx tag that was created by
              previouse rules, the value will be taken according to xpath, defined in the valueSource


  TAGS FOR ACTION PART:

  checkCondition    -   defines which logic value (true/false) should the condition/s fit in order
              to execute this rule, the "operator" attribute defines how the logic value
              should be computed: and/or condition(by default processed and condition)
  conditionCode   - for rule of type condition indicates prefix for condition code
              which should be used by rule that uses this condition as identifier
              for spesific condition
  conditionTag    - indicates condition of which tag and with which code should
              be used
  routineCode     - routine that should be applied (optional),
              may appear several times in the same rule: separate tag
              will appear in the output for each routine code in the rule
  uniqueParam     - parameter to be passed to routine,makes possible to get
              different value then will be accepted from the same
              routine when the last is applied from another rule
  targetFlag      - indicates if the value should be merged in the output
              to exist tag with the same name (if flag="merge"), or
              another occurence of the same tag will appear in the
              output (if flag="new"),should appear only once (mandatory)
  tagDelim      - defines string that will delimit merged data (optional),
              relevant only when flag="merge", more than one occurence is possible:
              when more than one tagDelims are defined one should defind attribute "count"
              to indicate how many times this delimiter should be used;
              one can also define "newTag" and then in the seria of merges new tag will
              be created
  startSpace      - when set to "true" indicates that space should be added at the
              beginning of the delimeter (needed, because spaces at the end are ignored
              by xml parsers)
  endSpace      - when set to "true" indicates that space should be added at the
              end of the delimeter (needed, because spaces at the end are ignored
              by xml parsers)
  tagExists     - when is set to "false", indicates that new tag should be
              created in the output only if there is none with the same
              name already,(optional),can be set to "true" or "false" only,
              is relevant only when flag="new"

=end


class XmlRulesParser
  attr_reader :doc, :rules, :rules_name, :logger
  def initialize(rules_name)
    @doc = load(rules_name)
    @rules_name = rules_name
    @logger = Logger.new(STDOUT)
  end

  def parse
    conditions = parse_conditions
    @rules = parse_rules(conditions)
  end

  def to_csv
    if @rules.nil?
      puts 'parsing...'
      @rules = parse
    end

    puts 'generating CSV ...'

    CSV.open("rules/#{@rules_name}.csv", 'w') do |csv|
      csv << %w(disabled section field group behaviour type select if then)
      @rules.sort.each do |section, fields|
        fields.each do |field, rules|
          rules.each do |rule|
            behaviour = ''
            if rule['behaviour']['type'].eql?('merge')
              first_delim = rule['behaviour']['delimiters'][0]['delimiter']
              delim_space = rule['behaviour']['delimiters'][0]['space']
              delim_count = rule['behaviour']['delimiters'][0]['count'] || 0
              if rule['behaviour']['delimiters'].length == 2
                other_delim = rule['behaviour']['delimiters'][1]['delimiter']
                other_space = rule['behaviour']['delimiters'][1]['space']
              else
                other_delim = ''
                other_space = 'none'
              end
              behaviour =  "#{rule['behaviour']['type']}, ['#{first_delim}', :#{delim_space}, #{delim_count}, '#{other_delim}', :#{other_space}]"
            else
              behaviour = "#{rule['behaviour']['type']}"
            end

            condition_if = ''
            unless rule['conditions']['rule_conditions'].empty?
              condition_operator = rule['conditions']['operator']
              condition_logic = rule['conditions']['logic']
              rule['conditions']['rule_conditions'].each do |rule_condition|
                condition_if += " #{condition_operator} " if condition_if.size > 0
                condition_if += "#{rule_condition['type']}(#{create_data_content(rule_condition)})"

                routines = ''
                rule_condition['routines'].each do |routine|
                  routine.each do |fn,p|
                    routines += ' AND ' if routines.size > 0
                    if p.nil? || p.length == 0
                      routines += "#{fn}() "
                    else
                      routines += "#{fn}(#{p}) "
                    end

                  end
                end
                condition_if += condition_logic.eql?('false') ? ' <> ': " = #{rule_condition['flag']}(#{routines})"
              end
            end

            condition_then = ''
            rule['routines'].each do |routine|
              routine.each do |fn,p|
                if p.nil? || p.length == 0
                  condition_then += "#{fn}() "
                else
                  condition_then += "#{fn}(#{p}) "
                end
              end
            end

            csv << [rule['disable'], section, field, rule['group'], behaviour, rule['type'], create_data_content(rule), condition_if, condition_then]
          end
        end

      end

    end

  end

  private
  def escaped(s)
    s.gsub("'","\\\\'").gsub('"', '\"')
  end

  def load(rules_name)
    #@logger.info('loading rules')
    primo_dir = ENV['primo_dev']
    #rules_path = "#{primo_dir}/ng/primo/home/profile/publish/publish/production/pipes/#{rules_name}"
    rules_path = "./pipes/#{rules_name}/conf"
    raise "Unable to find rule #{rules_name}" unless File.exists?(rules_path)

    Nokogiri::XML(File.open("#{rules_path}/rules.xml"))
  end


  def parse_conditions
    rules_conditions = {}
    @doc.xpath('/ConversionRules/rule[@type = "condition"]').each do |raw_condition|
      rulegroup = get_rule_group(raw_condition)
      type = get_rule_type(raw_condition)
      data = get_data(raw_condition)
      condition_code = raw_condition.element_children.search('action/conditionCode').text

      routines = get_routines(raw_condition)

      rules_conditions[condition_code] =  {'group'    => rulegroup,
                                           'type'     => type,
                                           'data'     => data,
                                           'routines' => routines}
    end

    rules_conditions
  end

  def parse_rules(rules_conditions)
    rules_store = {}

    @doc.xpath('/ConversionRules/rule[@type != "condition" or not(attribute::type)]').each do |raw_rule|
      rules = []

      section = raw_rule.element_children.search('target/sectionTag').text
      field   = raw_rule.element_children.search('target/targetTag').text

      if section.length == 0
        puts raw_rule
        exit 1
      end

      if rules_store.keys.include?(section) && rules_store[section].keys.include?(field)
        rules = rules_store[section][field]
      end

    # GET rulegroup, ifDisabled and type
      behaviours = get_behaviours(raw_rule)

      rulegroup = get_rule_group(raw_rule)
      disabled = raw_rule.attribute('disable').nil? ? false : raw_rule.attribute('disable').value
      type = get_rule_type(raw_rule)
    # DATA
      data = get_data(raw_rule)

    # ROUTINES
      routines = get_routines(raw_rule)
    # conditions
      conditions = get_conditions(raw_rule, rules_conditions)

      rule = {'type'     => type,
              'data'     => data,
              'disable'  => disabled,
              'group'    => rulegroup,
              'behaviour' => behaviours,
              'conditions' => conditions,
              'routines'  => routines
             }

      rules << rule
      fields = rules_store[section] || {}
      fields[field] = rules

      rules_store[section] = fields
    end
    rules_store
  end

  def create_data_content(rule)
    case rule['type']
      when 'marc'
        tag    = rule['data']['tag']
        ind1   = rule['data']['ind1']
        ind2   = rule['data']['ind2']
        codes  = rule['data']['code']
        in_out = rule['data']['in_out'].eql?('-') ? 'exclude' : 'include'

        data_content = "'#{tag}', '#{ind1.join(',')}', '#{ind2.join(',')}', :#{in_out} => ['#{codes.join(',')}']"
      when 'xml'
        data_content = "'#{rule['data'].to_s}'"
      when 'pnx'
        data_content = "'#{rule['data'].to_s}'"
      when 'constant'
        data_content = "'#{rule['data'].to_s}'"
      when 'config'
        data_content = "'#{rule['data'].to_s}'"
    end

    data_content
  end

  def get_rule_type(raw_rule)
    type = 'xml'
    unless raw_rule.element_children.search('source').attribute('type').nil?
      type = raw_rule.element_children.search('source').attribute('type').value
    end

    if raw_rule.element_children.search('source/tagField').length > 0
      type = 'marc'
    end

    type
  end

  def get_data(raw_rule)
    data = ''
    type = get_rule_type(raw_rule)

    case type
    when 'xml'
      data = raw_rule.element_children.search('source/sourceTag').text
    when 'marc'

      tag = raw_rule.element_children.search('source/tagField').text
      subfieldInOut = raw_rule.element_children.search('source/subFieldDesc').text

      subfieldCodes = []
      raw_rule.element_children.search('source/subFieldCode').each do |code|
        subfieldCodes << code.text
      end

      inds1 = []
      raw_rule.element_children.search('source/ind1').each do |ind1|
        sign = ind1.attribute('desc') && ind1.attribute('desc').value.eql?('-') ? '-' : ''
        v = ind1.attribute('value').value

        inds1 << "#{sign}#{v}"
      end

      inds2 = []
      raw_rule.element_children.search('source/ind2').each do |ind2|
        #inds2 << ind2.attribute('value').value
        sign = ind2.attribute('desc') && ind2.attribute('desc').value.eql?('-') ? '-' : ''
        v = ind2.attribute('value').value

        inds2 << "#{sign}#{v}"

      end


      data = {'tag' => tag,
              'ind1' => inds1,
              'ind2' => inds2,
              'code' => subfieldCodes,
              'in_out' => subfieldInOut}
    else #config, pnx, constant
      data = raw_rule.element_children.search('source/valueSource').text
    end

    data
  end

  def get_rule_group(raw_rule)
    rulegroup = raw_rule.attribute('rulegroup').nil? ? '' : raw_rule.attribute('rulegroup').value
  end

  def get_routines(raw_rule)
    routines = []
    raw_rule.element_children.search('action/routine').each do |action|
      routines << {action.attribute('code').value => action.text}  unless action.attribute('code').value.eql?('null')
    end

    routines
  end

  def get_conditions(raw_rule, rules_conditions)
    conditions = { 'logic'    => 'true',
                   'operator' => 'and',
                   'rule_conditions' => []}
    rule_conditions = []

    check_condition    = raw_rule.element_children.search('action/checkCondition')
    condition_logic    = check_condition.text || 'true'
    condition_operator = check_condition.empty? || check_condition.attribute('operator').nil? ? 'and' : check_condition.attribute('operator').value

    conditions['logic']    = condition_logic
    conditions['operator'] = condition_operator

    raw_rule.element_children.search('action/conditionTag').each do |condition|
      condition_tag = condition.attribute('code').value

      if rules_conditions.include?(condition_tag)
        rule_condition = rules_conditions[condition_tag]
        unless condition.attribute('flag').nil?
          case condition.attribute('flag').value
          when 'one'
            rule_condition['flag'] = 'any'
          when 'serial'
            rule_condition['flag'] = 'current'
          when 'all'
            rule_condition['flag'] = 'all'
          else
            rule_condition['flag'] = 'last'
          end
        else
          rule_condition['flag'] = 'last'
        end

        unless condition.attribute('logic').nil?
          rule_condition['logic'] = condition.attribute('logic').value
        else
          rule_condition['logic'] = 'true'
        end
      end

      rule_conditions << rule_condition
    end
    conditions['rule_conditions'] = rule_conditions
    conditions
  end

  def get_behaviours(raw_rule)
    behaviour = {}
    delimiters = []

    behaviour_type = 'add'
    target_flag = raw_rule.element_children.search('action/targetFlag')

    unless target_flag.attribute('flag').nil?
      #debugger if target_flag.attribute('flag').value.eql?('merge')
      case target_flag.attribute('flag').value
      when 'merge'
        behaviour_type = 'merge'
        tag_delim = raw_rule.element_children.search('action/tagDelim')

        tag_delim.each do |delim|
          space = 'none'
          start_space = !delim.attribute('startSpace').nil? && delim.attribute('startSpace').value.eql?('true')
          end_space   = !delim.attribute('endSpace').nil? && delim.attribute('endSpace').value.eql?('true')
          count       = delim.attribute('count').value || 0 unless delim.attribute('count').nil?

          if start_space && end_space
            space = 'both'
          elsif start_space && !end_space
            space = 'before'
          elsif !start_space && end_space
            space = 'after'
          else
            space = 'none'
          end


          delimiters << {'delimiter' => delim.text,
                         'count'     => count,
                         'space'     => space
                       }
        end
      when 'new'
        tag_exists = raw_rule.element_children.search('action/tagExists')
        #unless tag_exists.attribute('flag').nil?
          if tag_exists.text.eql?('false')
            behaviour_type = 'or'
          end
        #end
      else
        behaviour_type = 'and'
      end
    end

    behaviour = {'type' => behaviour_type, 'delimiters' => delimiters }
  end
end
