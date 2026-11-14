# frozen_string_literal: true

# Parses the Shadowrocket and Quantumult X rule lists used by lazy.conf.
# No network access or filesystem mutation takes place in this module.
module LazyFixRules
  class ParseError < ArgumentError; end
  class UnsupportedRuleError < ArgumentError; end

  ALIASES = {
    'HOST' => 'DOMAIN',
    'HOST-SUFFIX' => 'DOMAIN-SUFFIX',
    'HOST-KEYWORD' => 'DOMAIN-KEYWORD',
    'HOST-WILDCARD' => 'DOMAIN-WILDCARD',
    'IP6-CIDR' => 'IP-CIDR6',
    'MATCH' => 'FINAL'
  }.freeze
  DOMAIN_TYPES = %w[DOMAIN DOMAIN-SUFFIX DOMAIN-KEYWORD DOMAIN-WILDCARD USER-AGENT URL-REGEX].freeze
  NETWORK_TYPES = %w[IP-CIDR IP-CIDR6 IP-ASN GEOIP].freeze
  SR_ONLY_TYPES = %w[USER-AGENT URL-REGEX].freeze
  TYPES = (DOMAIN_TYPES + NETWORK_TYPES + ['FINAL']).freeze
  BUILTIN_POLICIES = %w[PROXY DIRECT TAILSCALE REJECT REJECT-DICT REJECT-ARRAY REJECT-200 REJECT-IMG REJECT-TINYGIF REJECT-VIDEO REJECT-DROP REJECT-NO-DROP].freeze

  module_function

  # A missing row policy is legal in a ruleset. The enclosing RULE-SET policy
  # always wins over a Quantumult X row's policy. The only supported option is
  # no-resolve; any token after the optional policy must be this exact option.
  def parse_rule(line, outer_policy: nil, source: nil)
    fail_parse('rule must be a String', source) unless line.is_a?(String)
    text = line.sub(/\A\uFEFF/, '').strip
    return nil if text.empty? || text.start_with?('#', '//')

    fail_parse('rule contains a newline', source) if text.match?(/[\r\n]/)
    fields = text.split(',', -1).map(&:strip)
    fail_parse('empty rule field', source) if fields.any?(&:empty?)
    original_type = fields.shift
    type = ALIASES.fetch(original_type, original_type)
    fail_parse("unknown rule type #{type.inspect}", source) unless TYPES.include?(type)
    validate_policy(outer_policy, source) unless outer_policy.nil?

    if type == 'FINAL'
      fail_parse('FINAL requires exactly one policy', source) unless fields.length == 1
      validate_policy(fields.first, source)
      return { type: type, value: nil, policy: normalize_policy(outer_policy || fields.first), options: [], source: source }
    end

    value = fields.shift
    fail_parse("#{type} requires a value", source) if value.nil?
    row_policy = fields.shift unless fields.empty? || fields.first == 'no-resolve'
    validate_policy(row_policy, source) unless row_policy.nil?
    unless fields.empty? || (fields == ['no-resolve'] && NETWORK_TYPES.include?(type))
      fail_parse("unsupported options for #{type}: #{fields.inspect}", source)
    end
    { type: type, value: value, policy: normalize_policy(outer_policy || row_policy), options: fields, source: source }
  end

  def parse_ruleset(text, policy:, source:)
    fail_parse('ruleset must be a String', source) unless text.is_a?(String)
    rules = []
    text.each_line.with_index(1) do |line, number|
      location = source ? "#{source}:#{number}" : "line #{number}"
      rule = parse_rule(line, outer_policy: policy, source: location)
      if rule
        rule[:source] = source
        rule[:line] = number
        rules << rule
      end
    end
    rules
  end

  # Serializers emit complete configuration rules, not policy-free providers.
  def sr_line(rule)
    checked_rule(rule)
    fields = [rule[:type]]
    fields << rule[:value] unless rule[:type] == 'FINAL'
    (fields + [rule[:policy]] + rule[:options]).join(',')
  end

  def mihomo_line(rule)
    checked_rule(rule, allow_process: true)
    type = rule[:type]
    if SR_ONLY_TYPES.include?(type)
      raise UnsupportedRuleError, "#{type} has no Mihomo equivalent; omit explicitly and record the difference"
    end
    return "MATCH,#{rule[:policy]}" if type == 'FINAL'

    # The installed Mihomo 1.19.10 supports DOMAIN-REGEX, but does not yet have
    # DOMAIN-WILDCARD. Escape every regex metacharacter except the two glob
    # operators, and anchor both ends so a wildcard never becomes a substring.
    value = rule[:value]
    if type == 'DOMAIN-WILDCARD'
      type = 'DOMAIN-REGEX'
      value = wildcard_regex(value)
    end
    ([type, value, rule[:policy]] + rule[:options]).join(',')
  end

  # The caller decides the ordering of the stages and patch precedence.
  # No deduplication or sorting occurs within a stage.
  def partition_rules(rules)
    result = { domain: [], network: [], final: [] }
    rules.each do |rule|
      type = rule[:type]
      group = if DOMAIN_TYPES.include?(type)
                :domain
              elsif NETWORK_TYPES.include?(type)
                :network
              elsif type == 'FINAL'
                :final
              else
                raise ParseError, "cannot partition unknown rule type #{type.inspect}"
              end
      result[group] << rule
    end
    result
  end

  def wildcard_regex(value)
    pattern = value.each_char.map do |char|
      case char
      when '*' then '.*'
      when '?' then '.'
      when '.', '^', '$', '+', '(', ')', '[', ']', '{', '}', '|', '\\'
        "\\#{char}"
      else char
      end
    end.join
    "(?i)^#{pattern}$"
  end

  def validate_policy(policy, source)
    unless policy.is_a?(String) && !policy.strip.empty? && !policy.match?(/[,\r\n]/) && policy != 'no-resolve'
      fail_parse("invalid policy #{policy.inspect}", source)
    end
  end

  def normalize_policy(policy)
    return nil if policy.nil?
    upper = policy.upcase
    BUILTIN_POLICIES.include?(upper) ? upper : policy
  end

  # Process exceptions are supplied by the Windows configuration builder, not
  # parsed from the shared Shadowrocket sources or advertised as SR rules.
  def checked_rule(rule, allow_process: false)
    valid_type = rule.is_a?(Hash) && (TYPES.include?(rule[:type]) || (allow_process && rule[:type] == 'PROCESS-NAME'))
    unless valid_type && rule[:options].is_a?(Array)
      raise ParseError, 'invalid normalized rule'
    end
    validate_policy(rule[:policy], nil)
    if rule[:type] == 'FINAL'
      raise ParseError, 'FINAL cannot have a value or options' unless rule[:value].nil? && rule[:options].empty?
    else
      value = rule[:value]
      unless value.is_a?(String) && !value.empty? && !value.match?(/[,\r\n]/)
        raise ParseError, 'invalid rule value'
      end
      valid_options = rule[:options].empty? || (NETWORK_TYPES.include?(rule[:type]) && rule[:options] == ['no-resolve'])
      raise ParseError, 'unsupported rule options' unless valid_options
    end
    rule
  end

  def fail_parse(message, source)
    raise ParseError, source ? "#{source}: #{message}" : message
  end
end
