# frozen_string_literal: true

require 'minitest/autorun'
require_relative 'rules'

class LazyFixRulesTest < Minitest::Test
  Rules = LazyFixRules

  def parse(line, policy = 'DIRECT')
    Rules.parse_rule(line, outer_policy: policy, source: 'fixture')
  end

  def test_every_observed_upstream_type_and_qx_normalization
    samples = {
      'DOMAIN' => ['example.com', 'DOMAIN'],
      'DOMAIN-SUFFIX' => ['example.com', 'DOMAIN-SUFFIX'],
      'DOMAIN-KEYWORD' => ['example', 'DOMAIN-KEYWORD'],
      'DOMAIN-WILDCARD' => ['*.example.com', 'DOMAIN-WILDCARD'],
      'USER-AGENT' => ['*YouTubeMusic*', 'USER-AGENT'],
      'URL-REGEX' => ['^https?:\\/\\/www\\.amazon\\.com\\/(Amazon-Video|gp\\/video)\\/', 'URL-REGEX'],
      'IP-CIDR' => ['192.0.2.0/24', 'IP-CIDR'],
      'IP-ASN' => ['56040', 'IP-ASN'],
      'HOST' => ['example.com', 'DOMAIN'],
      'HOST-SUFFIX' => ['example.com', 'DOMAIN-SUFFIX'],
      'HOST-KEYWORD' => ['example', 'DOMAIN-KEYWORD'],
      'HOST-WILDCARD' => ['*.example.com', 'DOMAIN-WILDCARD'],
      'IP6-CIDR' => ['2001:db8::/32', 'IP-CIDR6']
    }
    samples.each do |input_type, (value, output_type)|
      rule = parse("#{input_type},#{value},Original Group", 'PROXY')
      assert_equal({ type: output_type, value: value, policy: 'PROXY', options: [], source: 'fixture' }, rule)
    end
  end

  def test_outer_policy_overrides_qx_policy_and_preserves_network_option
    rule = parse('IP-CIDR,192.0.2.0/24,Apple,no-resolve', 'DIRECT')
    assert_equal 'DIRECT', rule[:policy]
    assert_equal ['no-resolve'], rule[:options]
    assert_equal 'IP-CIDR,192.0.2.0/24,DIRECT,no-resolve', Rules.sr_line(rule)
    assert_equal Rules.sr_line(rule), Rules.mihomo_line(rule)
  end

  def test_policy_free_ruleset_line_and_existing_policy
    assert_nil Rules.parse_rule('DOMAIN,example.com')[:policy]
    assert_equal 'My Group', Rules.parse_rule('DOMAIN,example.com,My Group')[:policy]
    assert_equal ['no-resolve'], parse('IP-CIDR,2001:b28:f23d::/48,no-resolve')[:options]
    assert_equal 'IP-CIDR,2001:b28:f23d::/48,DIRECT,no-resolve', Rules.mihomo_line(parse('IP-CIDR,2001:b28:f23d::/48,no-resolve'))
    assert_raises(Rules::ParseError) { Rules.sr_line(Rules.parse_rule('DOMAIN,example.com')) }
  end

  def test_known_sr_only_rules_are_preserved_but_not_silently_converted
    ['USER-AGENT,*YouTubeMusic*', 'URL-REGEX,^https?://example\\.com/video/'].each do |line|
      rule = parse(line, 'PROXY')
      assert_equal "#{line},PROXY", Rules.sr_line(rule)
      assert_raises(Rules::UnsupportedRuleError) { Rules.mihomo_line(rule) }
    end
  end

  def test_wildcard_conversion_matches_full_hostname_and_escapes_literals
    rule = parse('HOST-WILDCARD,a*c.example?.com,Global', 'PROXY')
    line = Rules.mihomo_line(rule)
    assert_equal 'DOMAIN-REGEX,(?i)^a.*c\\.example.\\.com$,PROXY', line
    pattern = Regexp.new(line.split(',')[1])
    %w[ac.example1.com abc.example2.com AxxC.ExampleQ.COM].each { |host| assert_match pattern, host }
    %w[xac.example1.com ac.example.com ac.example12.com ac.example1.com.evil acXexample1Ycom].each do |host|
      refute_match pattern, host
    end
    assert_equal 'DOMAIN-WILDCARD,a*c.example?.com,PROXY', Rules.sr_line(rule)
    assert_equal '(?i)^a\\+b\\[c\\]\\(d\\)\\{e\\}\\^\\$\\|\\\\f$', Rules.wildcard_regex('a+b[c](d){e}^$|\\f')
  end

  def test_final_and_geoip
    rule = Rules.parse_rule('FINAL,PROXY')
    assert_equal({ type: 'FINAL', value: nil, policy: 'PROXY', options: [], source: nil }, rule)
    assert_equal 'FINAL,PROXY', Rules.sr_line(rule)
    assert_equal 'MATCH,PROXY', Rules.mihomo_line(rule)
    assert_equal rule, Rules.parse_rule('MATCH,PROXY')
    assert_equal 'GEOIP,CN,DIRECT', Rules.mihomo_line(parse('GEOIP,CN,DIRECT'))
  end

  def test_comments_bom_and_windows_newlines
    text = "\uFEFF# heading\r\n\r\n // comment\r\nHOST,example.com,China\r\nIP6-CIDR,2001:db8::/32,China\r\n"
    rules = Rules.parse_ruleset(text, policy: 'DIRECT', source: 'source.list')
    assert_equal %w[DOMAIN IP-CIDR6], rules.map { |rule| rule[:type] }
    assert_equal ['DIRECT', 'DIRECT'], rules.map { |rule| rule[:policy] }
    assert_equal ['source.list', 'source.list'], rules.map { |rule| rule[:source] }
    assert_equal [4, 5], rules.map { |rule| rule[:line] }
  end

  def test_builtin_policy_normalization_preserves_custom_group_names
    assert_equal 'REJECT', Rules.parse_rule('DOMAIN,ad.example,Reject')[:policy]
    assert_equal 'DIRECT', parse('HOST,example.com,Apple', 'direct')[:policy]
    assert_equal 'PROXY', Rules.parse_rule('FINAL,Proxy')[:policy]
    assert_equal 'REJECT-DROP', Rules.parse_rule('DOMAIN,ad.example,reject-drop')[:policy]
    assert_equal 'My Proxy Group', Rules.parse_rule('DOMAIN,example.com,My Proxy Group')[:policy]
  end

  def test_process_rule_is_a_windows_only_serialization_exception
    rule = { type: 'PROCESS-NAME', value: 'cs2.exe', policy: 'DIRECT', options: [] }
    assert_equal 'PROCESS-NAME,cs2.exe,DIRECT', Rules.mihomo_line(rule)
    assert_raises(Rules::ParseError) { Rules.sr_line(rule) }
    assert_raises(Rules::ParseError) { Rules.parse_rule('PROCESS-NAME,cs2.exe,DIRECT') }
    assert_raises(Rules::ParseError) { Rules.partition_rules([rule]) }
    assert_raises(Rules::ParseError) { Rules.mihomo_line(rule.merge(options: ['no-resolve'])) }
  end

  def test_partition_preserves_order_and_has_no_deduplication
    rules = [
      'IP-CIDR,192.0.2.0/24,DIRECT',
      'DOMAIN,one.example,DIRECT',
      'USER-AGENT,*YouTube*,PROXY',
      'GEOIP,CN,DIRECT',
      'DOMAIN,one.example,DIRECT',
      'URL-REGEX,^https://example.com,PROXY',
      'FINAL,PROXY'
    ].map { |line| Rules.parse_rule(line) }
    stages = Rules.partition_rules(rules)
    assert_equal [rules[1], rules[2], rules[4], rules[5]], stages[:domain]
    assert_equal [rules[0], rules[3]], stages[:network]
    assert_equal [rules[6]], stages[:final]
    assert_equal 7, stages.values.flatten.length
  end

  def test_unknown_syntax_and_options_fail_closed
    bad_lines = [
      'FUTURE-RULE,example.com,DIRECT',
      'DOMAIN', 'DOMAIN,,DIRECT', 'DOMAIN,example.com,',
      'DOMAIN,example.com,DIRECT,no-resolve',
      'IP-CIDR,192.0.2.0/24,DIRECT,extended-matching',
      'IP-CIDR,192.0.2.0/24,no-resolve,no-resolve',
      'IP-CIDR,192.0.2.0/24,DIRECT,no-resolve,unknown',
      'FINAL', 'FINAL,PROXY,no-resolve',
      "DOMAIN,example.com,DIRECT\nDOMAIN,other.com,DIRECT"
    ]
    bad_lines.each do |line|
      error = assert_raises(Rules::ParseError) { parse(line) }
      assert_includes error.message, 'fixture'
    end
    error = assert_raises(Rules::ParseError) do
      Rules.parse_ruleset("# comment\nUNKNOWN,value\n", policy: 'DIRECT', source: 'upstream.list')
    end
    assert_includes error.message, 'upstream.list:2'
    assert_raises(Rules::ParseError) { Rules.partition_rules([{ type: 'UNKNOWN' }]) }
  end
end
