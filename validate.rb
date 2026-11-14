# frozen_string_literal: true

require 'ipaddr'
require 'yaml'

# An independent, offline reader of the generated outputs. This is deliberately
# not the generator's parser and does not contact DNS or start either client.
module LazyFixValidation
  class ValidationError < StandardError; end

  DOMAIN_TYPES = %w[DOMAIN DOMAIN-SUFFIX DOMAIN-KEYWORD DOMAIN-WILDCARD DOMAIN-REGEX USER-AGENT URL-REGEX].freeze
  IP_TYPES = %w[IP-CIDR IP-CIDR6 GEOIP IP-ASN].freeze
  TERMINAL_TYPES = %w[FINAL MATCH].freeze
  TYPES = (DOMAIN_TYPES + IP_TYPES + TERMINAL_TYPES + %w[PROCESS-NAME PROCESS-PATH NETWORK PROTOCOL DST-PORT AND OR NOT SUB-RULE]).freeze

  class Model
    attr_reader :rules, :sub_rules, :general, :ignored_types

    def initialize(kind, rules, sub_rules = {}, general = {}, hosts = {})
      @kind = kind
      @general = general
      @hosts = hosts
      @ignored_types = []
      @rules = rules.map { |line| compile(line) }
      @sub_rules = sub_rules.each_with_object({}) do |(name, lines), result|
        result[name] = lines.map { |line| compile(line) }
      end
      @ignored_types.uniq!
      # SR compiles domain-related matches before IP/database matches. Mihomo
      # uses the exact output order, so fixture conflicts can expose a bad port.
      @rules = @rules.sort_by { |rule| phase(rule) } if @kind == :shadowrocket
    end

    def route(request)
      if request[:ip].nil? && request[:host]
        value = @hosts[request[:host]]
        if value
          address = Array(value).find do |candidate|
            begin
              IPAddr.new(candidate)
              true
            rescue IPAddr::InvalidAddressError
              false
            end
          end
          request = request.merge(ip: address) if address
        end
      end
      result = scan(@rules, request)
      raise ValidationError, "#{@kind}: no final policy for fixture" unless result

      # Model the source General option, not a fabricated SR routing rule.
      block = @general.fetch('block-quic', 'always-allow').downcase
      if request[:network].to_s.downcase == 'udp' && request[:port] == 443
        result = 'REJECT' if block == 'all' || (block == 'all-proxy' && result == 'PROXY')
      end
      result
    end

    private

    def phase(rule)
      return 2 if TERMINAL_TYPES.include?(rule[:type])
      IP_TYPES.include?(rule[:type]) ? 1 : 0
    end

    # Split only commas outside logic-rule parentheses; regex payloads emitted
    # by this project have no commas and retain their original escaping.
    def fields(text)
      parts = []
      start = 0
      depth = 0
      escaped = false
      text.each_char.with_index do |char, index|
        if escaped
          escaped = false
          next
        end
        if char == '\\'
          escaped = true
          next
        end
        depth += 1 if char == '('
        depth -= 1 if char == ')'
        raise ValidationError, 'unbalanced rule parentheses' if depth < 0
        next unless char == ',' && depth.zero?

        parts << text[start...index].strip
        start = index + 1
      end
      raise ValidationError, 'unbalanced rule parentheses' unless depth.zero?
      parts << text[start..-1].strip
      parts
    end

    def unbox(text)
      unless text.start_with?('(') && text.end_with?(')')
        raise ValidationError, 'logic rule needs parenthesized conditions'
      end
      text[1...-1]
    end

    def compile(text, condition = false)
      raise ValidationError, 'rule must be a string' unless text.is_a?(String)
      tokens = fields(text)
      type = tokens.shift.to_s.upcase
      raise ValidationError, "unsupported rule type: #{type}" unless TYPES.include?(type)
      rule = { type: type }
      if TERMINAL_TYPES.include?(type)
        raise ValidationError, 'MATCH/FINAL is not a logic condition' if condition
        rule[:target] = tokens.shift
      else
        rule[:value] = tokens.shift
        raise ValidationError, 'rule payload is missing' if rule[:value].nil? || rule[:value].empty?
        rule[:target] = tokens.shift unless condition
      end
      rule[:options] = tokens
      if %w[AND OR NOT SUB-RULE].include?(type)
        inner = unbox(rule[:value])
        conditions = %w[NOT SUB-RULE].include?(type) ? [inner] : fields(inner).map { |item| unbox(item) }
        rule[:conditions] = conditions.map { |item| compile(item, true) }
      elsif %w[IP-CIDR IP-CIDR6].include?(type)
        rule[:cidr] = IPAddr.new(rule[:value])
      elsif type == 'DOMAIN-REGEX'
        rule[:regex] = Regexp.new(rule[:value])
      elsif type == 'DOMAIN-WILDCARD'
        rule[:regex] = Regexp.new('\\A' + Regexp.escape(rule[:value]).gsub('\\*', '.*').gsub('\\?', '.') + '\\z', Regexp::IGNORECASE)
      elsif %w[USER-AGENT URL-REGEX].include?(type)
        @ignored_types << type
      end
      if !condition && (rule[:target].nil? || rule[:target].empty?)
        raise ValidationError, 'rule policy is missing'
      end
      rule
    rescue IPAddr::InvalidAddressError, RegexpError => error
      raise ValidationError, "invalid offline rule payload (#{error.class})"
    end

    def scan(rules, request, depth = 0)
      raise ValidationError, 'recursive sub-rule chain' if depth > 8
      rules.each do |rule|
        next unless matches?(rule, request)
        if rule[:type] == 'SUB-RULE'
          children = @sub_rules[rule[:target]]
          raise ValidationError, 'referenced sub-rule is missing' unless children
          result = scan(children, request, depth + 1)
          return result if result
        else
          return policy(rule[:target])
        end
      end
      nil
    end

    def policy(target)
      value = target.to_s.upcase
      return value if %w[DIRECT PROXY REJECT].include?(value)
      return 'REJECT' if value.start_with?('REJECT-')
      # Do not print an unrecognized target: it might be a private node name.
      raise ValidationError, 'unrecognized policy in generated configuration'
    end

    def matches?(rule, request)
      value = rule[:value]
      host = request[:host].to_s.downcase.sub(/\.$/, '')
      case rule[:type]
      when 'FINAL', 'MATCH' then true
      when 'DOMAIN' then !host.empty? && host == value.downcase
      when 'DOMAIN-SUFFIX' then !host.empty? && (host == value.downcase || host.end_with?('.' + value.downcase))
      when 'DOMAIN-KEYWORD' then !host.empty? && host.include?(value.downcase)
      when 'DOMAIN-WILDCARD', 'DOMAIN-REGEX' then !host.empty? && rule[:regex].match?(host)
      when 'USER-AGENT', 'URL-REGEX' then false # No UA or URL is supplied by these fixtures.
      when 'IP-CIDR', 'IP-CIDR6'
        request[:ip] && rule[:cidr].include?(IPAddr.new(request[:ip]))
      when 'GEOIP' then request[:country].to_s.upcase == value.upcase
      when 'IP-ASN' then !request[:asn].nil? && request[:asn].to_s == value
      when 'PROCESS-NAME' then request[:process].to_s.casecmp(value).zero?
      when 'PROCESS-PATH' then request[:process_path].to_s == value
      when 'NETWORK', 'PROTOCOL' then request[:network].to_s.casecmp(value).zero?
      when 'DST-PORT'
        value.split('/').any? do |range|
          bounds = range.split('-').map { |part| Integer(part, 10) }
          (bounds.first..bounds.last).cover?(request[:port])
        end
      when 'AND' then rule[:conditions].all? { |item| matches?(item, request) }
      when 'OR' then rule[:conditions].any? { |item| matches?(item, request) }
      when 'NOT' then !matches?(rule[:conditions].first, request)
      when 'SUB-RULE' then matches?(rule[:conditions].first, request)
      else raise ValidationError, 'unhandled rule in offline model'
      end
    end
  end

  module_function

  # Psych 3 (system Ruby 2.6) takes positional options; newer Psych versions
  # require keyword options. Keep the same safe-loading policy on both.
  def load_yaml(text)
    keywords = YAML.method(:safe_load).parameters.any? { |kind, name| kind == :key && name == :permitted_classes }
    if keywords
      YAML.safe_load(text, permitted_classes: [], permitted_symbols: [], aliases: true)
    else
      YAML.safe_load(text, [], [], true)
    end
  end

  def check!(cfg_path, yaml_path, advertising_enabled: nil, advertising_domain: 'ad.12306.cn', exceptions: [], windows_process_direct: ['cs2.exe'])
    cfg = File.read(cfg_path, encoding: 'UTF-8').sub(/\A\uFEFF/, '')
    sections = Hash.new { |hash, key| hash[key] = [] }
    section = nil
    cfg.each_line do |line|
      text = line.strip
      if text.match?(/\A\[[^\]]+\]\z/)
        section = text[1...-1].downcase
      elsif section && !text.empty? && !text.start_with?('#', '//')
        sections[section] << text
      end
    end
    general = sections['general'].each_with_object({}) do |line, result|
      key, value = line.split('=', 2).map { |part| part && part.strip }
      result[key.downcase] = value if value
    end
    hosts = (sections['host'] + sections['hosts']).each_with_object({}) do |line, result|
      name, value = line.split('=', 2).map { |part| part && part.strip }
      result[name] = value if value && !value.start_with?('server:')
    end
    if advertising_enabled.nil?
      marker = cfg.match(/^\s*#\s*advertising[_ ]enabled\s*[:=]\s*(true|false)\b/i)
      raise ValidationError, 'advertising_enabled must be explicit or marked in cfg' unless marker
      advertising_enabled = marker[1].casecmp('true').zero?
    end
    unless advertising_enabled == true || advertising_enabled == false
      raise ValidationError, 'advertising_enabled must be boolean'
    end
    yaml = load_yaml(File.read(yaml_path, encoding: 'UTF-8'))
    unless yaml.is_a?(Hash) && yaml['rules'].is_a?(Array) && !sections['rule'].empty?
      raise ValidationError, 'generated configurations must contain rule lists'
    end
    sr = Model.new(:shadowrocket, sections['rule'], {}, general, hosts)
    mh = Model.new(:mihomo, yaml['rules'], yaml.fetch('sub-rules', {}), {}, yaml.fetch('hosts', {}))
    results = fixtures(advertising_enabled, advertising_domain, windows_process_direct).map do |test|
      request = { network: 'tcp', port: 443 }.merge(test[:request])
      intended = exception_policy(exceptions, request) || test[:expected]
      if intended == 'PROXY' && request[:network] == 'udp' && request[:port] == 443
        intended = 'REJECT'
      end
      actual = { mihomo: mh.route(request) }
      actual[:shadowrocket] = sr.route(request) unless test[:only_windows]
      expected = actual.keys.each_with_object({}) { |client, hash| hash[client] = intended }
      {
        name: test[:name], request: request, only_windows: !!test[:only_windows],
        expected: expected, actual: actual, passed: actual == expected
      }
    end
    failed = results.reject { |test| test[:passed] }
    unless failed.empty?
      detail = failed.map { |test| "#{test[:name]} expected=#{test[:expected]} actual=#{test[:actual]}" }.join('; ')
      raise ValidationError, "offline rule fixtures failed: #{detail}"
    end
    {
      passed: true, kind: 'offline_output_rule_model', advertising_enabled: advertising_enabled,
      cases: results,
      rule_counts: { shadowrocket: sr.rules.size, mihomo: mh.rules.size },
      ignored_shadowrocket_types: sr.ignored_types,
      limits: [
        'Offline output parsing and selected rule fixtures only; neither client was started and no test network traffic was sent.',
        'No actual DNS, GeoIP or ASN lookup: IP/country metadata in conflict fixtures is supplied explicitly; literal IP hosts mappings are read from each output.',
        'Shadowrocket is modeled as domain rules before IP/database rules; its runtime compiler and DNS-error fallback are not exercised.',
        'Shadowrocket USER-AGENT and URL-REGEX rules are ignored because these fixtures supply neither User-Agent nor request URL.',
        'Shadowrocket block-quic is modeled as UDP destination port 443; this does not verify client protocol detection or QUIC on other ports.',
        'TUN routing, system proxy bypasses, DNS/IPv6 behavior, node reachability, HTTPS rewrites and actual app/game login or payment are not tested.',
        'Configured .exe process fixtures are Windows/Mihomo only; they do not assert process matching in Shadowrocket.',
        'Fixture expectations honor explicitly supplied local exceptions and process selections; the advertising fixture can use a current, non-exempt source domain.',
        'Mihomo syntax validation with the installed core is a separate check; this module is not a complete client implementation.'
      ]
    }
  rescue Psych::Exception => error
    raise ValidationError, "cannot parse generated YAML (#{error.class})"
  end

  def exception_policy(exceptions, request)
    host = request[:host].to_s.downcase
    exceptions.each do |line|
      type, value, target = line.split(',').map(&:strip)
      unless %w[DOMAIN DOMAIN-SUFFIX].include?(type) && value && %w[DIRECT PROXY].include?(target)
        raise ValidationError, 'unsupported local exception in fixture expectations'
      end
      matched = host == value.downcase || (type == 'DOMAIN-SUFFIX' && host.end_with?('.' + value.downcase))
      return target if matched
    end
    nil
  end

  def fixtures(advertising_enabled, advertising_domain = 'ad.12306.cn', windows_process_direct = ['cs2.exe'])
    direct = %w[moutai519.com.cn app.moutai519.com.cn huya.com img.huya.com msstatic.com pvp.wanmei.com csgo.5eplay.com val.qq.com localhost apple.com wechatpay.com www.bilibili.com]
    proxy = %w[youtube.com netflix.com store.steampowered.com google.com example.invalid github.com]
    cases = direct.map { |host| { name: "direct:#{host}", request: { host: host }, expected: 'DIRECT' } }
    cases += proxy.map { |host| { name: "proxy:#{host}", request: { host: host }, expected: 'PROXY' } }
    ad_host = advertising_enabled ? advertising_domain : 'ad.12306.cn'
    unless ad_host.is_a?(String) && !ad_host.empty?
      raise ValidationError, 'advertising fixture requires a source domain'
    end
    cases << { name: "advertising:#{ad_host}", request: { host: ad_host }, expected: advertising_enabled ? 'REJECT' : 'DIRECT' }
    %w[127.0.0.1 10.8.0.1 172.16.5.3 192.168.1.9 ::1 fc00::1234].each do |ip|
      cases << { name: "private-ip:#{ip}", request: { ip: ip }, expected: 'DIRECT' }
    end
    cases += [
      { name: 'domain-before-cn-ip:google', request: { host: 'google.com', ip: '223.5.5.5', country: 'CN' }, expected: 'PROXY' },
      { name: 'domain-before-us-ip:moutai', request: { host: 'moutai519.com.cn', ip: '8.8.8.8', country: 'US' }, expected: 'DIRECT' },
      { name: 'advertising-before-cn-ip', request: { host: ad_host, ip: '223.5.5.5', country: 'CN' }, expected: advertising_enabled ? 'REJECT' : 'DIRECT' },
      { name: 'proxy-udp443', request: { host: 'youtube.com', network: 'udp', port: 443 }, expected: 'REJECT' },
      { name: 'fallback-proxy-udp443', request: { host: 'example.invalid', network: 'udp', port: 443 }, expected: 'REJECT' },
      { name: 'direct-udp443', request: { host: 'huya.com', network: 'udp', port: 443 }, expected: 'DIRECT' },
      { name: 'proxy-udp27015', request: { host: 'youtube.com', network: 'udp', port: 27015 }, expected: 'PROXY' }
    ]
    windows_process_direct.each do |name|
      cases << { name: "windows-process:#{name}", request: { host: 'game.example.invalid', process: name, network: 'udp', port: 27015 }, expected: 'DIRECT', only_windows: true }
    end
    cases
  end
end
