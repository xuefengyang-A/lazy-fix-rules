#!/usr/bin/env ruby
# frozen_string_literal: true
# Portable, credential-free build using Ruby standard libraries and an existing curl.
# MIHOMO_BIN optionally selects an already installed core; no software is downloaded.
require 'json'
require 'yaml'
require 'digest'
require 'fileutils'
require 'open3'
require 'time'
require 'securerandom'
require 'ipaddr'
require 'uri'
require 'tmpdir'
require 'optparse'
require_relative 'rules'
require_relative 'validate'

module LazyFixBuild
  ROOT = File.expand_path(__dir__)
  BASE_URL = 'https://raw.githubusercontent.com/Johnshall/Shadowrocket-ADBlock-Rules-Forever/release/lazy.conf'
  ADS_URL = 'https://johnshall.github.io/Shadowrocket-ADBlock-Rules-Forever/sr_ad_only.conf'
  COUNTRY_URL = 'https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/country.mmdb'
  ASN_URL = 'https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/GeoLite2-ASN.mmdb'
  GENERAL_KEYS = %w[skip-proxy tun-excluded-routes dns-server fallback-dns-server ipv6 prefer-ipv6 dns-direct-system icmp-auto-reply always-reject-url-rewrite private-ip-answer dns-direct-fallback-proxy hijack-dns udp-policy-not-supported-behaviour stun-response-ip stun-response-ipv6 block-quic].freeze

  def self.write(path, content)
    File.write(path, content, mode: 'w', perm: 0600)
    File.chmod(0600, path)
  end

  def self.section(text, name)
    text[/^\[#{Regexp.escape(name)}\]\s*\n(.*?)(?=^\[|\z)/m, 1] || raise("缺少 [#{name}] 段")
  end

  def self.active_lines(text)
    text.each_line.map(&:strip).reject { |s| s.empty? || s.start_with?('#', ';', '//') }
  end

  class Sources
    attr_reader :entries, :snapshot_batch

    def initialize(stage, source_dir: nil)
      @stage, @entries, @texts = stage, [], {}
      @mutex = Mutex.new
      @source_dir = source_dir
      if source_dir
        manifest = JSON.parse(File.read(File.join(source_dir, '..', 'manifest.json')))
        @old_sources = manifest.fetch('sources')
        @snapshot_batch = manifest.fetch('batch')
      end
      FileUtils.mkdir_p(File.join(stage, 'sources'))
    end

    def fetch(url)
      return @texts[url] if @texts.key?(url)
      filename = Digest::SHA256.hexdigest(url)[0, 16] + '-' + File.basename(URI(url).path)
      path = File.join(@stage, 'sources', filename)
      retrieval = {}
      previous = nil
      data = if @source_dir
               previous = @old_sources.find { |entry| entry.fetch('url') == url }
               raise "Reused snapshot is missing a source: #{url}" unless previous
               expected_file = "sources/#{filename}"
               raise 'Snapshot source filename does not match its canonical URL' unless previous.fetch('file') == expected_file
               saved = File.binread(File.join(@source_dir, filename))
               raise "Reused source hash mismatch: #{url}" unless Digest::SHA256.hexdigest(saved) == previous.fetch('sha256')
               retrieval['retrieval_url'] = previous.fetch('retrieval_url', url)
               saved
             else
               LazyFixBuild.download(url, max_bytes: 20_000_000, metadata: retrieval)
             end
      utf8 = data.dup.force_encoding('UTF-8')
      raise "Rule source is not UTF-8: #{url}" unless utf8.valid_encoding?
      LazyFixBuild.write(path, data)
      entry = { 'url' => url, 'retrieval_url' => retrieval.fetch('retrieval_url', url),
        'file' => "sources/#{filename}", 'sha256' => Digest::SHA256.hexdigest(data),
        'bytes' => data.bytesize, 'captured_at' => previous ? previous.fetch('captured_at') : Time.now.utc.iso8601,
        'acquisition' => previous ? 'reused-snapshot' : 'downloaded' }
      @mutex.synchronize { @entries << entry; @texts[url] = utf8.sub(/\A\uFEFF/, '') }
      @texts[url]
    end

    def fetch_many(urls)
      queue, errors = Queue.new, Queue.new
      urls.uniq.each { |url| queue << url unless @texts.key?(url) }
      workers = Array.new([6, queue.size].min) do
        Thread.new do
          loop do
            begin
              url = queue.pop(true)
            rescue ThreadError
              break
            end
            begin
              fetch(url)
            rescue StandardError => error
              errors << error
            end
          end
        end
      end
      workers.each(&:join)
      raise errors.pop unless errors.empty?
    end
  end

  def self.github_contents_url(url)
    uri = URI(url)
    return nil unless uri.is_a?(URI::HTTPS) && uri.host == 'raw.githubusercontent.com'
    owner, repo, ref, *path = uri.path.split('/').reject(&:empty?)
    raise 'Unsupported raw GitHub source URL' if [owner, repo, ref].any?(&:nil?) || path.empty? || uri.query
    "https://api.github.com/repos/#{owner}/#{repo}/contents/#{path.join('/')}?#{URI.encode_www_form('ref' => URI.decode_www_form_component(ref))}"
  end

  def self.download(url, max_bytes:, metadata: nil)
    raise 'Sources must use HTTPS' unless URI(url).is_a?(URI::HTTPS)
    api_url = github_contents_url(url)
    attempts = api_url && ENV['GITHUB_RAW_VIA_API'] == '1' ? [api_url] : [url, api_url].compact
    last_status = nil
    attempts.each do |retrieval_url|
      api = retrieval_url == api_url
      # Raw GitHub gets one bounded attempt before the official Contents API.
      # No mirror, embedded token, or quota-bypassing fallback is used.
      timeout = api_url && !api ? '25' : '120'
      args = ['curl', '--fail', '--silent', '--show-error', '--location', '--proto', '=https',
        '--proto-redir', '=https', '--connect-timeout', '8', '--max-time', timeout,
        '--retry', '0', '--max-filesize', max_bytes.to_s]
      args += ['--header', 'Accept: application/vnd.github.raw+json'] if api
      data, _error, status = Open3.capture3(*args, retrieval_url, binmode: true)
      last_status = status.exitstatus
      next unless status.success?
      raise "Source is empty: #{url}" if data.empty?
      raise "Source exceeds size limit: #{url}" if data.bytesize > max_bytes
      metadata['retrieval_url'] = retrieval_url if metadata
      return data
    end
    raise "Source download failed: #{url} (curl #{last_status}); no unofficial mirror was used"
  end

  def self.load_overrides
    data = JSON.parse(File.read(File.join(ROOT, 'overrides.json')))
    expected = %w[advertising_enabled exceptions domestic_direct windows_process_direct]
    raise 'overrides.json 字段错误' unless data.keys.sort == expected.sort
    raise 'advertising_enabled 必须是 true 或 false' unless [true, false].include?(data['advertising_enabled'])
    %w[exceptions domestic_direct].each do |key|
      raise "#{key} 必须是数组" unless data[key].is_a?(Array)
      data[key].each do |line|
        r = LazyFixRules.parse_rule(line)
        policies = key == 'exceptions' ? %w[DIRECT PROXY] : ['DIRECT']
        raise "#{key} 只接受 DOMAIN/DOMAIN-SUFFIX 与允许的出口策略" unless r && %w[DOMAIN DOMAIN-SUFFIX].include?(r[:type]) && policies.include?(r[:policy]) && r[:options].empty?
      end
    end
    unless data['windows_process_direct'].is_a?(Array) && data['windows_process_direct'].all? { |s| s.is_a?(String) && s.match?(/\A[a-zA-Z0-9_. -]+\.exe\z/) }
      raise 'windows_process_direct 必须是 .exe 名称数组'
    end
    data
  end

  def self.read_general(base)
    expected_sections = ['General', 'Proxy', 'Proxy Group', 'Rule', 'Host', 'URL Rewrite', 'MITM']
    raise '上游配置段发生变化，需要复核' unless base.scan(/^\[([^\]]+)\]/).flatten == expected_sections
    mitm_keys = active_lines(section(base, 'MITM')).map { |s| s.split('=', 2).first.strip }
    raise '上游新增 MITM 设置，需要复核' unless mitm_keys == ['hostname']
    settings = active_lines(section(base, 'General')).to_h do |line|
      key, val = line.split('=', 2).map(&:strip)
      raise 'General 格式变化，需要人工复核' unless val
      [key, val]
    end
    unknown = settings.keys - GENERAL_KEYS
    missing = GENERAL_KEYS - settings.keys
    raise "上游 General 字段变化，需要复核：#{(unknown + missing).join(', ')}" unless unknown.empty? && missing.empty?
    # These settings have no generic cross-engine conversion. Refuse new values silently changing intent.
    required = { 'ipv6' => 'true', 'prefer-ipv6' => 'false', 'fallback-dns-server' => 'system', 'dns-direct-system' => 'false', 'private-ip-answer' => 'true', 'dns-direct-fallback-proxy' => 'true', 'udp-policy-not-supported-behaviour' => 'REJECT', 'block-quic' => 'all-proxy' }
    required.each { |k, v| raise "上游 #{k} 已变化，需要复核" unless settings[k] == v }
    %w[Proxy Proxy\ Group].each { |name| raise "上游新增 [#{name}] 内容，需要复核" unless active_lines(section(base, name)).empty? }
    settings
  end

  def self.host_settings(base)
    hosts, policies = {}, {}
    active_lines(section(base, 'Host')).each do |line|
      name, val = line.split('=', 2).map(&:strip)
      raise 'Host 段格式变化' unless val
      if val == 'server:system'
        # SR glob *.example includes subdomains, not the apex. Mihomo leading dot has that scope.
        mapped = name.start_with?('*.') ? name[1..-1] : name
        policies[mapped] = ['system']
      elsif val.start_with?('server:')
        raise '新增 Host DNS 类型，需要复核'
      else
        IPAddr.new(val)
        hosts[name] = val
      end
    end
    [hosts, policies]
  end

  def self.proxy_line(rule)
    converted = LazyFixRules.mihomo_line(rule)
    return converted unless rule[:policy] == 'PROXY'
    if rule[:type] == 'FINAL'
      ['AND,((NETWORK,udp),(DST-PORT,443)),REJECT', 'MATCH,PROXY']
    else
      # Keep no-resolve inside the condition, rather than as a sub-rule name suffix.
      parts = converted.split(',')
      index = parts.index('PROXY') || raise('代理规则格式错误')
      parts.delete_at(index)
      "SUB-RULE,(#{parts.join(',')}),proxy-egress"
    end
  end

  def self.windows_config(base, general, rules)
    hosts, host_policy = host_settings(base)
    nameservers = general.fetch('dns-server').split(',').map(&:strip)
    plain_dns = nameservers.select { |s| s.match?(/\A[0-9.]+\z/) }
    raise '原版缺少可用于启动 DoH 的普通 DNS，需要复核' if plain_dns.empty?
    route_excludes = general.fetch('tun-excluded-routes').split(',').map(&:strip)
    fake_range = IPAddr.new('198.18.0.0/16')
    route_excludes.each do |cidr|
      network = IPAddr.new(cidr)
      raise 'TUN 排除路由与 Fake-IP 冲突' if network.ipv4? && (network.include?(fake_range.to_range.first) || fake_range.include?(network.to_range.first))
    end
    ordered = rules.flat_map { |r| proxy_line(r) }
    {
      'mixed-port' => 7897, 'allow-lan' => false, 'bind-address' => '127.0.0.1',
      'mode' => 'rule', 'log-level' => 'info', 'ipv6' => true,
      'find-process-mode' => 'always', 'profile' => { 'store-selected' => true },
      'tun' => { 'enable' => true, 'stack' => 'system', 'auto-route' => true,
        'auto-detect-interface' => true, 'strict-route' => true,
        'dns-hijack' => ['any:53'], 'route-exclude-address' => route_excludes },
      'dns' => { 'enable' => true, 'listen' => '127.0.0.1:1053', 'ipv6' => true,
        'enhanced-mode' => 'fake-ip', 'fake-ip-range' => '198.18.0.1/16',
        'fake-ip-filter' => ['localhost', '+.lan', '+.local', '+.home.arpa'],
        'use-hosts' => true, 'use-system-hosts' => false, 'respect-rules' => false,
        'default-nameserver' => plain_dns, 'nameserver' => nameservers,
        'fallback' => ['system'],
        'fallback-filter' => { 'geoip' => false, 'ipcidr' => [], 'domain' => [] },
        'nameserver-policy' => host_policy },
      'hosts' => hosts,
      'proxy-groups' => [{ 'name' => 'PROXY', 'type' => 'select', 'proxies' => ['REJECT'] }],
      'sub-rules' => { 'proxy-egress' => ['AND,((NETWORK,udp),(DST-PORT,443)),REJECT', 'MATCH,PROXY'] },
      'rules' => ordered
    }
  end

  def self.prepare_data(stage, data_dir: nil)
    FileUtils.mkdir_p(File.join(stage, 'data'))
    { 'Country.mmdb' => COUNTRY_URL, 'ASN.mmdb' => ASN_URL }.map do |name, url|
      retrieval = {}
      data = if data_dir
               path = File.join(data_dir, name)
               raise "Supplied data directory is missing #{name}" unless File.file?(path)
               File.binread(path)
             else
               download(url, max_bytes: 50_000_000, metadata: retrieval)
             end
      raise "#{name} is missing the MaxMind format marker" unless data.include?("\xAB\xCD\xEFMaxMind.com".b)
      path = File.join(stage, 'data', name)
      write(path, data)
      entry = { 'file' => "data/#{name}", 'sha256' => Digest::SHA256.hexdigest(data),
        'bytes' => data.bytesize, 'captured_at' => Time.now.utc.iso8601 }
      if data_dir
        entry.merge('source' => 'local-reused', 'acquisition' => 'reused-local', 'reference_url' => url,
          'provenance' => 'Reused the explicitly supplied local database. Its original download origin was not independently verified by this build.')
      else
        entry.merge('source' => url, 'retrieval_url' => retrieval.fetch('retrieval_url', url), 'acquisition' => 'downloaded')
      end
    end
  end

  def self.syntax_check(stage, binary: ENV['MIHOMO_BIN'])
    if binary.nil? || binary.empty?
      return { 'performed' => false, 'passed' => nil,
        'reason' => 'MIHOMO_BIN was not supplied; independent output parsing and routing fixtures only. No core syntax check was performed.' }
    end
    raise 'MIHOMO_BIN must name an existing executable; no software is installed by this build' unless File.executable?(binary)
    home = File.join(stage, '.check')
    FileUtils.mkdir_p(home)
    %w[Country.mmdb ASN.mmdb].each { |name| FileUtils.cp(File.join(stage, 'data', name), File.join(home, name)) }
    check_config = LazyFixValidation.load_yaml(File.read(File.join(stage, 'lazy-fix.yaml'), encoding: 'UTF-8'))
    check_config['geox-url'] = %w[mmdb asn geoip geosite].to_h { |key| [key, 'disabled://network-forbidden'] }
    check_path = File.join(home, 'check.yaml')
    write(check_path, YAML.dump(check_config))
    out, error, status = Open3.capture3(binary, '-t', '-d', home, '-f', check_path)
    # A local verification log must not publish the runner's absolute directories.
    safe = (out + error).gsub(stage, '<build-output>').gsub(binary, '<mihomo>')
    write(File.join(stage, 'mihomo-check.txt'), safe)
    raise 'Mihomo syntax check failed; no output was replaced' unless status.success?
    version, = Open3.capture3(binary, '-v')
    { 'performed' => true, 'passed' => true, 'version' => version.lines.first.to_s.strip,
      'mode' => 'syntax-only; no TUN or proxy listener started; database download URLs disabled in validation copy' }
  ensure
    FileUtils.rm_rf(home) if home && File.directory?(home)
  end

  def self.check_public_yaml!(config)
    raise 'Public configuration must not contain nodes or providers' if config.key?('proxies') || config.key?('proxy-providers')
    expected = [{ 'name' => 'PROXY', 'type' => 'select', 'proxies' => ['REJECT'] }]
    raise 'Public PROXY group must use only the REJECT placeholder' unless config['proxy-groups'] == expected
    forbidden = %w[secret external-controller external-controller-tls authentication]
    raise 'Public configuration contains private control settings' unless (config.keys & forbidden).empty?
  end

  def self.check_output_path!(output)
    raise 'Output must not replace the source directory or its parent' if output == ROOT || ROOT.start_with?(output + File::SEPARATOR)
    raise 'Output cannot be a symlink' if File.symlink?(output)
    return unless File.exist?(output)
    raise 'Output exists and is not a directory' unless File.directory?(output)
    return if Dir.children(output).empty?
    manifest = File.join(output, 'manifest.json')
    unless File.file?(manifest) && JSON.parse(File.read(manifest))['artifact'] == 'lazy-fix-public'
      raise 'Refusing to replace a non-build output directory'
    end
  end

  def self.replace_output(stage, output)
    old = nil
    if File.exist?(output)
      old = output + '.previous-' + SecureRandom.hex(5)
      File.rename(output, old)
    end
    begin
      File.rename(stage, output)
    rescue StandardError
      File.rename(old, output) if old
      raise
    end
    FileUtils.rm_rf(old) if old
  end

  def self.run(output:, data_dir: nil, source_dir: nil)
    output = File.expand_path(output)
    check_output_path!(output)
    overrides = load_overrides
    batch = Time.now.utc.strftime('%Y%m%dT%H%M%SZ') + '-' + SecureRandom.hex(3)
    FileUtils.mkdir_p(File.dirname(output))
    stage = Dir.mktmpdir('.lazy-fix-build-', File.dirname(output))
    source = Sources.new(stage, source_dir: source_dir)
    puts '读取同一批上游规则…'
    base = source.fetch(BASE_URL)
    general = read_general(base)
    top = active_lines(section(base, 'Rule'))
    urls = top.select { |s| s.start_with?('RULE-SET,') }.map { |s| s.split(',')[1] }
    source.fetch_many(urls + [ADS_URL])
    origin = top.flat_map do |line|
      if line.start_with?('RULE-SET,')
        fields = line.split(',')
        raise '顶层 RULE-SET 语法变化' unless fields.size == 3 && %w[PROXY DIRECT].include?(fields[2])
        parsed = LazyFixRules.parse_ruleset(source.fetch(fields[1]), policy: fields[2], source: fields[1])
        raise "规则源没有有效规则：#{fields[1]}" if parsed.empty?
        parsed
      else
        [LazyFixRules.parse_rule(line, source: BASE_URL)]
      end
    end
    parts = LazyFixRules.partition_rules(origin)
    raise '原版 FINAL 变化' unless parts[:final].size == 1 && parts[:final].first[:policy] == 'PROXY'

    ad_text = source.fetch(ADS_URL)
    raise '广告源出现其他配置段，需要复核' unless ad_text.scan(/^\[([^\]]+)\]/).flatten == ['Rule']
    all_ads = active_lines(section(ad_text, 'Rule')).map { |s| LazyFixRules.parse_rule(s, source: ADS_URL) }
    raise '广告源类型/策略变化，需要复核' unless all_ads.all? { |r| %w[DOMAIN-SUFFIX IP-CIDR].include?(r[:type]) && r[:policy] == 'REJECT' }
    ads = overrides['advertising_enabled'] ? all_ads.select { |r| r[:type] == 'DOMAIN-SUFFIX' } : []
    raise '广告源没有域名规则，需要复核' if overrides['advertising_enabled'] && ads.empty?
    exceptions = overrides['exceptions'].map { |s| LazyFixRules.parse_rule(s, source: 'overrides:exceptions') }
    domestic = overrides['domestic_direct'].map { |s| LazyFixRules.parse_rule(s, source: 'overrides:domestic_direct') }
    shared = exceptions + ads + domestic + parts[:domain] + parts[:network] + parts[:final]
    unsupported = shared.select { |r| %w[USER-AGENT URL-REGEX].include?(r[:type]) }
    # Windows process match is platform-specific and follows ad blocking, before broad Game/Steam rules.
    win_process = overrides['windows_process_direct'].map { |p| { type: 'PROCESS-NAME', value: p, policy: 'DIRECT', options: [] } }
    windows_rules = exceptions + ads + domestic + win_process + parts[:domain].reject { |r| %w[USER-AGENT URL-REGEX].include?(r[:type]) } + parts[:network] + parts[:final]
    header = "# Lazy-fix batch: #{batch}\n# Advertising enabled: #{overrides['advertising_enabled']}\n# Modified generated paired snapshot; both formats share this batch.\n# Sources: https://github.com/Johnshall/Shadowrocket-ADBlock-Rules-Forever\n# Rule contributors: https://github.com/blackmatrix7/ios_rule_script and https://github.com/iab0x00/ProxyRules\n"
    generated_rule = "[Rule]\n# 规则已展开为同批远程快照；由公开构建流程成对更新。\n" + shared.map { |r| LazyFixRules.sr_line(r) }.join("\n") + "\n\n"
    cfg = header + base.sub(/^\[Rule\].*?(?=^\[|\z)/m) { generated_rule }
    raise '规则段替换失败' if cfg.include?("\nRULE-SET,")
    %w[General Proxy Proxy\ Group Host URL\ Rewrite MITM].each do |name|
      raise "#{name} 原版设置未保留" unless section(cfg, name) == section(base, name)
    end
    write(File.join(stage, 'lazy-fix.cfg'), cfg)
    # Some Shadowrocket import paths expect .conf. This is an exact byte alias,
    # not another policy variant.
    write(File.join(stage, 'lazy-fix.conf'), cfg)
    yaml = windows_config(base, general, windows_rules)
    check_public_yaml!(yaml)
    write(File.join(stage, 'lazy-fix.yaml'), header + YAML.dump(yaml))
    write(File.join(stage, 'overrides.json'), JSON.pretty_generate(overrides) + "\n")
    puts '检查双格式规则与 Mihomo 语法…'
    ad_sample = ads.find do |rule|
      !exceptions.any? do |exception|
        domain, allowed = rule[:value].downcase, exception[:value].downcase
        domain == allowed || (exception[:type] == 'DOMAIN-SUFFIX' && domain.end_with?('.' + allowed))
      end
    end
    checks = LazyFixValidation.check!(File.join(stage, 'lazy-fix.cfg'), File.join(stage, 'lazy-fix.yaml'),
      advertising_enabled: overrides['advertising_enabled'], advertising_domain: ad_sample ? ad_sample[:value] : 'ad.12306.cn',
      exceptions: overrides['exceptions'], windows_process_direct: overrides['windows_process_direct'])
    geodata = prepare_data(stage, data_dir: data_dir)
    checks['mihomo'] = syntax_check(stage)
    checks[:limits] << 'Fixtures test routing-policy selection; PROXY is an unbound REJECT placeholder until a private local merge supplies the node.'
    checks['batch'] = batch
    checks['shadowrocket_extension_alias_identical'] = File.binread(File.join(stage, 'lazy-fix.cfg')) == File.binread(File.join(stage, 'lazy-fix.conf'))
    raise 'Shadowrocket extension alias differs' unless checks['shadowrocket_extension_alias_identical']
    checks['shadowrocket_non_rule_sections_preserved'] = true
    checks['windows_only_processes'] = overrides['windows_process_direct']
    checks['unsupported_mihomo_rules'] = unsupported.map { |r| { 'type' => r[:type], 'value' => r[:value], 'policy' => r[:policy], 'source' => r[:source] } }
    checks['not_live_tested'] = ['Shadowrocket import and connection', 'iPhone/iPad apps', 'Windows TUN', 'CS2/5E/Perfect World/Valorant sessions']
    write(File.join(stage, 'validation.json'), JSON.pretty_generate(checks) + "\n")
    manifest = {
      'artifact' => 'lazy-fix-public', 'batch' => batch, 'generated_at' => Time.now.utc.iso8601,
      'source_mode' => source_dir ? 'reused-snapshot' : 'downloaded', 'source_snapshot_batch' => source.snapshot_batch,
      'generator_sha256' => %w[build.rb rules.rb validate.rb].to_h { |name| [name, Digest::SHA256.file(File.join(ROOT, name)).hexdigest] },
      'base' => BASE_URL, 'advertising_source' => ADS_URL,
      'sources' => source.entries.sort_by { |e| e['url'] },
      'geodata' => geodata,
      'counts' => { 'original_rules' => origin.size, 'original_ruleset_sources' => urls.size,
        'advertising_domain_rules' => ads.size, 'advertising_ip_rules_excluded' => all_ads.count { |r| r[:type] == 'IP-CIDR' },
        'shadowrocket_rules' => shared.size, 'mihomo_unsupported_rules' => unsupported.size,
        'domestic_supplements' => domestic.size },
      'outputs' => %w[lazy-fix.cfg lazy-fix.conf lazy-fix.yaml overrides.json].to_h { |name| [name, Digest::SHA256.file(File.join(stage, name)).hexdigest] },
      'aliases' => { 'lazy-fix.conf' => 'lazy-fix.cfg' },
      'notes' => ['Snapshot rules do not refresh independently on clients.', 'GeoIP CN uses each client database; border classification may differ.', 'Public outputs contain no node credentials. Windows requires a device-local private PROXY binding; the public placeholder rejects proxy traffic.']
    }
    write(File.join(stage, 'manifest.json'), JSON.pretty_generate(manifest) + "\n")
    replace_output(stage, output)
    puts "完成：#{batch}；#{ads.size} 条广告域名规则，#{unsupported.size} 条已列明的客户端不兼容匹配。"
  ensure
    FileUtils.rm_rf(stage) if stage && File.directory?(stage) && File.basename(stage).start_with?('.lazy-fix-build-')
  end
end

if $PROGRAM_NAME == __FILE__
  begin
    options = {}
    parser = OptionParser.new do |args|
      args.banner = 'Usage: ruby build.rb --output DIR [--data-dir DIR] [--source-dir DIR]'
      args.on('--output DIR') { |value| options[:output] = value }
      args.on('--data-dir DIR') { |value| options[:data_dir] = value }
      args.on('--source-dir DIR') { |value| options[:source_dir] = value }
    end
    parser.parse!
    raise parser.banner unless options[:output] && !options[:output].empty? && ARGV.empty?
    File.umask(0022)
    LazyFixBuild.run(**options)
  rescue StandardError => error
    warn "Build failed; no new outputs published: #{error.message}"
    exit 1
  end
end
