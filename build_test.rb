# frozen_string_literal: true
require 'minitest/autorun'
require 'tmpdir'
require_relative 'build'

class PublicBuildTest < Minitest::Test
  RULE_URL = 'https://example.org/fixture.list'

  def base_config
    <<~CONFIG
      [General]
      skip-proxy = localhost
      tun-excluded-routes = 127.0.0.0/8,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16
      dns-server = https://dns.alidns.com/dns-query,223.5.5.5
      fallback-dns-server = system
      ipv6 = true
      prefer-ipv6 = false
      dns-direct-system = false
      icmp-auto-reply = true
      always-reject-url-rewrite = false
      private-ip-answer = true
      dns-direct-fallback-proxy = true
      hijack-dns = 8.8.8.8:53,8.8.4.4:53
      udp-policy-not-supported-behaviour = REJECT
      stun-response-ip = 1.1.1.1
      stun-response-ipv6 = ::1
      block-quic = all-proxy

      [Proxy]
      # Nodes remain on the device.
      [Proxy Group]
      [Rule]
      DOMAIN-SUFFIX,google.com,PROXY
      RULE-SET,#{RULE_URL},DIRECT
      GEOIP,CN,DIRECT
      FINAL,PROXY
      [Host]
      *.apple.com = server:system
      *.icloud.com = server:system
      localhost = 127.0.0.1
      [URL Rewrite]
      ^https?://google.cn https://www.google.com 302
      [MITM]
      hostname = *.google.cn
    CONFIG
  end

  def fixture_rules
    <<~RULES
      # The outer DIRECT policy must override this QX row's group name.
      HOST-SUFFIX,12306.cn,Global
      HOST-SUFFIX,apple.com,Apple
      HOST-SUFFIX,wechatpay.com,WeChat
      HOST-SUFFIX,bilibili.com,BiliBili
      HOST-WILDCARD,*.example.cn,China
      USER-AGENT,*Fixture*
      URL-REGEX,^https://fixture.example/video/
      IP-CIDR,127.0.0.0/8,no-resolve
      IP-CIDR,10.0.0.0/8,no-resolve
      IP-CIDR,172.16.0.0/12,no-resolve
      IP-CIDR,192.168.0.0/16,no-resolve
      IP6-CIDR,::1/128,China
      IP6-CIDR,fc00::/7,China
    RULES
  end

  def downloads(rules = fixture_rules)
    {
      LazyFixBuild::BASE_URL => base_config,
      LazyFixBuild::ADS_URL => "[Rule]\nDOMAIN-SUFFIX,ad.12306.cn,Reject\nIP-CIDR,192.0.2.3/32,Reject\n",
      RULE_URL => rules,
      LazyFixBuild::COUNTRY_URL => "fixture-country\xAB\xCD\xEFMaxMind.com".b,
      LazyFixBuild::ASN_URL => "fixture-asn\xAB\xCD\xEFMaxMind.com".b
    }
  end

  def build_with_fixture(output, rules = fixture_rules)
    data = downloads(rules)
    fetch = lambda { |url, max_bytes:, metadata: nil| data.fetch(url) }
    no_core = lambda { |_stage| { 'performed' => false, 'passed' => nil, 'reason' => 'test fixture; no core run' } }
    LazyFixBuild.stub(:download, fetch) do
      LazyFixBuild.stub(:syntax_check, no_core) do
        capture_io { LazyFixBuild.run(output: output) }
      end
    end
  end

  def test_public_build_retains_shared_rules_and_no_node_dependencies
    Dir.mktmpdir('public-build-test-') do |dir|
      output = File.join(dir, 'dist')
      build_with_fixture(output)
      cfg = File.read(File.join(output, 'lazy-fix.cfg'))
      yaml = LazyFixValidation.load_yaml(File.read(File.join(output, 'lazy-fix.yaml')))
      manifest = JSON.parse(File.read(File.join(output, 'manifest.json')))
      validation = JSON.parse(File.read(File.join(output, 'validation.json')))
      assert_equal File.binread(File.join(output, 'lazy-fix.cfg')), File.binread(File.join(output, 'lazy-fix.conf'))
      assert_equal manifest['outputs']['lazy-fix.cfg'], manifest['outputs']['lazy-fix.conf']
      refute yaml.key?('proxies')
      refute yaml.key?('proxy-providers')
      assert_equal [{ 'name' => 'PROXY', 'type' => 'select', 'proxies' => ['REJECT'] }], yaml['proxy-groups']
      assert_includes yaml['rules'], 'PROCESS-NAME,cs2.exe,DIRECT'
      refute_includes cfg, 'PROCESS-NAME'
      assert_equal 2, validation.fetch('unsupported_mihomo_rules').size
      assert validation.fetch('passed')
      assert_equal false, validation.fetch('mihomo').fetch('performed')
      assert_equal manifest.fetch('batch'), validation.fetch('batch')
      assert_includes cfg, "# Lazy-fix batch: #{manifest.fetch('batch')}"
      assert_includes File.read(File.join(output, 'lazy-fix.yaml')), "# Lazy-fix batch: #{manifest.fetch('batch')}"
      %w[General Proxy Proxy\ Group Host URL\ Rewrite MITM].each do |name|
        assert_equal LazyFixBuild.section(base_config, name), LazyFixBuild.section(cfg, name)
      end
      manifest.fetch('sources').each do |source|
        assert_match(%r{\Ahttps://}, source.fetch('url'))
        assert_equal source.fetch('sha256'), Digest::SHA256.file(File.join(output, source.fetch('file'))).hexdigest
      end
      manifest.fetch('geodata').each do |source|
        assert_match(%r{\Ahttps://github.com/MetaCubeX/}, source.fetch('source'))
      end
      refute_includes JSON.generate(manifest), Dir.pwd
      refute_includes JSON.generate(validation), dir
    end
  end

  def test_unknown_or_empty_ruleset_preserves_previous_output
    Dir.mktmpdir('failure-test-') do |dir|
      output = File.join(dir, 'dist')
      build_with_fixture(output)
      original = File.binread(File.join(output, 'manifest.json'))
      ["UNKNOWN-RULE,example.com\n", "# temporarily unavailable\n"].each do |bad_rules|
        assert_raises(ArgumentError, RuntimeError) { build_with_fixture(output, bad_rules) }
        assert_equal original, File.binread(File.join(output, 'manifest.json'))
        assert_empty Dir.glob(File.join(dir, '.lazy-fix-build-*'))
      end
    end
  end

  def test_failed_directory_switch_restores_previous_output
    Dir.mktmpdir('rename-test-') do |dir|
      output, stage = %w[dist staged].map { |name| File.join(dir, name) }
      [output, stage].each { |path| FileUtils.mkdir_p(path) }
      File.write(File.join(output, 'marker'), 'old')
      File.write(File.join(stage, 'marker'), 'new')
      original = File.method(:rename)
      rename = lambda do |from, to|
        raise IOError, 'simulated rename failure' if from == stage
        original.call(from, to)
      end
      File.stub(:rename, rename) { assert_raises(IOError) { LazyFixBuild.replace_output(stage, output) } }
      assert_equal 'old', File.read(File.join(output, 'marker'))
    end
  end

  def test_no_mihomo_environment_is_explicitly_unchecked
    result = LazyFixBuild.syntax_check('unused', binary: nil)
    assert_equal false, result.fetch('performed')
    assert_nil result.fetch('passed')
    assert_match(/No core syntax check/, result.fetch('reason'))
  end

  def test_public_node_or_provider_injection_is_rejected
    template = { 'proxy-groups' => [{ 'name' => 'PROXY', 'type' => 'select', 'proxies' => ['REJECT'] }] }
    LazyFixBuild.check_public_yaml!(template)
    %w[proxies proxy-providers secret external-controller].each do |key|
      assert_raises(RuntimeError) { LazyFixBuild.check_public_yaml!(template.merge(key => 'forbidden')) }
    end
  end

  def test_safe_yaml_reading_rejects_object_tags
    assert_equal({ 'example' => true }, LazyFixValidation.load_yaml("example: true\n"))
    assert_raises(Psych::DisallowedClass) { LazyFixValidation.load_yaml("--- !ruby/object:Object {}\n") }
  end

  def test_official_contents_fallback_retains_the_same_repository_ref_and_path
    raw = 'https://raw.githubusercontent.com/example/rules/main/nested/Some.list'
    assert_equal 'https://api.github.com/repos/example/rules/contents/nested/Some.list?ref=main', LazyFixBuild.github_contents_url(raw)
    assert_nil LazyFixBuild.github_contents_url('https://example.org/file.list')
    assert_raises(RuntimeError) { LazyFixBuild.github_contents_url(raw + '?unexpected=true') }
  end

  def test_binary_download_and_actual_retrieval_provenance
    raw = 'https://raw.githubusercontent.com/example/rules/main/Some.list'
    responses = [
      ['', 'timeout', Struct.new(:exitstatus) { def success?; false; end }.new(28)],
      ["\xAB\xCD\xEFMaxMind.com".b, '', Struct.new(:exitstatus) { def success?; true; end }.new(0)]
    ]
    calls = []
    capture = lambda do |*args|
      calls << args
      responses.shift
    end
    previous = ENV.delete('GITHUB_RAW_VIA_API')
    metadata = {}
    Open3.stub(:capture3, capture) do
      result = LazyFixBuild.download(raw, max_bytes: 1000, metadata: metadata)
      assert_equal Encoding::BINARY, result.encoding
      assert_equal 2, calls.length
      assert_equal({ binmode: true }, calls.last.last)
      assert_equal LazyFixBuild.github_contents_url(raw), metadata.fetch('retrieval_url')
    end
  ensure
    ENV['GITHUB_RAW_VIA_API'] = previous if previous
  end

  def test_supplied_databases_are_explicitly_reused_without_disclosing_paths
    Dir.mktmpdir('database-test-') do |dir|
      data_dir, stage = %w[input build].map { |name| File.join(dir, name) }
      FileUtils.mkdir_p(data_dir)
      %w[Country.mmdb ASN.mmdb].each do |name|
        File.binwrite(File.join(data_dir, name), "fixture\xAB\xCD\xEFMaxMind.com".b)
      end
      no_download = lambda { |*args| flunk 'Local data mode must not download databases' }
      LazyFixBuild.stub(:download, no_download) do
        records = LazyFixBuild.prepare_data(stage, data_dir: data_dir)
        assert_equal %w[reused-local reused-local], records.map { |entry| entry['acquisition'] }
        assert_equal %w[local-reused local-reused], records.map { |entry| entry['source'] }
        refute_includes JSON.generate(records), dir
        records.each do |entry|
          assert_match(%r{\Ahttps://github.com/MetaCubeX/}, entry['reference_url'])
          assert_equal entry['sha256'], Digest::SHA256.file(File.join(stage, entry['file'])).hexdigest
        end
      end
    end
  end

  def test_reused_sources_keep_original_timestamp_and_verify_hash
    Dir.mktmpdir('source-reuse-test-') do |dir|
      output = File.join(dir, 'dist')
      build_with_fixture(output)
      old = JSON.parse(File.read(File.join(output, 'manifest.json')))
      stage = File.join(dir, 'reuse')
      source = LazyFixBuild::Sources.new(stage, source_dir: File.join(output, 'sources'))
      no_download = lambda { |*args| flunk 'Snapshot reuse must not contact the network' }
      LazyFixBuild.stub(:download, no_download) do
        assert_equal base_config, source.fetch(LazyFixBuild::BASE_URL)
      end
      previous = old.fetch('sources').find { |entry| entry['url'] == LazyFixBuild::BASE_URL }
      assert_equal previous.fetch('captured_at'), source.entries.first.fetch('captured_at')
      assert_equal 'reused-snapshot', source.entries.first.fetch('acquisition')
      assert_equal old.fetch('batch'), source.snapshot_batch
      File.write(File.join(output, previous.fetch('file')), 'tampered')
      another = LazyFixBuild::Sources.new(File.join(dir, 'bad'), source_dir: File.join(output, 'sources'))
      assert_raises(RuntimeError) { another.fetch(LazyFixBuild::BASE_URL) }
    end
  end
end
