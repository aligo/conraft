require 'erb'
require 'ostruct'
require 'open-uri'
require 'fileutils'
require 'base64'
require 'uri'
require 'yaml'
require 'json'

@ua = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko)'
@cache_dir = File.join(__dir__, 'cache')
FileUtils.mkdir_p @cache_dir
@output_dir = File.join(__dir__, 'outputs')
FileUtils.mkdir_p @output_dir

def read_cache(cache_name)
  cache_file = File.join(@cache_dir, cache_name)
  if (File.mtime(cache_file) rescue Time.at(0)) < (Time.now - 1 * 24 * 3600)
    data = yield
    File.open(cache_file, 'w').puts data
    data
  else
    File.open(cache_file).read
  end
end

def parse_ini(str)
  data = {lines: []}
  cur = data
  str.split("\n").each do |line|
    line.strip!
    case line
    when /^\#.*$/
    when /^\[(.+)\]$/
      cur = data[$1] ||= {lines: []}
    when /^(.+?)=(.+)$/
      cur[$1.strip] = $2.strip
    else
      cur[:lines].push line
    end
  end
  data
end

def craft_conf(conf_name, groups, exclude_rules = [])
  filtered_rules = @rules.reject { |r| exclude_rules.include?(r[2]) }
  filtered_rules_groups = @rules_groups.reject { |g| exclude_rules.include?(g) }

  File.open(File.join(@output_dir, "#{conf_name}.conf"), 'w').puts @surge_erb.result(OpenStruct.new(
    groups_proxies: @proxies_groups['surge'].select{|g,v| groups.include?(g)},
    rules:  filtered_rules,
    rules_groups: filtered_rules_groups,
    config: @config
  ).instance_eval { binding })

  File.open(File.join(@output_dir, "#{conf_name}.yaml"), 'w').puts @clash_erb.result(OpenStruct.new(
    groups_proxies: @proxies_groups['clash'].select{|g,v| groups.include?(g)},
    rules:  filtered_rules,
    rules_groups: filtered_rules_groups,
    config: @config
  ).instance_eval { binding })
end

def get_surge_line(server_conf)
  type = server_conf['type']
  surge_line = "#{type}, #{server_conf['server']}, #{server_conf['port']}, "
  params = {}

  case type
  when 'ss'
    params['encrypt-method'] = server_conf['cipher']
    params['password'] = server_conf['password']
    params['obfs'] = server_conf.dig('plugin-opts', 'mode')
    params['obfs-host'] = server_conf.dig('plugin-opts', 'host')
    params['udp-relay'] = 'true' if server_conf['udp-relay'] || server_conf['udp']

  when 'trojan'
    params['password'] = server_conf['password']
    params['sni'] = server_conf['sni']
    params['skip-cert-verify'] = 'true' if server_conf['skip-cert-verify']
    params['udp-relay'] = 'true' if server_conf['udp-relay'] || server_conf['udp']
    if server_conf['network'] == 'ws'
      params['ws'] = 'true'
      params['ws-path'] = server_conf.dig('ws-opts', 'path')
      ws_headers = server_conf.dig('ws-opts', 'headers')
      params['ws-headers'] = ws_headers.map { |k, v| "#{k}:#{v}" }.join('|') if ws_headers.is_a?(Hash) && !ws_headers.empty?
    end

  when 'vmess'
    params['username'] = server_conf['uuid']
    params['encrypt-method'] = server_conf['cipher']
    params['vmess-aead'] = 'true' if server_conf['alterId'].to_i == 0
    if server_conf['tls']
      params['tls'] = 'true'
      params['sni'] = server_conf['sni'] || server_conf['servername']
    end
    if server_conf['network'] == 'ws'
      params['ws'] = 'true'
      params['ws-path'] = server_conf.dig('ws-opts', 'path')
      ws_headers = server_conf.dig('ws-opts', 'headers')
      params['ws-headers'] = ws_headers.map { |k, v| "#{k}:#{v}" }.join('|') if ws_headers.is_a?(Hash) && !ws_headers.empty?
    end
    params['skip-cert-verify'] = 'true' if server_conf['skip-cert-verify']
    params['udp-relay'] = 'true' if server_conf['udp-relay'] || server_conf['udp']

  when 'hysteria2'
    params['password'] = server_conf['password']
    params['sni'] = server_conf['sni']
    params['skip-cert-verify'] = 'true' if server_conf['skip-cert-verify']
    down = server_conf['down']
    params['download-bandwidth'] = down.to_s.gsub(/[^\d]/, '') if down

  when 'tuic'
    params['uuid'] = server_conf['uuid']
    params['password'] = server_conf['password']
    params['version'] = (server_conf['version'] || 5).to_s
    params['sni'] = server_conf['sni']
    params['skip-cert-verify'] = 'true' if server_conf['skip-cert-verify']
    alpn = server_conf['alpn']
    params['alpn'] = (alpn.is_a?(Array) ? alpn.first : alpn.to_s) if alpn

  when 'snell'
    params['psk'] = server_conf['psk']
    params['version'] = server_conf['version']&.to_s
    params['obfs'] = server_conf.dig('obfs-opts', 'mode')
    params['obfs-host'] = server_conf.dig('obfs-opts', 'host')
  end

  surge_line += params.compact.select { |_, v| v.is_a?(String) && !v.empty? }.map { |k, v| "#{k}=#{v}" }.join(', ')
  surge_line
end

@config = YAML.load_file('./config.yml')


@rules = []
@rules_groups = ['@Global']

@config['rules'].each do |rule_set|
  group = rule_set.delete 'group'
  auto_proxy_list = rule_set.delete 'auto_proxy_list'
  force_remote_dns = rule_set.delete 'force_remote_dns'
  @rules_groups.push group unless @rules_groups.include?(group)
  rule_set.each do |rule_match, rule_config|
    rule_config['list']&.each do |l|
      @rules.push [rule_match, l, group]
    end
  end
  auto_proxy_list&.each do |list_name, url|
    list_data = read_cache(list_name){ Base64.decode64(URI.open(url, 'User-Agent' => @ua).read) }
    list_data.split("\n").each do |l|
      unless l.empty? || (l =~ /^[\!\[\@\/]/)
        l.gsub! /^(?:[^\/]+:\/\/)?(?:.*\*\.)?([^\/]+)(?:\/.*)?/, '\1'
        l.gsub! /^(?:\.|\|{1,2}|\*)?(.+)/, '\1'
        rule = ['DOMAIN-SUFFIX', l, group]
        rule.push 'force-remote-dns' if force_remote_dns
        @rules.push rule
      end
    end
  end
end

@rules_groups -= ['Proxy', 'DIRECT']

@surge_erb = ERB.new(File.open('templates/surge.conf.erb','r').read)
@clash_erb = ERB.new(File.open('templates/clash.yaml.erb','r').read)

@proxies_groups = {'surge' => {}, 'clash' => {}}

@config['servers'].each do |conf_name, conf|
  begin
    @proxies_groups['surge'][conf_name] = {}
    @proxies_groups['clash'][conf_name] = []

    conf['servers']&.each do |name, server_conf|
      server_name = "#{conf_name}: #{name}"
      @proxies_groups['clash'][conf_name].push({'name' => server_name}.merge(server_conf))
      @proxies_groups['surge'][conf_name][server_name] = get_surge_line(server_conf)
    end
    clash_conf = if conf['clash_path']
      File.read(File.expand_path(conf['clash_path'], __dir__))
    elsif conf['clash_url']
      read_cache("#{conf_name}_clash"){ URI.open(conf['clash_url'], 'User-Agent' => @ua).read }
    end
    if clash_conf
      clash_data = YAML.load clash_conf
      proxies = clash_data['proxies'] || clash_data['Proxy']
      proxies.each do |server_conf|
        server_name = "#{conf_name}: #{server_conf['name'].strip}"
        @proxies_groups['clash'][conf_name].push(server_conf.merge('name' => server_name))
        @proxies_groups['surge'][conf_name][server_name] = get_surge_line(server_conf)
      end
    end

    surge_conf = if conf['surge_path']
      File.read(File.expand_path(conf['surge_path'], __dir__))
    elsif conf['surge_url']
      read_cache("#{conf_name}_surge"){ URI.open(conf['surge_url'], 'User-Agent' => @ua).read }
    end
    if surge_conf
      @proxies_groups['surge'][conf_name] = {}
      surge_data = parse_ini(surge_conf)
      proxies = surge_data['Proxy']
      proxies.delete :lines
      proxies.select!{|k,v| v!= 'direct'}
      @proxies_groups['surge'][conf_name].merge! proxies.map{|k,v| ["#{conf_name}: #{k}",v] }.to_h
    end

    if conf['excludes']
      conf['excludes'].each do |exclude|
        @proxies_groups.each do |type, groups|
          groups[conf_name].reject! do |item|
            item.to_s.include?(exclude)
          end
        end
      end
    end
  rescue => e
    puts "Error on `#{conf_name}`"
    raise e
  end
end

@config['outputs'].each do |name, conf|
  if conf.is_a?(Array)
    craft_conf(name, conf)
  else
    craft_conf(name, conf['servers'], conf['exclude_rules'] || [])
  end
end

@config['after_cmds'].each do |cmd|
  `#{cmd}`
end