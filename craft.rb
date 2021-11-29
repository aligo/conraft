require 'erb'
require 'ostruct'
require 'open-uri'
require 'fileutils'
require 'base64'
require 'yaml'
require 'json'

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

def craft_conf(conf_name, groups)
  File.open(File.join(@output_dir, "#{conf_name}.conf"), 'w').puts @surge_erb.result(OpenStruct.new(
    groups_proxies: @proxies_groups['surge'].select{|g,v| groups.include?(g)},
    rules:  @rules,
    rules_groups: @rules_groups,
    config: @config
  ).instance_eval { binding })

  File.open(File.join(@output_dir, "#{conf_name}.yaml"), 'w').puts @clash_erb.result(OpenStruct.new(
    groups_proxies: @proxies_groups['clash'].select{|g,v| groups.include?(g)},
    rules:  @rules,
    rules_groups: @rules_groups,
    config: @config
  ).instance_eval { binding })
end

def get_surge_line(server_conf)
  surge_line = "#{server_conf['type']}, #{server_conf['server']}, #{server_conf['port']}, "
  params = {}
  case server_conf['type']
  when 'ss'
    params = {
      'encrypt-method' => server_conf['cipher'],
      'password'       => server_conf['password'],
      'obfs'           => server_conf.dig('plugin-opts', 'mode'),
      'obfs-host'      => server_conf.dig('plugin-opts', 'host'),
      'udp-relay'      => server_conf['udp-relay']&.presence&.to_s,
    }
  end
  surge_line += params.select{|k, v| v&.length}.map{|k, v| "#{k}=#{v}"}.join(', ')
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
    list_data = read_cache(list_name){ Base64.decode64(open(url).read) }
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
  @proxies_groups['surge'][conf_name] = {}
  @proxies_groups['clash'][conf_name] = []

  conf['servers']&.each do |name, server_conf|
    server_name = "#{conf_name}: #{name}"
    @proxies_groups['clash'][conf_name].push({'name' => server_name}.merge(server_conf))
    @proxies_groups['surge'][conf_name][server_name] = get_surge_line(server_conf)
  end
  if conf['clash_url']
    if clash_conf = read_cache("#{conf_name}_clash"){ open(conf['clash_url']).read }
      clash_data = YAML.load clash_conf
      proxies = clash_data['proxies'] || clash_data['Proxy']
      proxies.each do |server_conf|
        server_name = "#{conf_name}: #{server_conf['name'].strip}"
        @proxies_groups['clash'][conf_name].push({'name' => server_name}.merge(server_conf))
        @proxies_groups['surge'][conf_name][server_name] = get_surge_line(server_conf)
      end
    end
  end
  if conf['surge_url']
    if surge_conf = read_cache("#{conf_name}_surge"){ open(conf['surge_url']).read }
      @proxies_groups['surge'][conf_name] = {}
      surge_data = parse_ini(surge_conf)
      proxies = surge_data['Proxy']
      proxies.delete :lines
      proxies.select!{|k,v| v!= 'direct'}
      @proxies_groups['surge'][conf_name].merge! proxies.map{|k,v| ["#{conf_name}: #{k}",v] }.to_h
    end
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
end

@config['outputs'].each do |name, servers|
  craft_conf(name, servers)
end

@config['after_cmds'].each do |cmd|
  exec cmd
end