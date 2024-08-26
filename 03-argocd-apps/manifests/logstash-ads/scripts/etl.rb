require 'time'
require 'date'
require 'dalli'
require 'net/http'
require "json"
require 'securerandom'
require 'ipaddr'
require 'csv'
require 'nokogiri'
require_relative 'sigma.rb'

# For Community-ID
require 'socket'
require 'digest'
require 'base64'

TRANSPORT_PROTOS = ['icmp', 'icmp6', 'tcp', 'udp', 'sctp']

PROTO_MAP = {
  'icmp' => 1,
  'tcp' => 6,
  'udp' => 17,
  'icmp6' => 58
}

ICMP4_MAP = {
  # Echo => Reply
  8 => 0,
  # Reply => Echo
  0 => 8,
  # Timestamp => TS reply
  13 => 14,
  # TS reply => timestamp
  14 => 13,
  # Info request => Info Reply
  15 => 16,
  # Info Reply => Info Req
  16 => 15,
  # Rtr solicitation => Rtr Adverstisement
  10 => 9,
  # Mask => Mask reply
  17 => 18,
  # Mask reply => Mask
  18 => 17,
}

ICMP6_MAP = {
  # Echo Request => Reply
  128 => 129,
  # Echo Reply => Request
  129 => 128,
  # Router Solicit => Advert
  133 => 134,
  # Router Advert => Solicit
  134 => 133,
  # Neighbor Solicit => Advert
  135 => 136,
  # Neighbor Advert => Solicit
  136 => 135,
  # Multicast Listener Query => Report
  130 => 131,
  # Multicast Report => Listener Query
  131 => 130,
  # Node Information Query => Response
  139 => 140,
  # Node Information Response => Query
  140 => 139,
  # Home Agent Address Discovery Request => Reply
  144 => 145,
  # Home Agent Address Discovery Reply => Request
  145 => 144,
}

VERSION = '1:'

# If this need to be changed so please change es-child.rb accordingly
MISP_IP = '10.141.98.162'
MISP_KEY = 'j7QDoNn6Z4nrXZTupWWxsJU9kD3PuqqE4XJuYNvd'

def bin_to_hex(s)
  s.each_byte.map { |b| b.to_s(16).rjust(2, '0') }.join(':')
end

# ###

def register(params)
    @blacklist_map = {}

    $stdout.sync = true
    @mc = Dalli::Client.new('memcached.memcached.svc.cluster.local:11211')
    @record_def = load_fields_map('/configs/fields-map.cfg')
    @cidr_map = load_cidr_map('/configs/cidr-map.cfg')
    @brute_force_map = load_brute_force_map('/configs/bruteforce.cfg')
    @blacklist_ip_map = load_blacklist_ip('/configs/watchlist-ip.cfg')
    @blacklist_url_map = load_blacklist_map('/configs/watchlist-url.cfg', 'url')
    @blacklist_hash_map = load_blacklist_map('/configs/watchlist-hash.cfg', 'hash')
    @blacklist_domain_map = load_blacklist_map('/configs/watchlist-domain.cfg', 'domain')

    @blacklist_map['ip'] = @blacklist_ip_map
    @blacklist_map['url'] = @blacklist_url_map
    @blacklist_map['hash'] = @blacklist_hash_map
    @blacklist_map['domain'] = @blacklist_domain_map

    @priority_map = {
        "1" => "high",
        "2" => "medium",
        "3" => "low"
    }

    # For Community-ID
    @use_base64 = params.fetch("use_base64", "true")
    @comm_id_seed = params.fetch("community_id_seed", "0").to_i
    # ###

    #load_malware_family_galaxies_cluster()
end

def load_brute_force_map(file_name)
    rec_map = Hash.new()

    fo = File.new(file_name, "r")
    while (line = fo.gets)
        #comment line
        if line.match(/^#.*$/)
            next
        end
  
        #blank line
        if line.match(/^\s*$/)
            next
        end
  
        category, user_field, status_field, fail_value, threshold = line.split(":")
        rec_map[category] = {
            "user_field" => user_field.strip,
            "status_field" => status_field.strip, 
            "fail_value" => fail_value.strip,
            "threshold" => threshold.strip
        }

        puts("DEBUG BRUTE-FORCE : #{category} -> #{line.strip}")
    end
    fo.close
  
    return rec_map
end

def load_cidr_map(file_name)
    rec_map = Hash.new()

    fo = File.new(file_name, "r")
    while (line = fo.gets)
        #comment line
        if line.match(/^#.*$/)
            next
        end
  
        #blank line
        if line.match(/^\s*$/)
            next
        end
  
        cidr, department = line.split(":")

        begin
            net1 = IPAddr.new(cidr)
        rescue
            puts("ERROR CIDR : #{cidr} -> #{department}")
        else
            #No error
            rec_map[cidr] = department.strip
            puts("DEBUG CIDR : #{cidr} -> #{department}")
        end
    end
    fo.close
  
    return rec_map
end

def load_blacklist_ip(file_name)
    rec_map = Hash.new()

    fo = File.new(file_name, "r")
    while (line = fo.gets)
        #comment line
        if line.match(/^#.*$/)
            next
        end
  
        #blank line
        if line.match(/^\s*$/)
            next
        end
  
        ip, count, total = line.split(":")

        begin
            net1 = IPAddr.new(ip)
        rescue
            puts("ERROR Blacklist IP : #{ip} -> #{ip}")
        else
            #No error
            rec_map[ip] = ip.strip
            puts("DEBUG Blacklist IP : #{ip} -> #{ip}")
        end
    end
    fo.close
  
    return rec_map
end

def load_blacklist_map(file_name, type)
    rec_map = Hash.new()

    fo = File.new(file_name, "r")
    while (line = fo.gets)
        #comment line
        if line.match(/^#.*$/)
            next
        end
  
        #blank line
        if line.match(/^\s*$/)
            next
        end
  
        strip_line = line.strip
        rec_map[line] = strip_line
        puts("DEBUG Loading from [#{file_name}] type=[#{type}] : [#{strip_line}]")
    end
    fo.close
  
    return rec_map
end

def load_fields_map(file_name)
    rec_map = Hash.new()
    fo = File.new(file_name, "r")
  
    while (line = fo.gets)
        #comment line
        if line.match(/^#.*$/)
            next
        end
  
        #blank line
        if line.match(/^\s*$/)
            next
        end
  
        tokens = line.split(":")
        cnt = 0
        rectype = ''
        fields_map = nil
  
        tokens.each do |token|
            if (cnt == 0)
                rectype = token
                rec_map[rectype] = Hash.new(rectype)
                fields_map = rec_map[rectype]
            else
                field_name, index = token.split("=")
                fields_map[field_name] = index.strip
                puts("DEBUG : #{rectype}:#{field_name}->#{index}")
            end
            cnt = cnt+1
        end
    end
    fo.close
  
    return rec_map
end

def is_above_cti_rate_limit(event, cache, attribute)

    rate_key = "cti-rate:#{attribute}"
    request_count = 0

    rc = cache.get(rate_key)
    if rc
        request_count = rc.to_i + 1
    else
        request_count = 1
    end

    rm = ENV["CTI_RATE_LIMIT"]
    cti_rate_limit = rm.to_i

    if (request_count > cti_rate_limit)
        event.set('ads_cti_status', 'rate-limit')
        return true
    else
        cache.set(rate_key, "#{request_count}", 1) #1 sec expiration
    end

    return false
end

def is_above_cti_error_limit(event, cache)

    rate_key = "cti-error-rate"
    request_count = 0

    rc = cache.get(rate_key)
    if rc
        request_count = rc.to_i
    else
        request_count = 1
    end

    rm = ENV["CTI_ERROR_RATE_LIMIT"]
    cti_error_rate_limit = rm.to_i

    if (request_count > cti_error_rate_limit)
        event.set('ads_cti_status', 'error-rate-limit')
        return true, request_count, rate_key
    end

    return false, request_count, rate_key
end

def load_malware_family_galaxies_cluster()

    uri = URI.parse("https://#{MISP_IP}/galaxy_clusters/index/83") # 83 is malware_family cluster
    api_key = MISP_KEY

    https = Net::HTTP.new(uri.host, uri.port)
    https.use_ssl = true
    https.verify_mode = OpenSSL::SSL::VERIFY_NONE
    https.read_timeout = 0.5
    https.open_timeout = 0.5
    https.max_retries = 0

    request = Net::HTTP::Get.new(uri.path)
    request['Accept'] = 'application/json'
    request['Content-Type'] = 'application/json'
    request['Authorization'] = api_key

    status = ''
    for i in 1..3 do # 3 attempts

        puts "### Trying to load malware-family from MISP, attempt no [#{i}]..."
        begin
            response = https.request(request)
        rescue TimeoutError
            status = 'misp-timeout'
        else
            #No error
            status = response.code
        end

        if (status == "200")
            @malware_families = Hash.new()

            misp_data = response.body
            arrs = JSON.parse(misp_data)
 
            if (arrs.count > 0)
                arrs.each do |obj|
                    cluster = obj['GalaxyCluster']
                    uuid = cluster['uuid']
                    value = cluster['value']

                    puts("### DEBUG - [#{uuid}] --> [#{value}]")
                    @malware_families[uuid] = value
                end
            else
                puts("### [Error] Got empty array of malware-family!!!")
            end

            return
        end
    end

    abort("### [Error] Unable to load malware-family from MISP [#{response}]")
end

def get_misp_response(event, cache, attribute, value)

    if (is_above_cti_rate_limit(event, cache, attribute))
        return nil
    end

    hit_error_limit, error_count, cache_key = is_above_cti_error_limit(event, cache)
    if (hit_error_limit)
        return nil
    end

    #return nil

    #uri = URI.parse('https://10.141.98.46/attributes/restSearch') #Old
    #api_key = 'QjR1eIKxQLcsQ4QP8YImJaQ7EfiaMfgFgeELNtST' #'jpk4wrH2EKoFbnjUeNZ12SUIRpGSGa5SORGTjJGP' #Old

    #uri = URI.parse('https://10.141.98.162/attributes/restSearch')
    #api_key = 'bQNDXokdTrgPR0KdDQKdMZKSza3NhqctrqM78w21' #'QHhSqz0asno9sHsGxGVmWfR5XKpC2GHwQjmeYphr'

    #uri = URI.parse('https://1.179.227.47/attributes/restSearch')
    #api_key = 'XsAoFxY6ygzKp5PL5mFiCf4pJgmyVP7M8QsmtqyO'

    uri = URI.parse("https://#{MISP_IP}/attributes/restSearch")
    api_key = MISP_KEY


    https = Net::HTTP.new(uri.host, uri.port)
    https.use_ssl = true
    https.verify_mode = OpenSSL::SSL::VERIFY_NONE
    https.read_timeout = 0.5
    https.open_timeout = 0.5
    https.max_retries = 0

    request = Net::HTTP::Post.new(uri.path)
    request['Accept'] = 'application/json'
    request['Content-Type'] = 'application/json'
    request['Authorization'] = api_key

    data = {
        "returnFormat" => "json",
        "enforceWarninglist" => true,
        "includeContext" => true,
        "value" => value,
        "limit" => "1",
        "type" => [ attribute ]
    }.to_json;
    request.body = "#{data}"

    status = ''
    begin
        response = https.request(request)
    rescue TimeoutError
        status = 'cti-timeout'
    else
        #No error
        status = response.code
    end
    event.set('ads_cti_status', "#{status}")

    if (status == "200")
        #puts response.body
        return response.body
    end

    error_count = error_count + 1
    cache.set(cache_key, "#{error_count}", 300) #5 minutes

    puts "### [Error] OpenCTI returned [#{response}]"
    return nil
end

def get_tlp(arr)
    if arr.nil?
        return
    end

    arr.each do |obj|
        tag = obj['name']

        if m = tag.match(/^tlp:(.+?)$/)
            tlp, rests = m.captures
            return tlp
        end
    end

    return ''
end

def get_threat_level(level)
    level_map = {
        "1" => "High",
        "2" => "Medium",
        "3" => "Low",
        "4" => "Undefined",
    }

    txt = level_map[level]
    if txt.nil?
        txt = "==unknown=="
    end

    return txt
end

def determine_threat_level(event, misp_arr, fldname)
    flags_arr = []
    tlid_arr = []

    misp_arr.each do |field|
        tlid = event.get("#{field}_tlid")
        is_alert_by_misp = event.get(field)

        if (is_alert_by_misp == "true")
            flags_arr.push(field)
            tlid_arr.push(tlid)
        end
    end

    alert_by_misp = 'false'
    if (flags_arr.count > 0)
        alert_by_misp = 'true'
    end
    event.set(fldname, alert_by_misp)

    levels = ['High', 'Medium', 'Low', 'Undefined']
    event.set("#{fldname}_tlid", '==unknown==')

    levels.each do |level|
        if (tlid_arr.include?(level))
            event.set("#{fldname}_tlid", level)
            break
        end
    end
end

def populate_misp_cluster(label, event, arr)
    if arr.nil?
        return
    end

    targetIndistries = []
    targetCountries = []
    sourceCountries = []
    malwareFamilies = []
    attackPatterns = []
    threatActors = []

    arr.each do |obj|
        tag = obj['name']

        if m = tag.match(/^mandiant:target_industry:(.*)$/)
            targetIndustry, rests = m.captures
            targetIndistries.push(targetIndustry)
        elsif m = tag.match(/^mandiant:target_country:(.*)$/)
            targetCountry, rests = m.captures
            targetCountries.push(targetCountry)
        elsif m = tag.match(/^mandiant:source_country:(.*)$/)
            sourceCountry, rests = m.captures
            sourceCountries.push(sourceCountry)
        elsif m = tag.match(/^misp-galaxy:mandiant-malware-family=\"(.*)\"$/)
            malwareFamily, rests = m.captures
            malwareFamilyName = @malware_families[malwareFamily]
            malwareFamilies.push(malwareFamilyName)
        elsif m = tag.match(/^misp-galaxy:mitre-attack-pattern=\"(.*) - (.*)\"$/)
            attackPattern, attackPatternId = m.captures
            attackPatterns.push(attackPatternId)
        elsif m = tag.match(/^misp-galaxy:mandiant-threat-actor=\"(.*)\"$/)
            threatActor, rests = m.captures
            threatActors.push(threatActor)
        end
    end

    event.set("#{label}_mitre_attack_pattern", attackPatterns.join(","))
    event.set("#{label}_mandiant_malware_family", malwareFamilies.join(","))
    event.set("#{label}_source_country", sourceCountries.join(","))
    event.set("#{label}_target_country", targetCountries.join(","))
    event.set("#{label}_target_industry", targetIndistries.join(","))
    event.set("#{label}_mandiant_threat_actor", threatActors.join(","))
end

def load_misp_cahce(event, cache, value_field, attribute, label)
    value = event.get(value_field)

    if value.nil? or value == ''
        #puts "Nothing to do because the field [#{value_field}] is blank [#{value}]"
        return
    end

    hit = event.get('cti_cache_hit_cnt')
    miss = event.get('cti_cache_miss_cnt')

    key = "cti:#{value_field}:#{attribute}:#{value}"
    misp_data = cache.get(key)
    if misp_data        
        event.set('cti_cache_hit_cnt', hit+1)
    else
        event.set('cti_cache_miss_cnt', miss+1)

        misp_data = get_misp_response(event, cache, attribute, value)

        if !misp_data.nil?
            # Response with status code 200
            cache.set(key, misp_data, 3600) #60 minutes expiration
        end
    end

    misp_alert = 'unknown'
    if !misp_data.nil?
        #TODO : We may keep CSV in Memcache instead of JSON to improve performance
        obj = JSON.parse(misp_data)
        attributes = obj['response']['Attribute']
        
        misp_alert = 'false'
        if (attributes.count > 0)
            misp_alert = 'true'

            evt = attributes[0]
            event.set("#{label}_category", evt['category'])
            event.set("#{label}_info", populate_misp_info(evt['Event']['info']))
            event.set("#{label}_tlid", get_threat_level(evt['Event']['threat_level_id']))
            event.set("#{label}_tlp", get_tlp(evt['Event']['Tag']))

            populate_misp_cluster(label, event, evt['Event']['Tag'])
        end

        event.set(label, misp_alert)
    end

    return [event]
end

def populate_misp_info(info)

    if m = info.match(/^(.*) - (.*) \((.+)\)$/)
        desc, code, id = m.captures
        return code
    end

    return info
end

def populate_category(event)
    log_group = ''
    category = ''
    delimit = ''

    line = event.get('message')
    if m = line.match(/^.+,....\/..\/..\s..:..:..,(.+?),(TRAFFIC|SYSTEM|THREAT),.*$/)
        dummy, fw_type = m.captures
        fw_type = fw_type.downcase!
        category = "syslog_fw_#{fw_type}"
        delimit = 'comma'
        log_group = 'syslog'
    elsif m = line.match(/^(.+?)\s(.+?)\s(.+?)\s(linux_.*?)\s(.+?)\s(.+?)\s(.+?)\s(.+?)$/)
        sev, ts, host, audit_type, rests = m.captures
        log_group = 'syslog'
        category = audit_type
        event.set('ads_host', host)
    elsif m = line.match(/^snort(.+)$/)
        category = 'snort'
        log_group = 'snort'
        delimit = 'tab'
    elsif m = line.match(/^suricata_log(.+)$/)
        category = 'snort'
        log_group = 'snort'
        delimit = 'tab'
    elsif m = line.match(/^.*(zeek_.+?)\[\-\]\:\s(.+?)\|.+$/)
        category, actual_event_epoch = m.captures
        log_group = 'zeek'
        delimit = 'pipe'
        #event.set('ads_actual_event_epoch', actual_event_epoch)

        if s = actual_event_epoch.match(/^(.+)\.(.+)$/)
            epoch, dummy = s.captures
            #event.set('ads_actual_event_epoch_dtm', epoch)
            begin
                act = DateTime.strptime("#{epoch}", '%s')
                #dtm = Time.at(epoch.to_i).to_datetime
                #puts("DEBUG8 - [#{act}] [#{dtm}]")

                event.set('ads_actual_event_date', act.to_s)
            rescue StandardError, AnotherError => e
                puts("ERROR8 - Rescue [#{epoch}] #{e.inspect}")
            end
        end
    elsif m = line.match(/^CEF\:.+\|(.+?)\|.+?\|.+?\|.+?\|(.+?)\|(.+?)\|(.+?)$/)
        # NDR
        ndr_vendor, ndr_name, ndr_severity, tmp_ndr_data = m.captures
        log_group = 'ndr'
        delimit = 'cef'
        category = "ndr_#{ndr_vendor.downcase}"
        event.set('tmp_ndr_data', tmp_ndr_data)
        event.set('ndr_severity', ndr_severity)
        event.set('ndr_name', ndr_name)
    elsif m = line.match(/^.+SyslogAlertForwarder:\s.+_/)
        category = 'ips_trellix'
        log_group = 'ips'
        delimit = 'ips_trellix'
    elsif m = line.match(/^.+EPO EPOEvents - EventFwd\s\[/)
        category = 'epo_trellix'
        log_group = 'epo'
        delimit = 'epo_xml'
    elsif m = line.match(/^.+\sossec:\s.+$/)
        category = 'xdr_wazuh'
        log_group = 'xdr'
        delimit = 'wazuh'
    else
        category = '==unknown=='
        log_group = '=unknown='
    end

    event.set('ads_category', category)
    event.set('ads_delimit', delimit)
    event.set('ads_log_group', log_group)

    begin
        ts = event.get('@timestamp') # ts --> 2024-01-24T23:08:38.575Z

        event.set('@ads_actual_received_date1', LogStash::Timestamp.parse_iso8601(ts.to_s))

        epoch_ts = DateTime.parse(ts.to_s).to_time.to_i
        act = DateTime.strptime("#{epoch_ts}", '%s')
        event.set('@ads_actual_received_date2', act.to_s)

        #event.set('ads_actual_received_date1_org', "#{ts.to_s}") # for debugging
    rescue StandardError, AnotherError => e
        puts("ERROR97 - Rescue #{e.inspect}")
    end
end

def populate_log_source(event)
    ads_log_source = event.get('logsource')
    if ads_log_source.nil? or ads_log_source == ''
        ads_log_source = '==unknown=='
    end
    event.set('ads_log_source', ads_log_source)
end

def dump_fields_map(event)
    puts("DEBUG0 : Dumping...")
    @record_def.each do |category, fields_map|
        fields_map.each do |field, index|
            puts("DEBUG1 : #{category}:#{field}->#{index}")
        end
    end
end

def is_ip?(ip)
    !!IPAddr.new(ip) rescue false
end

def populate_zone(event, from_field_name, to_field_name)

    ip = event.get(from_field_name)
    if ip.nil? or ip == ''
        return
    end

    if !is_ip?(ip)
        event.set('ads_debug', 'Not valid IP address')
        return
    end

    @cidr_map.each do |cidr, department|
        net1 = IPAddr.new(cidr)
        net2 = IPAddr.new(ip)

        if (net1.include?(net2))
            event.set(to_field_name, department)
            return
        end
    end

    event.set(to_field_name, '==unknown==')    
end

def check_blacklist_ip(event, from_field_name, to_field_name)

    is_blacklist = 'false'

    ip = event.get(from_field_name)
    if ip.nil? or ip == ''
        event.set(to_field_name, 'empty')
        return
    end

    if !is_ip?(ip)
        event.set('ads_debug', 'Not valid IP address')
        event.set(to_field_name, 'bad-dstip')
        return
    end

    if @blacklist_ip_map.has_key?(ip)
        is_blacklist = 'true'
    end

    event.set(to_field_name, is_blacklist)
end

def populate_direction(event)
    src_country = event.get('ads_country_src')
    dst_country = event.get('ads_country_dst')

    if src_country.nil? or src_country == ''
        src_country = '-'
    end

    if dst_country.nil? or dst_country == ''
        dst_country = '-'
    end

    if src_country == '-' and dst_country == '-'
        direction = 'internal-to-internal'
    elsif src_country != '-' and dst_country == '-'
        direction = 'external-to-internal'
    elsif src_country == '-' and dst_country != '-'
        direction = 'internal-to-external'
    elsif src_country != '-' and dst_country != '-'
        direction = 'external-to-external'
    end

    event.set('ads_traffic_direction', direction)
end

def parse_fields(event)
    line = event.get('message')

    category = event.get('ads_category')
    delimit = event.get('ads_delimit')
    if (delimit == 'pipe')
        tokens = line.split('|') #line.split(/\t/)
    elsif (delimit == 'comma')
        tokens = CSV.parse_line(line, liberal_parsing: true)
    end

    fields_map = @record_def[category]

    if (line.match(/^#.*$/))
        event.set('ads_debug', 'This is comment line')
    elsif !fields_map.nil?
        fields_map.each do |field, index|
            idx = index.to_i
            value = tokens[idx]
            if !value.nil?
                event.set(field, value)
            else
                #puts("Error - Field index [#{idx}], delimit by [#{delimit}] not found in category [#{category}]")
                event.set('ads_debug', 'Index not found')
            end
        end
    elsif (category == "snort")
        extract_snort(event, line)
    elsif (category == "ndr_extrahop")
        extract_cef_format(event, line)
    elsif (category == "ips_trellix")
        extract_ips_trellix(event, line)
    elsif (category == "epo_trellix")
        extract_epo_trellix(event, line)
    else
        #puts("Error - Category [#{category}] not found in fields-map.cfg")
        event.set('ads_debug', 'Unable to map fields')
    end

    if (category == "zeek_http")
        host = event.get('ads_host')
        path = event.get('ads_url_path')
        event.set('ads_url', "#{host}#{path}")
    end
end

def extract_ips_trellix(event, message)
    # <114>Oct 17 16:21:24 SyslogAlertForwarder: MIS_IPS9100 detected Outbound attack Malware: Gamarue Malware Traffic Detected (severity = High). 147.75.61.38:80 -> 10.104.227.10:54081 (result = Attack Blocked)
    if match = message.match(/^.+SyslogAlertForwarder:\s(.+?)\s(.+)\:\s(.+)\s\(severity\s=\s(.+?)\)\.\s(.+?):(.+?)\s->\s(.+?):(.+?)\s\(result\s=\s(.+?)\)$/i)
        rule_id, dummy, rule_name, priority, dst_ip, dst_port, src_ip, src_port, status = match.captures

        event.set('ads_src_ip', src_ip.strip)
        event.set('ads_src_port', src_port.strip)
        event.set('ads_dst_ip', dst_ip.strip)
        event.set('ads_dst_port', dst_port.strip)
        event.set('ads_priority', priority.strip)
        event.set('ads_rulename', rule_name.strip)
        event.set('ads_rule_id', rule_id.strip)
        event.set('ads_status', status.strip)
    end
end

def extract_epo_trellix(event, message)
    # <29>1 2023-11-23T04:02:08.0Z EPO EPOEvents - EventFwd [.+] <XML here>
    if match = message.match(/^.+EventFwd\s\[(.+)\]\s(.+)/i)
        meta_data, xml_data = match.captures

        xml_doc  = Nokogiri::XML(xml_data)
        root = xml_doc.root

        fields_map = {
            'ads_src_ip' => '//MachineInfo/IPAddress/text()',
            'ads_src_mac' => '//MachineInfo/RawMACAddress/text()',
            'ads_user' => '//MachineInfo/UserName/text()',
            'ads_host' => '//SoftwareInfo/Event/CommonFields/SourceHostName/text()',
            'ads_event_desc' => '//SoftwareInfo/Event/CustomFields/NaturalLangDescription/text()',
            'ads_epo_first_action_status' => '//SoftwareInfo/Event/CustomFields/FirstActionStatus/text()',
            'ads_epo_second_action_status' => '//SoftwareInfo/Event/CustomFields/SecondActionStatus/text()',
            'ads_epo_first_attempt_action' => '//SoftwareInfo/Event/CustomFields/FirstAttemptedAction/text()',
            'ads_epo_second_attempt_action' => '//SoftwareInfo/Event/CustomFields/SecondAttemptedAction/text()',
            'ads_epo_target_hash' => '//SoftwareInfo/Event/CustomFields/TargetHash/text()',
            'ads_epo_target_file_name' => '//SoftwareInfo/Event/CommonFields/TargetFileName/text()',
            'ads_epo_detection_method' => '//SoftwareInfo/CommonFields/AnalyzerDetectionMethod/text()',
            'ads_epo_threat_category' => '//SoftwareInfo/Event/CommonFields/ThreatCategory/text()',
            'ads_epo_threat_handled' => '//SoftwareInfo/Event/CommonFields/ThreatHandled/text()',
            'ads_epo_threat_type' => '//SoftwareInfo/Event/CommonFields/ThreatType/text()',
            'ads_epo_machine_name' => '//MachineInfo/MachineName/text()',
            'ads_epo_target_user_name' => '//SoftwareInfo/Event/CommonFields/TargetUserName/text()',
            'ads_epo_threat_action_taken' => '//SoftwareInfo/Event/CommonFields/ThreatActionTaken/text()',
            'ads_epo_source_process_name' => '//SoftwareInfo/Event/CommonFields/SourceProcessName/text()',
            'ads_epo_threat_name' => '//SoftwareInfo/Event/CommonFields/ThreatName/text()',
        }

        fields_map.each do |field_name, xpath|
            #puts("#### DEBUG-EPO-3 **** [#{field_name}] [#{xpath}] **** ####")

            value = root.xpath(xpath)
            data = "#{value}" # Convert to string
            event.set(field_name, data)
        end
    end
end

def extract_cef_format(event, message)
    #msgs = ndr_data.scan(/msg=.+$/) # Might be used in the future

    data = event.get('tmp_ndr_data')
    tmp_ndr_data = data.gsub(/msg=.+$/, "")

    flds = tmp_ndr_data.scan(/\S+?=\S+/)
    flds.each do |token|
        if m = token.match(/^(\S+?)=(\S+)$/)
            key, value = m.captures

            if (key == 'msg')
                next
            end

            begin
                event.set("ndr_#{key}", value.strip)
            rescue
                # Do nothing
            end
        end
    end

    event.remove('tmp_ndr_data')
end

def extract_snort(event, message)
    if match = message.match(/^.+?\s\[.+:.+:.+\] (.+?) \[Classification: (.+?)\] \[Priority: (.+?)\] \{(.+)\} (.+):(.+) -> (.+):(.+)$/i)
        rule_name, classification, priority, protocol, src_ip, src_port, dst_ip, dst_port = match.captures

        rule_name = rule_name.gsub('[**]', '')

        event.set('ads_classification', classification.strip)
        event.set('ads_src_ip', src_ip.strip)
        event.set('ads_src_port', src_port.strip)
        event.set('ads_dst_ip', dst_ip.strip)
        event.set('ads_dst_port', dst_port.strip)
        event.set('ads_L3_protocol', protocol.strip)
        event.set('ads_priority', priority.strip)
        event.set('ads_rulename', rule_name.strip)

        txt = @priority_map[priority.strip]
        if txt.nil?
            txt = "==unknown=="
        end
        event.set('ads_priority_txt', txt)

        # For Community-ID

        # Retreive the fields
        src_ip = event.get('ads_src_ip')
        src_p = event.get('ads_src_port').to_i
        dst_ip = event.get('ads_dst_ip')
        dst_p = event.get('ads_dst_port').to_i
        protocol = event.get('ads_L3_protocol')

        # Parse to sockaddr_in struct bytestring
        src = Socket.sockaddr_in(src_p, src_ip)
        dst = Socket.sockaddr_in(dst_p, dst_ip)

        is_one_way = false
        # Special case handling for ICMP type/codes
        if protocol == 'icmp' || protocol == 'icmp6'
            if src.length == 16 # IPv4
                if ICMP4_MAP.has_key?(src_p) == false
                    is_one_way = true
                end
            elsif src.length == 28 # IPv6
                if ICMP6_MAP.has_key?(src_p) == false
                    is_one_way = true
                end
                # Set this correctly if not already set
                protocol = 'icmp6'
            end
        end

        # Fetch the protocol number
        proto = PROTO_MAP.fetch(protocol.downcase, 0)

        # Parse out the network-ordered bytestrings for ip/ports
        if src.length == 16 # IPv4
            sip = src[4,4]
            sport = src[2,2]
        elsif src.length == 28 # IPv6
            sip = src[4,16]
            sport = src[2,2]
        end

        if dst.length == 16 # IPv4
            dip = dst[4,4]
            dport = dst[2,2]
        elsif dst.length == 28 # IPv6
            dip = dst[4,16]
            dport = dst[2,2]
        end

        if !( is_one_way || ((sip <=> dip) == -1) || ((sip == dip) && ((sport <=> dport) < 1)) )
            mip = sip
            mport = sport
            sip = dip
            sport = dport
            dip = mip
            dport = mport
        end

        # Hash all the things
        hash = Digest::SHA1.new
        hash.update([@comm_id_seed].pack('n')) # 2-byte seed

        hash.update(sip)  # 4 bytes (v4 addr) or 16 bytes (v6 addr)
        hash.update(dip)  # 4 bytes (v4 addr) or 16 bytes (v6 addr)

        hash.update([proto].pack('C')) # 1 byte for transport proto
        hash.update([0].pack('C')) # 1 byte padding

        # If transport protocol, hash the ports too
        hash.update(sport) # 2 bytes for port
        hash.update(dport) # 2 bytes for port

        comm_id = nil

        if @use_base64
            comm_id = VERSION + Base64.strict_encode64(hash.digest)
        else
            comm_id = VERSION + hash.hexdigest
        end

        event.set('ads_community_key', comm_id)
        # ###
    end
end

def calculate_delay_category(event)
    arrived_dtm = event.get('ts_arrived_kafka')
    picked_dtm = event.get('ts_picked_from_kafka')

    sec_diff = picked_dtm - arrived_dtm

    delay_bucket = ""
    if (sec_diff <= 10)
        delay_bucket = "<10s"
    elsif ((sec_diff > 10) && (sec_diff <= 30))
        delay_bucket = "10s-30s"
        event.set('is_delayed_log', 'true')
    elsif ((sec_diff > 30) && (sec_diff <= 60))
        delay_bucket = "30s-60s"
        event.set('is_delayed_log', 'true')
    elsif (sec_diff > 60)
        delay_bucket = ">60s"
        event.set('is_delayed_log', 'true')
    end
    event.set('ads_delay_bucket', delay_bucket)
end

def add_alert_metadata(event)
    meta_fields = [
        'ads_alert_by_dstip', 
        'ads_alert_by_srcip',
        'ads_alert_by_domain'
    ]

    arr = []
    meta_fields.each do |field|
        flag = event.get(field)
        if (flag == 'true')
            fn = "#{field}_info"
            fv = event.get(fn)
            kv = "[#{fn} => #{fv}]"
            arr.push(kv)
        end
    end

    if (arr.count > 0)
        metadata = arr.join(",")
        msg = event.get('message')
        event.set('message', "#{msg}\n\e[31m#{metadata}\e[0m")
    end
end

def populate_ts_aggregate(event)
    dtm = DateTime.now
    dtm += Rational('7/24') # Thailand timezone +7

    event.set('ads_ts_yyyy', dtm.year)
    event.set('ads_ts_mm', dtm.mon.to_s.rjust(2,'0'))
    event.set('ads_ts_dd', dtm.mday.to_s.rjust(2,'0'))
    event.set('ads_ts_hh', dtm.hour.to_s.rjust(2,'0'))
    event.set('ads_ts_wd', dtm.wday.to_s.rjust(2,'0'))
end

def populate_ml_labels(event)
    #### ads_ml_suspecious_dst_country ####
    valid_dst_country = ['TH', 'United States', 'Thailand', 'US', 'China', 'Japan', 'AT', 'United Kingdom']

    dst_coutry = event.get('ads_country_dst')
    dst_coutry_valid = event.get('ads_country_dst_valid')

    susp_dst_country = 'false'
    if (dst_coutry_valid == 'true')
        if (valid_dst_country.include?(dst_coutry))
            susp_dst_country = 'false'
        else
            susp_dst_country = 'true'
        end
    end
    event.set('ads_ml_label_susp_dst_country', susp_dst_country)

    #### ads_ml_suspecious_time ####
    hh = event.get('ads_ts_hh')
    wd = event.get('ads_ts_wd')

    suspecious_time = 'false'

    weekends_wd = ['06', '00'] # Saturday & Sunday
    workings_hh = ['00', '01', '02', '03', '04', '05', '20', '21', '22', '23'] # hours 00-23
    if (weekends_wd.include?(wd) && workings_hh.include?(hh))
        suspecious_time = 'true'
    end
    event.set('ads_ml_label_susp_time', suspecious_time)
end

def populate_original_ip(event)
    src_ip = event.get('ads_src_ip')
    dst_ip = event.get('ads_dst_ip')

    if src_ip.nil? or src_ip == ''
        return
    end

    if dst_ip.nil? or dst_ip == ''
        return
    end

    # This new fields will be mapped to IP type instead of string
    if is_ip?(src_ip)
        event.set('ads_ip_src', src_ip)
    end

    if is_ip?(dst_ip)
        event.set('ads_ip_dst', dst_ip)
    end
end

def final_manipulate(event)
    category = event.get('ads_category')

    if category == 'syslog_fw_threat'
        field = 'ads_classification'
        classification = event.get(field)

        if classification == '(9999)'
            new_value = 'URL Filtering(9999)'
            event.set(field, new_value)
        end
    end
end

def populate_brute_force(event, cache)
    category = event.get('ads_category')
    obj = @brute_force_map[category]

    if obj.nil?
        return
    end

    uf = obj['user_field']
    sf = obj['status_field']
    fv = obj['fail_value']
    ts = obj['threshold']

    status = event.get(sf)
    if (status != fv)
        return
    end

    #Failed login here
    user = event.get(uf)
    key = "bruteforce:#{category}:#{user}"    

    failed_count = 0
    fc = cache.get(key)

    if fc
        failed_count = fc.to_i + 1
    else
        failed_count = 1
    end

    #puts "### DEBUG - found failed login [#{key}] count=[#{failed_count}] threshold=[#{ts}] fc=[#{fc}]"

    if (failed_count >= ts.to_i)
        event.set('ads_bruteforce', 'true')
    end

    cache.set(key, "#{failed_count}", 60) #Check failed login without 60 seconds
end

def generate_fields(event)
    fields = []
    event.to_hash.each do |key, value|
        if key.match(/^ads_.*$/)
            fields.push(key)
        elsif key.match(/^ndr_.*$/)
            fields.push(key)
        end
    end

    sorted_fields = fields.sort
    return sorted_fields
end

def create_metric(event)
    sorted_fields = generate_fields(event)

    obj = Hash.new()
    #obj["last_update_date"] = event.get('@timestamp') # Not necessary needed
    obj["@timestamp"] = event.get('@timestamp')
    obj["id"] = SecureRandom.uuid # Maybe needed in the future to link back to Loki
    obj["pod_name_loki"] = event.get('pod_name_loki')
    obj["pod_name_syslog"] = event.get('pod_name_syslog')
    obj["cti_cache_hit_cnt"] = event.get('cti_cache_hit_cnt')
    obj["cti_cache_miss_cnt"] = event.get('cti_cache_miss_cnt')
    obj["ts_arrived_kafka"] = event.get('ts_arrived_kafka')
    obj["ts_picked_from_kafka"] = event.get('ts_picked_from_kafka')
    obj["ts_arrived_syslog"] = event.get('ts_arrived_syslog')
    obj["ts_left_syslog"] = event.get('ts_left_syslog')

    #sorted_fields.each do |field|
    #    value = event.get(field).to_s
    #    obj[field] = value.strip
    #end

    event.set("mt", obj)
end

def validate_country_code(event, country_code)
    cc = event.get(country_code)

    if cc.nil?
        return
    end

    is_valid = 'false'
    if cc.match(/^[a-zA-Z\s]+$/)
        is_valid = 'true'
    end

    if (is_valid == 'false')
        event.set(country_code, 'Thailand') # For ML
    end

    event.set("#{country_code}_valid", is_valid)
end

def validate_host(event, host_field)
    cc = event.get(host_field)

    if cc.nil?
        return
    end

    is_valid = 'true'
    if cc.match(/^\-+$/)
        is_valid = 'false'
    end

    event.set("#{host_field}_valid", is_valid)
end

def validate_protocol(event, field)
    cc = event.get(field)

    if cc.nil?
        return
    end

    is_valid = 'true'
    if (cc == '-')
        is_valid = 'false'
    end

    event.set("#{field}_valid", is_valid)
end

def parse_ml_prediction(event, data)
    field_map = {
        "supervised_dst_country_anomaly"    => ["ads_ml_predicted_susp_dst_country", "disable_predict_supervised_dest_country"],
        "supervised_login_anomaly"          => ["ads_ml_predicted_susp_time", "disable_predict_supervised_time"],
        "unsupervised_dst_country_anomaly" => ["ads_ml_anomaly_susp_dst_country", "disable_predict_anomaly_dest_country"],
        "unsupervised_login_anomaly"       => ["ads_ml_anomaly_susp_time", "disable_predict_anomaly_time"],
    }

    obj = JSON.parse(data)
    results = obj['results']

    #puts("#### DEBUG-1.1 parse ML response #####")

    results.each do |result|
        subject = result['subject']
        predicted_value = result['result']

        event_ml_field = ''
        ml_responsed_field_arr = field_map[subject]

        if (!ml_responsed_field_arr.nil?)
            event_ml_field = ml_responsed_field_arr[0]
            ml_input_param = ml_responsed_field_arr[1]
        end

        if (!event_ml_field.nil? and event_ml_field != '')
            event.set(event_ml_field, predicted_value)

            cache_key = get_ml_cache_key(event, ml_input_param)
            @mc.set(cache_key, "#{predicted_value}", 1200) # 5 minutes

            #puts("#### DEBUG-1.2 set cache key=[#{cache_key}] value=[#{predicted_value}] #####")
        end
    end
end

def get_ml_cache_key(event, ml_input_param)
    cache_key = "not_defined"

    if (ml_input_param == 'disable_predict_supervised_dest_country')
        dst_country = event.get('ads_country_dst')
        dst_port = event.get('ads_dst_port')
        cache_key = "ml.#{ml_input_param}.#{dst_country}.#{dst_port}" 
    elsif (ml_input_param == 'disable_predict_supervised_time')
        wd = event.get('ads_ts_wd')
        hh = event.get('ads_ts_hh')
        cache_key = "ml.#{ml_input_param}.#{wd}.#{hh}" 
    elsif (ml_input_param == 'disable_predict_anomaly_dest_country')
        dst_country = event.get('ads_country_dst')
        dst_port = event.get('ads_dst_port')
        cache_key = "ml.#{ml_input_param}.#{dst_country}.#{dst_port}" 
    elsif (ml_input_param == 'disable_predict_anomaly_time')
        wd = event.get('ads_ts_wd')
        hh = event.get('ads_ts_hh')
        cache_key = "ml.#{ml_input_param}.#{wd}.#{hh}" 
    end

    return cache_key
end

def get_ml_prediction(event, cache, cache_key)
    category = event.get('ads_category');

    ml_control_fields = {
        "disable_predict_anomaly_dest_country"    => ["zeek_conn|syslog_fw_threat", "ads_ml_anomaly_susp_dst_country"],
        "disable_predict_anomaly_time"            => ["zeek_radius", "ads_ml_anomaly_susp_time"],
        #"disable_predict_supervised_dest_country" => ["zeek_conn|syslog_fw_threat", "ads_ml_predicted_susp_dst_country"],
        #"disable_predict_supervised_time"         => ["zeek_radius", "ads_ml_predicted_susp_time"],
    }

    cache_keys = []
    cnt = 0
    ml_control_fields.each do |param, selected_category_arr|
        selected_category = selected_category_arr[0]
        ads_ml_result_field = selected_category_arr[1]

        if (selected_category.include?(category))
            cache_key_ml = get_ml_cache_key(event, param)
            cache_value_ml = @mc.get(cache_key_ml)

            if cache_value_ml
                # ML API will skip this query, then use the result from cache
                #puts("#### DEBUG-2.1 found in cache key=[#{cache_key_ml}] value=[#{cache_value_ml}] against [#{ads_ml_result_field}] #####")

                event.set(param, 'true')
                event.set(ads_ml_result_field, cache_value_ml)
            else
                #puts("#### DEBUG-2.2 not found in cache key=[#{cache_key_ml}] against [#{ads_ml_result_field}] #####")
                # Not in cache or expired
                cnt = cnt + 1
                event.set(param, 'false')
                cache_keys.push(cache_key_ml)
            end
        end
    end

    if (cnt <= 0)
        return
    end

    uri = URI.parse('http://10.141.98.148:31000/v5/gateway') #Use IP, no need to increase load to DNS server
    #api_key = 'noneed' 

    https = Net::HTTP.new(uri.host, uri.port)
    https.use_ssl = false #true
    https.verify_mode = OpenSSL::SSL::VERIFY_NONE
    https.read_timeout = 0.5
    https.open_timeout = 0.5
    https.max_retries = 0

    request = Net::HTTP::Post.new(uri.path)
    request['Accept'] = 'application/json'
    request['Content-Type'] = 'application/json'
    #request['Authorization'] = api_key

    request.body = event.to_json

    if (cnt > 0)
        #puts("#### DEBUG3 #{event.to_json} #####")
        # No need to preserve these temp fields
        ml_control_fields.each do |param, selected_category|
            event.remove(param)
        end
    end

    status = ''
    begin
        response = https.request(request)
    rescue TimeoutError
        status = 'ml-timeout'
    else
        #No error
        status = response.code
    end
    event.set('ads_ml_status', "#{status}")

    if (status == "200")
        #parse body to get prediction result here
        parse_ml_prediction(event, response.body) #body
        return response.body
    end

    cache_key_ml_debug = cache_keys.join(",")
    puts "### [Error] [#{cache_key_ml_debug}] ML returned status=[#{status}] [#{response}]"
    return nil
end

def populate_device_type(event)
    log_source = event.get('ads_log_source')
    category = event.get('ads_category')

    device_type = "==unknown=="

    if (log_source == 'PA-3260-NODE0')
        device_type = 'firewall_internet1'
    elsif (log_source == 'PA-3060-NODE1')
        device_type = 'firewall_internet2'
    elsif (log_source == 'PA-3260_Server02')
        device_type = 'firewall_server'
    elsif (log_source == 'PA-3060-DR')
        device_type = 'firewall_dr'
    elsif (log_source == 'RTARF-EDA6100v')
        device_type = 'ndr'
    elsif (log_source.match(/netapprove|ids/))
        device_type = 'tap'
    elsif (category == 'ips_trellix')
        device_type = 'ips'
    elsif (category == 'epo_trellix')
        device_type = 'epo'
    elsif (category == 'syslog_fw_threat')
        device_type = 'firewall_mta'
    elsif (category == 'xdr_wazuh')
        device_type = 'xdr'
    end

    event.set('ads_device_type', device_type)
end

def filter(event)

    destination = event.get('destination')
    if (destination == 'kafka')
        event.set('cti_cache_hit_cnt', 0)
        event.set('cti_cache_miss_cnt', 0)

        event.set('ts_arrived_kafka', Time.now.to_i)
        event.set('ts_arrived_syslog', Time.now.to_i)
        event.set('pod_name_syslog', ENV["POD_NAME"])

        populate_category(event)
        populate_log_source(event)
        populate_device_type(event)

        #dump_fields_map(event)
        parse_fields(event)
        populate_zone(event, 'ads_src_ip', 'ads_src_zone')
        populate_zone(event, 'ads_dst_ip', 'ads_dst_zone')

        populate_direction(event)
        populate_brute_force(event, @mc)

        check_blacklist_ip(event, 'ads_dst_ip', 'ads_alert_by_blacklist_dstip')
        check_blacklist_ip(event, 'ads_src_ip', 'ads_alert_by_blacklist_srcip')

        validate_country_code(event, 'ads_country_src')
        validate_country_code(event, 'ads_country_dst')
        validate_protocol(event, 'ads_L7_protocol')
        validate_host(event, 'ads_host')

        #load_misp_cahce(event, @mc, 'ads_dst_ip', 'ip-dst', 'ads_alert_by_dstip')
        #load_misp_cahce(event, @mc, 'ads_src_ip', 'ip-src', 'ads_alert_by_srcip')
        #load_misp_cahce(event, @mc, 'ads_host', 'domain', 'ads_alert_by_domain')
        #load_misp_cahce(event, @mc, 'ads_url', 'url', 'ads_alert_by_url')
        #load_misp_cahce(event, @mc, 'ads_sha256', 'sha256', 'ads_alert_by_sha256_1')
        #load_misp_cahce(event, @mc, 'ads_sha256', 'filename|sha256', 'ads_alert_by_sha256_2')

        misp_arr = ['ads_alert_by_dstip', 'ads_alert_by_srcip', 'ads_alert_by_domain']
        #determine_threat_level(event, misp_arr, 'ads_alert_by_misp')

        event.set('ts_left_syslog', Time.now.to_i)
        populate_ts_aggregate(event)

        #populate_ml_labels(event)
        #get_ml_prediction(event, @mc, 'ml-error-cnt') # Will use it later

        populate_original_ip(event)
        #validate_sigma_rules_phase1(event, @blacklist_map)

        final_manipulate(event)
#    elsif (destination == 'loki')
#        category = event.get('ads_category')
#        if (category == 'syslog_fw_traffic')
#            # Try to exclude it for now
#            return []
#        end

#        event.set('ts_picked_from_kafka', Time.now.to_i)
#        event.set('pod_name_loki', ENV["POD_NAME"])
#        event.set('@timestamp', LogStash::Timestamp.now)

#        calculate_delay_category(event)
        #add_alert_metadata(event)

#        validate_sigma_rules_phase2(event)
#        create_metric(event)
    elsif (destination == 'elasticsearch')
        # This is the one for new ES cluster, select just only some categories
        # to make ES works not too hard

        category = event.get('ads_category')
        if (category == 'syslog_fw_traffic') #if (category != 'syslog_fw_threat')
            # Try to exclude it for now
            return []
        end

        event.set('ts_picked_from_kafka', Time.now.to_i)
        event.set('pod_name_loki', ENV["POD_NAME"])
        event.set('@timestamp', LogStash::Timestamp.now)

        calculate_delay_category(event)
        #add_alert_metadata(event)

        #validate_sigma_rules_phase2(event)
        create_metric(event)
    end

    return [event]
end
