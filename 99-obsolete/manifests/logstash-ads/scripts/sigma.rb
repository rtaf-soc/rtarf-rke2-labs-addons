require "json"

def validate_sigma_rules_phase1(event, blacklist_map)
    rules_executed = {}

    operation_log_unknown(event, rules_executed)

    zeek_dns_mining_pools(event, rules_executed)
    zeek_dns_torproxy(event, rules_executed)
    zeek_dns_nkn(event, rules_executed)
    zeek_susp_kerberos_rc4(event, rules_executed)
    zeek_smb_converted_win_transferring_files_with_credential_data(event, rules_executed)
    zeek_smb_converted_win_susp_raccess_sensitive_fext(event, rules_executed)
    zeek_smb_converted_win_susp_psexec(event, rules_executed)
    zeek_smb_converted_win_impacket_secretdump(event, rules_executed)
    zeek_smb_converted_win_atsvc_task(event, rules_executed)
    zeek_dce_rpc_smb_spoolss_named_pipe(event, rules_executed)
    zeek_rdp_public_listener(event, rules_executed)
    zeek_http_webdav_put_request(event, rules_executed)
    zeek_http_omigod_no_auth_rce(event, rules_executed)
    zeek_http_executable_download_from_webdav(event, rules_executed)

    net_firewall_apt_equationgroup_c2(event, rules_executed)

    blacklist_by_src_ip(event, rules_executed)
    blacklist_by_dst_ip(event, rules_executed)
    blacklist_by_hash(event, rules_executed, blacklist_map['hash'])
    blacklist_by_url(event, rules_executed, blacklist_map['url'])
    blacklist_by_domain(event, rules_executed, blacklist_map['domain'])

    misp_ioc_by_dst_ip(event, rules_executed)
    misp_ioc_by_src_ip(event, rules_executed)
    misp_ioc_by_sha256(event, rules_executed)

    snort_priority_high_found(event, rules_executed)
    snort_malware_found(event, rules_executed)
    snort_exploit_found(event, rules_executed)
    cobalt_strike_command_and_control_beacon(event, rules_executed)

    rules = []
    rules_executed.to_hash.each do |key, value|
        if (value == 'true')
            #puts("DEBUG 1-2 SIGMA : #{key}")
            rules.push(key)
        end
    end

    rules_hit = rules.join('|')
    event.set("ads_rules_match", rules_hit)
end

def validate_sigma_rules_phase2(event)
    rules_executed = {}

    operation_log_delay_found_60s(event, rules_executed)

    rules = []
    rules_executed.to_hash.each do |key, value|
        if (value == 'true')
            #puts("DEBUG 2-2 SIGMA : #{key}")
            rules.push(key)
        end
    end

    arr1 = []
    rules_hit_p1 = event.get("ads_rules_match")

    if (!rules_hit_p1.nil? && rules_hit_p1 != '')
        arr1 = rules_hit_p1.split('|')
    end

    rules_hit = arr1 + rules
    event.set("ads_rules_match", rules_hit.join('|'))
end

##### Predicate Operator #####

def is_in_list_some(data, arr, option)
    arr.each do |item|
        if ((option == 'endswith') and data.end_with?(item))
            return true
        elsif ((option == 'startswith') and data.start_with?(item))
            return true
        elsif (data == item)
            return true
        end
    end

    return false
end

def is_in_list_all(data, arr, option)
    arr.each do |item|
        if ((option == 'contains') and !data.include?(item))
            return false
        end
    end

    return true
end

###### Operations ######

def operation_log_unknown(event, rules_executed)
    name = 'operation_log_unknown'
    rules_executed[name] = 'false'

    category = event.get('ads_category')
    if (category == '==unknown==')
        rules_executed[name] = 'true'

        #puts("DEBUG1 SIGMA : #{name}")
    end
end

def operation_log_delay_found_60s(event, rules_executed)
    name = 'operation_log_delay_found_60s'
    rules_executed[name] = 'false'

    bucket = event.get('ads_delay_bucket')
    if (bucket == '>60s')
        rules_executed[name] = 'true'

        #puts("DEBUG1 SIGMA : #{name}")
    end
end

##### Zeek DNS #####

def zeek_dns_torproxy(event, rules_executed)
    category = event.get('ads_category')
    if (category != 'zeek_dns')
        return
    end

    name = 'zeek_dns_torproxy'
    rules_executed[name] = 'false'

    dns = [
        'tor2web.org',
        'tor2web.com',
        'torlink.co',
        'onion.to',
        'onion.ink',
        'onion.cab',
        'onion.nu',
        'onion.link',
        'onion.it',
        'onion.city',
        'onion.direct',
        'onion.top',
        'onion.casa',
        'onion.plus',
        'onion.rip',
        'onion.dog',
        'tor2web.fi',
        'tor2web.blutmagie.de',
        'onion.sh',
        'onion.lu',
        'onion.pet',
        't2w.pw',
        'tor2web.ae.org',
        'tor2web.io',
        'tor2web.xyz',
        'onion.lt',
        's1.tor-gateways.de',
        's2.tor-gateways.de',
        's3.tor-gateways.de',
        's4.tor-gateways.de',
        's5.tor-gateways.de',
        'hiddenservice.net'
    ]

    query = event.get('ads_query')

    is_dns_in_list = is_in_list_some(query, dns, '')

    if (is_dns_in_list)
        rules_executed[name] = 'true'
    end
end

def zeek_dns_mining_pools(event, rules_executed)
    category = event.get('ads_category')
    if (category != 'zeek_dns')
        return
    end

    name = 'zeek_dns_mining_pools'
    rules_executed[name] = 'false'

    dns = [
        'monerohash.com',
        'do-dear.com',
        'xmrminerpro.com',
        'secumine.net',
        'xmrpool.com',
        'minexmr.org',
        'hashanywhere.com',
        'xmrget.com',
        'mininglottery.eu',
        'minergate.com',
        'moriaxmr.com',
        'multipooler.com',
        'moneropools.com',
        'xmrpool.eu',
        'coolmining.club',
        'supportxmr.com',
        'minexmr.com',
        'hashvault.pro',
        'xmrpool.net',
        'crypto-pool.fr',
        'xmr.pt',
        'miner.rocks',
        'walpool.com',
        'herominers.com',
        'gntl.co.uk',
        'semipool.com',
        'coinfoundry.org',
        'cryptoknight.cc',
        'fairhash.org',
        'baikalmine.com',
        'tubepool.xyz',
        'fairpool.xyz',
        'asiapool.io',
        'coinpoolit.webhop.me',
        'nanopool.org',
        'moneropool.com',
        'miner.center',
        'prohash.net',
        'poolto.be',
        'cryptoescrow.eu',
        'monerominers.net',
        'cryptonotepool.org',
        'extrmepool.org',
        'webcoin.me',
        'kippo.eu',
        'hashinvest.ws',
        'monero.farm',
        'linux-repository-updates.com',
        '1gh.com',
        'dwarfpool.com',
        'hash-to-coins.com',
        'pool-proxy.com',
        'hashfor.cash',
        'fairpool.cloud',
        'litecoinpool.org',
        'mineshaft.ml',
        'abcxyz.stream',
        'moneropool.ru',
        'cryptonotepool.org.uk',
        'extremepool.org',
        'extremehash.com',
        'hashinvest.net',
        'unipool.pro',
        'crypto-pools.org',
        'monero.net',
        'backup-pool.com',
        'mooo.com', # Dynamic DNS, may want to exclude
        'freeyy.me',
        'cryptonight.net',
        'shscrypto.net'
    ]

    answers = [
        '127.0.0.1',
        '0.0.0.0'
    ]

    query = event.get('ads_query')
    answer = event.get('ads_answer')

    is_dns_in_list = is_in_list_some(query, dns, 'endswith')
    is_answer_in_list = is_in_list_some(answer, answers, '')

    if (is_dns_in_list and !is_answer_in_list)
        rules_executed[name] = 'true'
    end
end

def zeek_dns_nkn(event, rules_executed)
    category = event.get('ads_category')
    if (category != 'zeek_dns')
        return
    end

    name = 'zeek_dns_nkn'
    rules_executed[name] = 'false'

    dns = [
        'seed',
        '.nkn.org'
    ]

    query = event.get('ads_query')

    is_dns_contains_all = is_in_list_all(query, dns, 'contains')

    if (is_dns_contains_all)
        rules_executed[name] = 'true'
    end
end

##### Zeek Kerberos #####

def zeek_susp_kerberos_rc4(event, rules_executed)
    category = event.get('ads_category')
    if (category != 'zeek_kerberos')
        return
    end

    name = 'zeek_susp_kerberos_rc4'
    rules_executed[name] = 'false'

    request_type = event.get('ads_request_type')
    cypher = event.get('ads_cypher')
    service = event.get('ads_service')

    if ((request_type == 'TGS') and (cypher == 'rc4-hmac') and !service.start_with?('$'))
        rules_executed[name] = 'true'
    end
end

##### Zeek SMB #####

def zeek_smb_converted_win_transferring_files_with_credential_data(event, rules_executed)
    category = event.get('ads_category')
    if (category != 'zeek_smb_files')
        return
    end

    name = 'zeek_smb_converted_win_transferring_files_with_credential_data'
    rules_executed[name] = 'false'

    names = [
        '\\mimidrv',
        '\\lsass',
        '\\hiberfil',
        '\\sqldmpr',
        '\\sam',
        '\\ntds.dit',
        '\\security',
        '\\windows\\minidump\\'
    ]

    filename = event.get('ads_name')

    is_name_in_list = is_in_list_some(filename, names, '')

    if (is_name_in_list)
        rules_executed[name] = 'true'
    end
end

def zeek_smb_converted_win_susp_raccess_sensitive_fext(event, rules_executed)
    category = event.get('ads_category')
    if (category != 'zeek_smb_files')
        return
    end

    name = 'zeek_smb_converted_win_susp_raccess_sensitive_fext'
    rules_executed[name] = 'false'

    names = [
        '.pst',
        '.ost',
        '.msg',
        '.nst',
        '.oab',
        '.edb',
        '.nsf',
        '.bak',
        '.dmp',
        '.kirbi',
        '\\groups.xml',
        '.rdp'
    ]

    filename = event.get('ads_name')

    is_name_in_list = is_in_list_some(filename, names, 'endswith')

    if (is_name_in_list)
        rules_executed[name] = 'true'
    end
end

def zeek_smb_converted_win_susp_psexec(event, rules_executed)
    category = event.get('ads_category')
    if (category != 'zeek_smb_files')
        return
    end

    name = 'zeek_smb_converted_win_susp_psexec'
    rules_executed[name] = 'false'

    paths = [
        '\\\\',
        '\\IPC$'
    ]

    names = [
        '-stdin',
        '-stdout',
        '-stderr'
    ]

    filename = event.get('ads_name')
    path = event.get('ads_map_path')

    is_name_in_list = is_in_list_some(filename, names, 'endswith')
    is_path_in_list = is_in_list_all(path, paths, 'contains')

    if (is_name_in_list and is_path_in_list and !filename.start_with?('PSEXESVC'))
        rules_executed[name] = 'true'
    end
end

def zeek_smb_converted_win_impacket_secretdump(event, rules_executed)
    category = event.get('ads_category')
    if (category != 'zeek_smb_files')
        return
    end

    name = 'zeek_smb_converted_win_impacket_secretdump'
    rules_executed[name] = 'false'

    paths = [
        '\\',
        'ADMIN$'
    ]

    filename = event.get('ads_name')
    path = event.get('ads_map_path')

    is_path_in_list = is_in_list_all(path, paths, 'contains')

    if (is_path_in_list and filename.include?('SYSTEM32\\') and filename.end_with?('.tmp'))
        rules_executed[name] = 'true'
    end
end

def zeek_smb_converted_win_atsvc_task(event, rules_executed)
    category = event.get('ads_category')
    if (category != 'zeek_smb_files')
        return
    end

    name = 'zeek_smb_converted_win_atsvc_task'
    rules_executed[name] = 'false'

    filename = event.get('ads_name')
    path = event.get('ads_map_path')

    if (filename == 'atsvc' and path == '\\\\\\*\IPC$')
        rules_executed[name] = 'true'
    end
end

def zeek_dce_rpc_smb_spoolss_named_pipe(event, rules_executed)
    category = event.get('ads_category')
    if (category != 'zeek_smb_files')
        return
    end

    name = 'zeek_dce_rpc_smb_spoolss_named_pipe'
    rules_executed[name] = 'false'

    filename = event.get('ads_name')
    path = event.get('ads_map_path')

    if (filename == 'spoolss' and path.end_with?('IPC$'))
        rules_executed[name] = 'true'
    end
end

##### Zeek RDP #####

def zeek_rdp_public_listener(event, rules_executed)
    category = event.get('ads_category')
    if (category != 'zeek_rdp')
        return
    end

    name = 'zeek_rdp_public_listener'
    rules_executed[name] = 'false'

    sources = [
        '192.168.',
        '10.',
        '172.16.',
        '172.17.',
        '172.18.',
        '172.19.',
        '172.20.',
        '172.21.',
        '172.22.',
        '172.23.',
        '172.24.',
        '172.25.',
        '172.26.',
        '172.27.',
        '172.28.',
        '172.29.',
        '172.30.',
        '172.31.',
        'fd',
        '2620:83:800f'
    ]

    src_ip = event.get('ads_src_ip')

    is_source_in_list = is_in_list_some(src_ip, sources, 'startswith')

    if (!is_source_in_list)
        rules_executed[name] = 'true'
    end
end

##### Zeek Http ####

def zeek_http_webdav_put_request(event, rules_executed)
    category = event.get('ads_category')
    if (category != 'zeek_http')
        return
    end

    name = 'zeek_http_webdav_put_request'
    rules_executed[name] = 'false'

    user_agent = event.get('ads_user_agent')
    method = event.get('ads_http_method')

    if (user_agent.include?('WebDAV') and method == 'PUT')
        rules_executed[name] = 'true'
    end
end

def zeek_http_omigod_no_auth_rce(event, rules_executed)
    category = event.get('ads_category')
    if (category != 'zeek_http')
        return
    end

    name = 'zeek_http_omigod_no_auth_rce'
    rules_executed[name] = 'false'

    status = event.get('ads_status')
    method = event.get('ads_http_method')
    uri = event.get('ads_url_path')

    if (uri == '/wsman' and status == '200' and method == 'POST')
        rules_executed[name] = 'true'
    end
end

def zeek_http_executable_download_from_webdav(event, rules_executed)
    category = event.get('ads_category')
    if (category != 'zeek_http')
        return
    end

    name = 'zeek_http_executable_download_from_webdav'
    rules_executed[name] = 'false'

    status = event.get('ads_status')
    uri = event.get('ads_url_path')
    user_agent = event.get('ads_user_agent')

    if (user_agent.include?('WebDAV') and uri.include?('webdav') and uri.end_with?('.exe') )
        rules_executed[name] = 'true'
    end
end

#### Zeek Connection ####

def net_firewall_apt_equationgroup_c2(event, rules_executed)
    category = event.get('ads_category')
    if (category != 'zeek_conn')
        return
    end

    name = 'net_firewall_apt_equationgroup_c2'
    rules_executed[name] = 'false'

    addresses = [
        '69.42.98.86',
        '89.185.234.145'
    ]

    src_ip = event.get('ads_src_ip')
    dst_ip = event.get('ads_dst_ip')

    is_source_in_list = is_in_list_some(src_ip, addresses, '')
    is_dest_in_list = is_in_list_some(dst_ip, addresses, '')

    if (is_source_in_list or is_dest_in_list)
        rules_executed[name] = 'true'
    end
end

#### Blacklist ####
def blacklist_by_src_ip(event, rules_executed)
    category = event.get('ads_category')
    if (category != 'zeek_conn')
        return
    end

    name = 'blacklist_by_src_ip'
    rules_executed[name] = 'false'

    is_blacklist = event.get('ads_alert_by_blacklist_srcip')
    rules_executed[name] = is_blacklist
end

def blacklist_by_dst_ip(event, rules_executed)
    category = event.get('ads_category')
    if (category != 'zeek_conn')
        return
    end

    name = 'blacklist_by_dst_ip'
    rules_executed[name] = 'false'

    is_blacklist = event.get('ads_alert_by_blacklist_dstip')
    rules_executed[name] = is_blacklist
end

def blacklist_by_hash(event, rules_executed, blacklist_map)
    category = event.get('ads_category')
    if (category != 'zeek_files')
        return
    end

    name = 'blacklist_by_hash'
    rules_executed[name] = 'false'

    sha256 = event.get('ads_sha256')
    sha1 = event.get('ads_sha1')

    lookup_sha256 = blacklist_map[sha256]
    lookup_sha1 = blacklist_map[sha1]

    if !lookup_sha256.nil? or !lookup_sha1.nil?
        #Found in blacklist
        rules_executed[name] = 'true'
    end
end

def blacklist_by_url(event, rules_executed, blacklist_map)
    category = event.get('ads_category')
    if (category != 'zeek_http')
        return
    end

    name = 'blacklist_by_url'
    rules_executed[name] = 'false'

    url = event.get('ads_url_path')
    lookup_url = blacklist_map[url]

    if !lookup_url.nil?
        #Found in blacklist
        rules_executed[name] = 'true'
    end
end

def blacklist_by_domain(event, rules_executed, blacklist_map)
    category = event.get('ads_category')
    if (category != 'zeek_dns')
        return
    end

    name = 'blacklist_by_domain'
    rules_executed[name] = 'false'

    domain = event.get('ads_host')
    lookup_domain = blacklist_map[domain]

    if !lookup_domain.nil?
        #Found in blacklist
        rules_executed[name] = 'true'
    end
end

#### MISP ####
def misp_ioc_by_dst_ip(event, rules_executed)
    name = 'misp_ioc_by_dst_ip'
    rules_executed[name] = 'false'

    is_ioc_found = event.get('ads_alert_by_dstip')
    rules_executed[name] = is_ioc_found
end

def misp_ioc_by_src_ip(event, rules_executed)
    name = 'misp_ioc_by_src_ip'
    rules_executed[name] = 'false'

    is_ioc_found = event.get('ads_alert_by_srcip')
    rules_executed[name] = is_ioc_found
end

def misp_ioc_by_sha256(event, rules_executed)
    name = 'misp_ioc_by_sha256'
    rules_executed[name] = 'false'

    is_ioc_found_1 = event.get('ads_alert_by_sha256_1')
    is_ioc_found_2 = event.get('ads_alert_by_sha256_2')

    if (is_ioc_found_2 == 'true' or is_ioc_found_1 == 'true')
        rules_executed[name] = 'true'
    end
end

#### Snort ####
def snort_priority_high_found(event, rules_executed)
    category = event.get('ads_category')
    if (category != 'snort')
        return
    end

    name = 'snort_priority_high_found'
    rules_executed[name] = 'false'

    priority = event.get('ads_priority_txt')

    if (priority == 'high')
        rules_executed[name] = 'true'
    end
end

def snort_malware_found(event, rules_executed)
    category = event.get('ads_category')
    if (category != 'snort')
        return
    end

    name = 'snort_malware_found'
    rules_executed[name] = 'false'

    rule_name = event.get('ads_rulename')
    classification = event.get('ads_classification')

    if (rule_name.match(/WinWrapper\.Adware/i) or classification.match(/WinWrapper\.Adware/i))
        rules_executed[name] = 'true'
    end
end

def snort_exploit_found(event, rules_executed)
    category = event.get('ads_category')
    if (category != 'snort')
        return
    end

    name = 'snort_exploit_found'
    rules_executed[name] = 'false'

    rule_name = event.get('ads_rulename')
    classification = event.get('ads_classification')

    if (rule_name.match(/EXPLOIT/i) or classification.match(/EXPLOIT/i))
        rules_executed[name] = 'true'
    end
end

#### Cobalt Strike ####
def cobalt_strike_command_and_control_beacon(event, rules_executed)
    category = event.get('ads_category')
    if ((category != 'zeek_ssl') && (category != 'zeek_http'))
        return
    end

    name = 'cobalt_strike_command_and_control_beacon'
    rules_executed[name] = 'false'

    host = event.get('ads_host')

    if (host.match(/[a-z]{3}.stage.[0-9]{8}\..*/))
        rules_executed[name] = 'true'
    end
end
