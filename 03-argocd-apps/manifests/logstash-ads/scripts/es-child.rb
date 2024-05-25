require 'time'
require 'date'
require 'dalli'
require 'net/http'
require "json"

# If this need to be changed so please change etl.rb accordingly
MISP_IP = '10.141.98.162'
MISP_KEY = 'j7QDoNn6Z4nrXZTupWWxsJU9kD3PuqqE4XJuYNvd'

def register(params)
    $stdout.sync = true

    #load_mitr_attack_pattern()
end


def load_mitr_attack_pattern()

    uri = URI.parse("https://#{MISP_IP}/galaxy_clusters/index/31") # 31 is mitr-attack-pattern
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

        puts "### Trying to load attack pattern from MISP, attempt no [#{i}]..."
        begin
            response = https.request(request)
        rescue TimeoutError
            status = 'misp-timeout'
        else
            #No error
            status = response.code
        end

        if (status == "200")
            @attack_patterns = Hash.new()

            misp_data = response.body
            arrs = JSON.parse(misp_data)
 
            if (arrs.count > 0)
                arrs.each do |obj|
                    cluster = obj['GalaxyCluster']

                    value = cluster['value'] # Example --> "Keychain - T1579"
                    name = value # Set it to default value 

                    if m = value.match(/^(.*) - (.*)$/)
                        desc, name = m.captures
                    end

                    puts("### DEBUG - [#{name}] --> [#{value}]")
                    @attack_patterns[name] = value
                end
            else
                puts("### [Error] Got empty array of attack-patterns !!!")
            end

            return
        end
    end

    abort("### [Error] Unable to load attack-patterns from MISP [#{response}]")
end


def populate_child_data(event, childs, table_name, table_category)

    field_name = "ads_alert_by_#{table_category}_#{table_name}"
    field_info = "ads_alert_by_#{table_category}_info"
    field_tlid = "ads_alert_by_#{table_category}_tlid"
    field_category = "ads_alert_by_#{table_category}_category"

    field_value = event.get(field_name)
    if field_value.nil?
        return
    end

    info_value = event.get(field_info)
    tlid_value = event.get(field_tlid)
    category_value = event.get(field_category)

    #puts "DEBUG - Field name [#{field_name}], table[#{table_name}], category=[#{table_category}]"
    tokens = field_value.split(",")

    tokens.each do |token|
        obj = Hash.new()

        obj['table_name'] = table_name
        obj['table_category'] = table_category
        obj['alert_info'] = info_value
        obj['alert_tlid'] = tlid_value
        obj['alert_category'] = category_value
        obj['name'] = token
        obj['description'] = token # Set default value

        if ((table_name == "mitre_attack_pattern") && @attack_patterns.has_key?(token))
            obj['description'] = @attack_patterns[token]
        end

        childs.push(obj)
    end
end

def filter(event)
    is_misp_alert = event.get('ads_alert_by_misp')

    if (is_misp_alert != "true")
        return []
    end

    #chance = rand(1...1000)
    #if (chance > 900)
    #    return []
    #end

    childs = []

    alert_flag = event.get("ads_alert_by_dstip")
    if (alert_flag == "true")
        populate_child_data(event, childs, 'mandiant_malware_family', 'dstip')
        populate_child_data(event, childs, 'mandiant_threat_actor', 'dstip')
        populate_child_data(event, childs, 'mitre_attack_pattern', 'dstip')
        populate_child_data(event, childs, 'source_country', 'dstip')
        populate_child_data(event, childs, 'target_country', 'dstip')
        populate_child_data(event, childs, 'target_industry', 'dstip')
    end

    alert_flag = event.get("ads_alert_by_domain")
    if (alert_flag == "true")
        populate_child_data(event, childs, 'mandiant_malware_family', 'domain')
        populate_child_data(event, childs, 'mandiant_threat_actor', 'domain')
        populate_child_data(event, childs, 'mitre_attack_pattern', 'domain')
        populate_child_data(event, childs, 'source_country', 'domain')
        populate_child_data(event, childs, 'target_country', 'domain')
        populate_child_data(event, childs, 'target_industry', 'domain')
    end

    alert_flag = event.get("ads_alert_by_srcip")
    if (alert_flag == "true")
        populate_child_data(event, childs, 'mandiant_malware_family', 'srcip')
        populate_child_data(event, childs, 'mandiant_threat_actor', 'srcip')
        populate_child_data(event, childs, 'mitre_attack_pattern', 'srcip')
        populate_child_data(event, childs, 'source_country', 'srcip')
        populate_child_data(event, childs, 'target_country', 'srcip')
        populate_child_data(event, childs, 'target_industry', 'srcip')
    end

    alert_flag = event.get("ads_alert_by_sha256_1")
    if (alert_flag == "true")
        populate_child_data(event, childs, 'mandiant_malware_family', 'sha256_1')
        populate_child_data(event, childs, 'mandiant_threat_actor', 'sha256_1')
        populate_child_data(event, childs, 'mitre_attack_pattern', 'sha256_1')
        populate_child_data(event, childs, 'source_country', 'sha256_1')
        populate_child_data(event, childs, 'target_country', 'sha256_1')
        populate_child_data(event, childs, 'target_industry', 'sha256_1')
    end

    alert_flag = event.get("ads_alert_by_url")
    if (alert_flag == "true")
        populate_child_data(event, childs, 'mandiant_malware_family', 'url')
        populate_child_data(event, childs, 'mandiant_threat_actor', 'url')
        populate_child_data(event, childs, 'mitre_attack_pattern', 'url')
        populate_child_data(event, childs, 'source_country', 'url')
        populate_child_data(event, childs, 'target_country', 'url')
        populate_child_data(event, childs, 'target_industry', 'url')
    end


    event.set('ads_child', childs)
    event.set('ads_pod_name_es', ENV["POD_NAME"])

    return [event]
end
