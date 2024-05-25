require 'time'
require 'date'
require 'dalli'
require 'net/http'
require "json"

def register(params)
    $stdout.sync = true
end

def filter(event)
    category = event.get('ads_category')
    dst_country = event.get('ads_country_dst')
    country_dst_valid = event.get('ads_country_dst_valid')

    if ((category != 'zeek_radius') && (category != 'syslog_fw_traffic') && (category != 'zeek_conn'))
        return []
    end

    if (category == 'syslog_fw_traffic')
        if (dst_country == "10.0.0.0-10.255.255.255")
            return []
        end

        if (country_dst_valid == "false")
            return []
        end
    end

    if (category == 'zeek_conn')
        if (country_dst_valid == "false")
            return []
        end
    end

    evt = event.to_json
    event.set('message', evt) #Pass original object

    return [event]
end
