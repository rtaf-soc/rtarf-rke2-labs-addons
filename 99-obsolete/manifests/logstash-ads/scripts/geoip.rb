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
    direction = event.get('ads_traffic_direction')
    protocol = event.get('ads_L7_protocol')
    status = event.get('ads_status')

    if (category != 'syslog_fw_traffic')
        return []
    end

    if (direction != 'external-to-external')
        return []
    end

    if ((status != 'deny') && (status != 'drop'))
        return []
    end

    src_ip = event.get('ads_src_ip')
    dst_ip = event.get('ads_dst_ip')
    src_port = event.get('ads_src_port')
    dst_port = event.get('ads_dst_port')

    msg = "#{src_ip},#{dst_ip},#{src_port},#{dst_port},#{protocol},status:#{status}"
    puts("DEBUG : #{msg}")

    event.set('message', msg)

    return [event]
end
