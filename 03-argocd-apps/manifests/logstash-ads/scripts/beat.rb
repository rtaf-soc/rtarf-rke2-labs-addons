require 'time'
require 'date'
require 'dalli'
require 'net/http'
require "json"

def register(params)
    $stdout.sync = true
end

def filter(event)
    event.set('ts_arrived_kafka', Time.now.to_i)
    event.set('pod_name_syslog', 'logstash-beat-0')

    evt = event.to_json
    event.set('message', evt) #Pass original object

    type = event.get('type')
    event.set('type', 'log')
    event.set('tx_type', type)

    program = event.get('program')
    if program.nil? or program == ''
        event.set('ads_category', 'beat_unknown')
    else
        event.set('ads_category', program)
    end

    return [event]
end
