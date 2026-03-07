require 'json'

module CoreAdapter
  module_function

  FALLBACK_STATE = {
    system_status: 'operational',
    peers_count: 8,
    relay_status: 'sync-bridge online',
    ai_last_insight: 'No anomaly patterns observed in this window.',
    recent_event_hash: 'bf5cfda1e218837d2f8a597f8011b4096',
    last_sync: nil,
    last_event_hash: 'bf5cfda1e218',
    event_type: 'startup',
    event_timestamp: nil,
    event_origin: 'ui_fallback',
    event_channel: 'system',
  }.freeze

  def build_state
    from_json, status = read_json_state
    return [from_json, 'real', 'file', status] if from_json

    from_sqlite, sqlite_status = read_sqlite_state
    return [from_sqlite, 'real', 'sqlite', sqlite_status] if from_sqlite

    [FALLBACK_STATE.dup, 'fallback_simulated', 'fallback', status || sqlite_status || 'fallback_no_data_source']
  end

  def read_json_state
    path = ENV['NEXO_UI_STATE_PATH'] || ENV['NEXO_STATE_PATH'] || File.join(Dir.pwd, 'state.json')

    return [nil, 'json_path_missing'] unless path && !path.empty? && File.file?(path)

    raw = File.read(path)
    return [nil, 'json_empty'] if raw.nil? || raw.empty?

    parsed = JSON.parse(raw)
    return [nil, 'json_not_object'] unless parsed.is_a?(Hash)

    normalized = normalize(parsed)
    return [nil, 'json_invalid_normalized'] unless normalized

    [normalized, 'ok']
  rescue StandardError => e
    [nil, "json_read_error: #{e.class.name}"]
  end

  def read_sqlite_state
    return [nil, 'sqlite_path_missing'] unless File.file?(sqlite_path)

    require 'sqlite3'

    db = ::SQLite3::Database.new(sqlite_path)
    db.results_as_hash = true

    row = db.get_first_row('SELECT payload FROM nexo_state WHERE id = 1;')
    return [nil, 'sqlite_no_payload'] unless row && row['payload']

    parsed = JSON.parse(row['payload'])
    return [nil, 'sqlite_invalid_payload'] unless parsed.is_a?(Hash)

    normalized = normalize(parsed)
    return [nil, 'sqlite_invalid_normalized'] unless normalized

    [normalized, 'ok']
  rescue StandardError => e
    [nil, "sqlite_read_error: #{e.class.name}"]
  ensure
    db&.close
  end

  def sqlite_path
    ENV['NEXO_UI_SQLITE_PATH'] || File.join(Dir.pwd, 'state.db')
  end

  def normalize(payload)
    status = payload['system_status'] || payload['systemStatus'] || payload[:system_status] || 'unknown'
    peers = payload['peers_count'] || payload['peersCount'] || payload[:peers_count] || 0
    relay = payload['relay_status'] || payload['relayStatus'] || payload[:relay_status] || 'unknown'
    insight = payload['ai_last_insight'] || payload['aiLastInsight'] || payload[:ai_last_insight] || 'No insight available.'
    hash = payload['recent_event_hash'] || payload['recentEventHash'] || payload[:recent_event_hash] || '000000000000'
    sync = payload['last_sync'] || payload['lastSync'] || payload[:last_sync] || Time.now.utc.strftime('%Y-%m-%d %H:%M:%S UTC')
    event_hash = payload['last_event_hash'] || payload['lastEventHash'] || payload[:last_event_hash] || hash
    event_type = payload['event_type'] || payload['eventType'] || payload[:event_type] || 'unknown'
    event_timestamp = payload['event_timestamp'] || payload['eventTimestamp'] || payload[:event_timestamp] || Time.now.utc.strftime('%Y-%m-%d %H:%M:%S UTC')
    event_origin = payload['event_origin'] || payload['eventOrigin'] || payload[:event_origin] || 'unknown'
    event_channel = payload['event_channel'] || payload['eventChannel'] || payload[:event_channel] || 'unknown'

    {
      system_status: status,
      peers_count: peers.to_i,
      relay_status: relay,
      ai_last_insight: insight,
      recent_event_hash: hash,
      last_sync: sync,
      last_event_hash: event_hash,
      event_type: event_type,
      event_timestamp: event_timestamp,
      event_origin: event_origin,
      event_channel: event_channel,
    }
  end
end
