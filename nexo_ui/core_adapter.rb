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
  }.freeze

  def build_state
    from_json = read_json_state
    return [from_json, 'real'] if from_json

    from_sqlite = read_sqlite_state
    return [from_sqlite, 'real'] if from_sqlite

    [FALLBACK_STATE.dup, 'fallback_simulated']
  end

  def read_json_state
    path = ENV['NEXO_UI_STATE_PATH'] || ENV['NEXO_STATE_PATH'] || File.join(Dir.pwd, 'state.json')

    return nil unless path && !path.empty? && File.file?(path)

    raw = File.read(path)
    return nil if raw.nil? || raw.empty?

    parsed = JSON.parse(raw)
    return nil unless parsed.is_a?(Hash)

    normalized = normalize(parsed)
    return nil unless normalized

    normalized
  rescue StandardError
    nil
  end

  def read_sqlite_state
    return nil unless File.file?(sqlite_path)

    require 'sqlite3'

    db = ::SQLite3::Database.new(sqlite_path)
    db.results_as_hash = true

    row = db.get_first_row('SELECT payload FROM nexo_state WHERE id = 1;')
    return nil unless row && row['payload']

    parsed = JSON.parse(row['payload'])
    normalized = normalize(parsed)
    normalized
  rescue StandardError
    nil
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

    {
      system_status: status,
      peers_count: peers.to_i,
      relay_status: relay,
      ai_last_insight: insight,
      recent_event_hash: hash,
      last_sync: sync,
    }
  end
end
