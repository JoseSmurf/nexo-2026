require 'json'

module CoreAdapter
  module_function

  FALLBACK_STATE = {
    system_status: 'operational',
    peers_count: 8,
    relay_status: 'sync-bridge online',
    network_mode: 'mesh',
    mesh_status: 'stable',
    ai_last_insight: 'No anomaly patterns observed in this window.',
    recent_event_hash: 'bf5cfda1e218837d2f8a597f8011b4096',
    last_sync: nil,
    last_event_hash: 'bf5cfda1e218',
    event_type: 'startup',
    event_timestamp: nil,
    event_origin: 'ui_fallback',
    event_channel: 'system',
    recent_events: [],
    recent_ai_insights: [],
    recent_chat_messages: [],
  }.freeze

  FALLBACK_AI_INSIGHTS = [
    {
      text: 'No anomaly patterns observed in this window.',
      timestamp: '2026-03-07 00:00:00 UTC',
      type: 'bootstrap',
      origin: 'ui_fallback',
    },
    {
      text: 'AI model confidence stable across recent pulses.',
      timestamp: '2026-03-07 00:00:30 UTC',
      type: 'bootstrap',
      origin: 'ui_fallback',
    },
  ].freeze

  FALLBACK_CHAT_MESSAGES = [
    {
      hash: 'chatb01a9f8c4e2d13f0e5a7',
      origin: 'ui_fallback',
      channel: 'global',
      text: 'Welcome to the global chat channel.',
      timestamp: '2026-03-07 00:02:05 UTC',
    },
    {
      hash: 'chatb02f7b1a4c6e98f9d4a0c',
      origin: 'ui_fallback',
      channel: 'global',
      text: 'Offline mode active. Messages are simulated.',
      timestamp: '2026-03-07 00:01:40 UTC',
    },
  ].freeze

  FALLBACK_RECENT_EVENTS = [
    {
      hash: '88e0b1c3d7a44e6f9d2f8a1124cd3b90f',
      type: 'audit_sync',
      timestamp: '2026-03-07 00:02:00 UTC',
      origin: 'relay',
      channel: 'system',
    },
    {
      hash: 'a12d9f8b56ca4d90c3b88f4f7a2e12345',
      type: 'bootstrap',
      timestamp: '2026-03-07 00:01:00 UTC',
      origin: 'core_adapter',
      channel: 'control',
    },
    {
      hash: 'bf5cfda1e218837d2f8a597f8011b4096',
      type: 'startup',
      timestamp: '2026-03-07 00:00:00 UTC',
      origin: 'ui_fallback',
      channel: 'system',
    },
  ].freeze

  def build_state
    from_json, status = read_json_state
    return [from_json, 'real', 'file', status] if from_json

    from_sqlite, sqlite_status = read_sqlite_state
    return [from_sqlite, 'real', 'sqlite', sqlite_status] if from_sqlite

    [build_fallback_state, 'fallback_simulated', 'fallback', status || sqlite_status || 'fallback_no_data_source']
  end

  def build_fallback_state
    state = FALLBACK_STATE.dup
    state[:recent_events] = normalize_events(payload_to_events(FALLBACK_RECENT_EVENTS))
    state[:recent_ai_insights] = payload_to_ai_insights(FALLBACK_AI_INSIGHTS)
    state[:recent_chat_messages] = normalize_chat_messages(payload_to_chat_messages(FALLBACK_CHAT_MESSAGES))
    state
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
    network_mode = normalize_network_mode(payload['network_mode'] || payload['networkMode'] || payload[:network_mode] || payload[:networkMode])
    mesh_status = normalize_mesh_status(payload['mesh_status'] || payload['meshStatus'] || payload[:mesh_status] || payload[:meshStatus])
    insight = payload['ai_last_insight'] || payload['aiLastInsight'] || payload[:ai_last_insight] || 'No insight available.'
    hash = payload['recent_event_hash'] || payload['recentEventHash'] || payload[:recent_event_hash] || '000000000000'
    sync = payload['last_sync'] || payload['lastSync'] || payload[:last_sync] || 'n/a'
    events = payload['recent_events'] || payload[:recent_events]
    recent_events = normalize_events(events)
    recent_ai_insights = normalize_ai_insights(payload['recent_ai_insights'] || payload[:recent_ai_insights] || payload['ai_recent_insights'] || payload[:ai_recent_insights])
    chat_payload = payload['recent_chat_messages']
    chat_payload = payload[:recent_chat_messages] if chat_payload.nil?
    chat_payload = payload['chat_messages'] if chat_payload.nil?
    chat_payload = payload[:chat_messages] if chat_payload.nil?
    recent_chat_messages = chat_payload.nil? ? fallback_chat_messages : normalize_chat_messages(chat_payload)

    if recent_events.empty?
      recent_events = payload_to_events(
        [
          {
            hash: event_hash(payload, hash),
            type: payload_event_type(payload, 'unknown'),
            timestamp: payload_event_timestamp(payload),
            origin: payload_event_origin(payload),
            channel: payload_event_channel(payload),
          },
        ],
      )
    end

    latest = recent_events.first

    {
      system_status: status,
      peers_count: peers.to_i,
      relay_status: relay,
      network_mode: network_mode,
      mesh_status: mesh_status,
      ai_last_insight: insight,
      recent_event_hash: hash,
      last_sync: sync,
      last_event_hash: latest[:hash],
      event_type: latest[:type],
      event_timestamp: latest[:timestamp],
      event_origin: latest[:origin],
      event_channel: latest[:channel],
      recent_events: recent_events,
      recent_ai_insights: recent_ai_insights,
      recent_chat_messages: recent_chat_messages,
    }
  end

  def normalize_ai_insights(insights)
    normalized = []

    return fallback_ai_insights if insights.nil?

    return fallback_ai_insights unless insights.is_a?(Array)

    insights.each do |item|
      next unless item.is_a?(Hash)

      normalized << {
        text: item['text'] || item[:text] || 'No insight available.',
        timestamp: item['timestamp'] || item['time'] || item[:timestamp] || item[:time] || 'n/a',
        type: item['type'] || item[:type] || 'ai_insight',
        origin: item['origin'] || item[:origin] || 'unknown',
      }
    end

    normalized = normalized.first(3)
    return fallback_ai_insights if normalized.empty?

    normalized
  end

  def fallback_ai_insights
    payload_to_ai_insights(FALLBACK_AI_INSIGHTS).map(&:dup)
  end

  def payload_to_ai_insights(insights)
    normalize_ai_insights(insights)
  end

  def normalize_chat_messages(messages)
    normalized = []

    return [] unless messages.is_a?(Array)

    messages.each do |item|
      next unless item.is_a?(Hash)

      normalized << {
        hash: item['hash'] || item[:hash] || item['message_hash'] || item[:message_hash] || '000000000000',
        origin: item['origin'] || item[:origin] || 'unknown',
        channel: item['channel'] || item[:channel] || 'global',
        text: item['text'] || item[:text] || '',
        timestamp: item['timestamp'] || item['time'] || item[:timestamp] || item[:time] || 'n/a',
      }
    end

    return normalized.first(5)
  end

  def payload_to_chat_messages(messages)
    normalize_chat_messages(messages)
  end

  def fallback_chat_messages
    payload_to_chat_messages(FALLBACK_CHAT_MESSAGES).map(&:dup)
  end

  def payload_event_type(payload, default = 'unknown')
    payload['event_type'] || payload['eventType'] || payload[:event_type] || default
  end

  def payload_event_timestamp(payload)
    payload['event_timestamp'] || payload['eventTimestamp'] || payload[:event_timestamp] || 'n/a'
  end

  def payload_event_origin(payload)
    payload['event_origin'] || payload['eventOrigin'] || payload[:event_origin] || 'unknown'
  end

  def payload_event_channel(payload)
    payload['event_channel'] || payload['eventChannel'] || payload[:event_channel] || 'unknown'
  end

  def normalize_network_mode(value)
    return 'mesh' if value.to_s.empty?
    mode = value.to_s.strip.downcase
    return mode if %w[mesh relay hybrid].include?(mode)

    'hybrid'
  end

  def normalize_mesh_status(value)
    return 'stable' if value.to_s.empty?
    status = value.to_s.strip.downcase
    return status if %w[stable unstable].include?(status)

    'stable'
  end

  def event_hash(payload, fallback)
    payload['last_event_hash'] || payload['lastEventHash'] || payload[:last_event_hash] || fallback
  end

  def normalize_events(events)
    normalized = []

    return fallback_recent_events if events.nil?

    unless events.is_a?(Array)
      return fallback_recent_events
    end

    events.each do |item|
      next unless item.is_a?(Hash)

      normalized << {
        hash: item['hash'] || item['event_hash'] || item[:hash] || item[:event_hash] || '000000000000',
        type: item['type'] || item['event_type'] || item[:type] || item[:event_type] || 'unknown',
        timestamp: item['timestamp'] || item['event_timestamp'] || item[:timestamp] || item[:event_timestamp] || 'n/a',
        origin: item['origin'] || item['event_origin'] || item[:origin] || item[:event_origin] || 'unknown',
        channel: item['channel'] || item['event_channel'] || item[:channel] || item[:event_channel] || 'unknown',
      }
    end

    return fallback_recent_events if normalized.empty?

    normalized.first(5)
  end

  def payload_to_events(events)
    normalize_events(events).map(&:dup)
  end

  def fallback_recent_events
    payload_to_events(FALLBACK_RECENT_EVENTS).map(&:dup)
  end
end
