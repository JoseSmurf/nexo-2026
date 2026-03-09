require 'json'
require 'net/http'
require 'uri'
require 'time'

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
    recent_flow: [],
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
    from_core, status = read_core_state
    return [from_core, 'real', 'core', status] if from_core

    from_json, status = read_json_state
    return [from_json, 'real', 'file', status] if from_json

    from_sqlite, sqlite_status = read_sqlite_state
    return [from_sqlite, 'real', 'sqlite', sqlite_status] if from_sqlite

    [build_fallback_state, 'fallback_simulated', 'fallback', status || sqlite_status || 'fallback_no_data_source']
  end

  def send_chat_message(text:, origin:, channel: 'global')
    url = ENV['NEXO_CORE_CHAT_SEND_URL'] || core_endpoint_url('/api/chat/send')
    return [nil, 'core_chat_url_empty'] if url.to_s.strip.empty?

    uri = URI.parse(url)
    return [nil, 'core_chat_url_invalid'] unless uri.is_a?(URI::HTTP) || uri.is_a?(URI::HTTPS)

    request = Net::HTTP::Post.new(uri)
    request['Content-Type'] = 'application/json'
    request.body = JSON.generate(
      {
        text: text,
        origin: origin,
        channel: channel,
      },
    )

    response = Net::HTTP.start(
      uri.host,
      uri.port,
      use_ssl: uri.scheme == 'https',
      read_timeout: 1,
      open_timeout: 1,
    ) do |http|
      http.request(request)
    end

    return [nil, "core_chat_http_#{response.code}"] unless response.is_a?(Net::HTTPSuccess)

    body = response.body.to_s
    return [nil, 'core_chat_http_empty'] if body.empty?

    parsed = JSON.parse(body)
    return [nil, 'core_chat_not_object'] unless parsed.is_a?(Hash)

    [parsed, 'ok']
  rescue StandardError => e
    [nil, "core_chat_request_error: #{e.class.name}"]
  end

  def read_core_state
    url = ENV['NEXO_CORE_STATE_URL'] || core_endpoint_url('/api/state')
    return [nil, 'core_url_empty'] if url.to_s.strip.empty?

    uri = URI.parse(url)
    return [nil, 'core_url_invalid'] unless uri.is_a?(URI::HTTP) || uri.is_a?(URI::HTTPS)

    response = Net::HTTP.start(
      uri.host,
      uri.port,
      use_ssl: uri.scheme == 'https',
      read_timeout: 1,
      open_timeout: 1,
    ) do |http|
      request = Net::HTTP::Get.new(uri)
      http.request(request)
    end

    return [nil, "core_http_#{response.code}"] unless response.is_a?(Net::HTTPSuccess)

    body = response.body.to_s
    return [nil, 'core_http_empty'] if body.empty?

    parsed = JSON.parse(body)
    return [nil, 'core_not_object'] unless parsed.is_a?(Hash)

    normalized = normalize(parsed, source: :core)
    return [nil, 'core_invalid_normalized'] unless normalized

    payload = parsed['state'] if parsed.key?('state')
    if payload.is_a?(Hash)
      fallback_normalized = normalize(payload, source: :core)
      return [fallback_normalized, 'ok'] if fallback_normalized
    end

    [normalized, 'ok']
  rescue StandardError => e
    [nil, "core_request_error: #{e.class.name}"]
  end

  def build_fallback_state
    state = FALLBACK_STATE.dup
    state[:recent_events] = normalize_events(payload_to_events(FALLBACK_RECENT_EVENTS))
    state[:recent_ai_insights] = payload_to_ai_insights(FALLBACK_AI_INSIGHTS)
    state[:recent_chat_messages] = normalize_chat_messages(payload_to_chat_messages(FALLBACK_CHAT_MESSAGES))
    state[:recent_flow] = build_recent_flow(
      state[:recent_events],
      state[:recent_ai_insights],
      state[:recent_chat_messages],
    )
    apply_derived_observability!(state, source: :fallback)
    state
  end

  def read_json_state
    path = ENV['NEXO_UI_STATE_PATH'] || ENV['NEXO_STATE_PATH'] || File.join(Dir.pwd, 'state.json')

    return [nil, 'json_path_missing'] unless path && !path.empty? && File.file?(path)

    raw = File.read(path)
    return [nil, 'json_empty'] if raw.nil? || raw.empty?

    parsed = JSON.parse(raw)
    return [nil, 'json_not_object'] unless parsed.is_a?(Hash)

    normalized = normalize(parsed, source: :file)
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

    normalized = normalize(parsed, source: :sqlite)
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

  def core_endpoint_url(path)
    uri = URI.parse(ENV['NEXO_CORE_STATE_URL'] || 'http://127.0.0.1:3000/api/state')
    uri.path = path
    uri.query = nil
    uri.fragment = nil
    uri.to_s
  rescue URI::InvalidURIError
    ''
  end

  def normalize(payload, source: :fallback)
    is_core_source = (source == :core)
    use_fallback = !is_core_source
    use_chat_fallback = use_fallback
    use_flow_fallback = use_fallback

    status = payload['system_status'] || payload['systemStatus'] || payload[:system_status] || 'unknown'
    peers = payload['peers_count'] || payload['peersCount'] || payload[:peers_count] || 0
    relay = payload['relay_status'] || payload['relayStatus'] || payload[:relay_status] || 'unknown'
    network_mode = normalize_network_mode(payload['network_mode'] || payload['networkMode'] || payload[:network_mode] || payload[:networkMode])
    mesh_status = normalize_mesh_status(payload['mesh_status'] || payload['meshStatus'] || payload[:mesh_status] || payload[:meshStatus])
    insight = payload['ai_last_insight'] || payload['aiLastInsight'] || payload[:ai_last_insight] || 'No insight available.'
    hash = payload['recent_event_hash'] || payload['recentEventHash'] || payload[:recent_event_hash] || '000000000000'
    sync = payload['last_sync'] || payload['lastSync'] || payload[:last_sync] || 'n/a'
    events = payload['recent_events'] || payload[:recent_events]
    recent_events = normalize_events(events, allow_fallback: use_fallback)
    recent_ai_insights = normalize_ai_insights(
      payload['recent_ai_insights'] || payload[:recent_ai_insights] || payload['ai_recent_insights'] || payload[:ai_recent_insights],
      allow_fallback: use_fallback,
    )
    chat_payload = payload['recent_chat_messages']
    chat_payload = payload[:recent_chat_messages] if chat_payload.nil?
    chat_payload = payload['chat_messages'] if chat_payload.nil?
    chat_payload = payload[:chat_messages] if chat_payload.nil?
    recent_chat_messages = chat_payload.nil? ? (use_chat_fallback ? fallback_chat_messages : []) : normalize_chat_messages(chat_payload)
    recent_flow = if is_core_source
      normalize_flow_core(payload['recent_flow'] || payload[:recent_flow])
    else
      normalize_flow(payload['recent_flow'] || payload[:recent_flow], recent_events, recent_ai_insights, recent_chat_messages, use_fallback: use_flow_fallback)
    end
    chat_send_available = payload['chat_send_available']
    chat_send_available = payload[:chat_send_available] if chat_send_available.nil?
    chat_send_mode = payload['chat_send_mode']
    chat_send_mode = payload[:chat_send_mode] if chat_send_mode.nil?
    chat_send_reason = payload['chat_send_reason']
    chat_send_reason = payload[:chat_send_reason] if chat_send_reason.nil?

    if is_core_source
      chat_send_available = !!chat_send_available
      chat_send_mode = chat_send_mode.to_s.strip
      chat_send_mode = chat_send_available ? 'core' : 'core_unavailable' if chat_send_mode.empty?
      chat_send_reason = chat_send_reason.to_s
    end

    if recent_events.empty? && use_fallback
      recent_events = [payload_to_events(
        [
          {
            hash: event_hash(payload, hash),
            type: payload_event_type(payload, 'unknown'),
            timestamp: payload_event_timestamp(payload),
            origin: payload_event_origin(payload),
            channel: payload_event_channel(payload),
          },
        ],
      )].flatten
    end

    latest = recent_events.first || {
      hash: 'n/a',
      type: 'startup',
      timestamp: 'n/a',
      origin: 'core_engine',
      channel: 'system',
    }

    state = {
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
      recent_flow: recent_flow,
      chat_send_available: chat_send_available,
      chat_send_mode: chat_send_mode,
      chat_send_reason: chat_send_reason,
    }

    apply_derived_observability!(state, source: source)
    state
  end

  def apply_derived_observability!(state, source:)
    latest = Array(state[:recent_flow]).first || Array(state[:recent_events]).first || {}
    state[:latest_change_kind] ||= (latest[:kind] || latest['kind'] || 'startup').to_s
    state[:latest_change_summary] ||= (
      latest[:summary] || latest['summary'] || latest[:type] || latest['type'] || 'No recent changes observed.'
    ).to_s
    state[:latest_change_origin] ||= (latest[:origin] || latest['origin'] || 'core_engine').to_s
    state[:latest_change_timestamp] ||= latest[:timestamp] || latest['timestamp'] || 0
    state[:latest_change_channel] ||= (
      latest[:channel] || latest['channel'] || 'system'
    ).to_s

    if state[:write_status].to_s.empty?
      state[:write_status] =
        case source
        when :core
          state[:chat_send_available] ? 'writable' : 'read_only'
        when :file, :sqlite
          'read_only'
        else
          'unavailable'
        end
    end
  end

  def normalize_flow_core(flow_items)
    return [] unless flow_items.is_a?(Array)

    normalized = []
    flow_items.each do |item|
      next unless item.is_a?(Hash)

      normalized << {
        kind: normalize_flow_kind(item['kind'] || item[:kind]),
        origin: item['origin'] || item[:origin] || 'unknown',
        summary: item['summary'] || item[:summary] || item['text'] || item[:text] || '',
        timestamp: normalize_flow_timestamp(item['timestamp'] || item[:timestamp]),
        hash: item['hash'] || item[:hash],
        channel: item['channel'] || item[:channel] || '',
      }
    end

    normalized.first(5)
  end

  def normalize_flow(flow_items, events, ai_insights, chat_messages, use_fallback: true)
    normalized = []

    return build_recent_flow(events, ai_insights, chat_messages) if flow_items.nil?
    return build_recent_flow(events, ai_insights, chat_messages) unless flow_items.is_a?(Array)

    flow_items.each do |item|
      next unless item.is_a?(Hash)

      kind = (item['kind'] || item[:kind] || 'event').to_s
      next unless %w[event chat ai].include?(kind)

      normalized << {
        kind: kind,
        origin: item['origin'] || item[:origin] || 'unknown',
        summary: item['summary'] || item[:summary] || item['text'] || item[:text] || '',
        timestamp: item['timestamp'] || item[:timestamp] || 'n/a',
        hash: item['hash'] || item[:hash],
        channel: item['channel'] || item[:channel] || '',
      }
    end

    normalized = normalized.first(5)
    return build_recent_flow(events, ai_insights, chat_messages) if normalized.empty? && use_fallback

    normalized.sort_by! do |item|
      ts = flow_item_timestamp(item[:timestamp])
      kind_order = item[:kind] == 'event' ? 0 : item[:kind] == 'ai' ? 1 : 2
      [-ts, kind_order]
    end
    normalized
  end

  def build_recent_flow(events, ai_insights, chat_messages)
    candidates = []

    Array(events).each_with_index do |event, index|
      event_type = event[:type] || event['type'] || 'event'
      candidates << {
        kind: 'event',
        origin: event[:origin] || event['origin'] || 'unknown',
        summary: human_event_summary(event_type),
        timestamp: event[:timestamp] || event['timestamp'] || 'n/a',
        hash: event[:hash] || event['hash'],
        channel: event[:channel] || event['channel'] || '',
        _time: flow_item_timestamp(event[:timestamp] || event['timestamp']),
        _rank: 0,
        _index: index,
      }
    end

    Array(ai_insights).each_with_index do |insight, index|
      candidates << {
        kind: 'ai',
        origin: insight[:origin] || insight['origin'] || 'ui_simulator_ai',
        summary: insight[:text] || insight['text'] || 'AI insight',
        timestamp: insight[:timestamp] || insight['timestamp'] || 'n/a',
        hash: insight[:hash] || insight['hash'],
        channel: insight[:type] || insight['type'] || 'ui_insight',
        _time: flow_item_timestamp(insight[:timestamp] || insight['timestamp']),
        _rank: 1,
        _index: index,
      }
    end

    Array(chat_messages).each_with_index do |message, index|
      candidates << {
        kind: 'chat',
        origin: message[:origin] || message['origin'] || 'ui_simulator_chat',
        summary: message[:text] || message['text'] || '(empty)',
        timestamp: message[:timestamp] || message['timestamp'] || 'n/a',
        hash: message[:hash] || message['hash'],
        channel: message[:channel] || message['channel'] || 'global',
        _time: flow_item_timestamp(message[:timestamp] || message['timestamp']),
        _rank: 2,
        _index: index,
      }
    end

    ordered = candidates.sort_by { |item| [-item[:_time], item[:_rank], item[:_index]] }
    ordered.first(5).map do |item|
      {
        kind: item[:kind],
        origin: item[:origin],
        summary: item[:summary],
        timestamp: item[:timestamp],
        hash: item[:hash],
        channel: item[:channel],
      }
    end
  end

  def human_event_summary(event_type)
    case event_type.to_s
    when 'system_event:approved'
      'approved decision'
    when 'system_event:flagged'
      'flagged for review'
    when 'system_event:blocked'
      'blocked decision'
    else
      event_type.to_s
    end
  end

  def flow_item_timestamp(raw_timestamp)
    return raw_timestamp.to_i if raw_timestamp.is_a?(Integer)
    return raw_timestamp.to_f if raw_timestamp.is_a?(Float)

    text = raw_timestamp.to_s
    return 0 if text.nil? || text.empty?

    stripped = text.strip
    return stripped.to_i if stripped =~ /\A\d+\z/

    begin
      Time.parse(stripped).to_i
    rescue StandardError
      0
    end
  end

  def normalize_ai_insights(insights, allow_fallback: true)
    normalized = []

    return allow_fallback ? fallback_ai_insights : [] if insights.nil?

    return allow_fallback ? fallback_ai_insights : [] unless insights.is_a?(Array)

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
    return fallback_ai_insights if normalized.empty? && allow_fallback

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

  def normalize_events(events, allow_fallback: true)
    normalized = []

    return allow_fallback ? fallback_recent_events : [] if events.nil?

    unless events.is_a?(Array)
      return fallback_recent_events if allow_fallback
      return []
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

    return fallback_recent_events if normalized.empty? && allow_fallback

    normalized.first(5)
  end

  def payload_to_events(events)
    normalize_events(events).map(&:dup)
  end

  def normalize_flow_kind(value)
    kind = (value || 'event').to_s
    return kind if %w[event chat ai].include?(kind)

    'event'
  end

  def normalize_flow_timestamp(value)
    return value if value.is_a?(Integer) || value.is_a?(Float)
    str = value.to_s
    return 'n/a' if str.empty?

    str
  end

  def fallback_recent_events
    payload_to_events(FALLBACK_RECENT_EVENTS).map(&:dup)
  end
end
