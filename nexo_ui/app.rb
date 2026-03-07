require 'sinatra'
require 'json'
require 'digest'
require 'time'
require_relative 'core_adapter'

set :public_folder, File.join(__dir__, 'public')
set :views, File.join(__dir__, 'views')

configure do
  set :bind, '0.0.0.0'
  set :port, 4567
end

set :state, CoreAdapter.build_fallback_state.merge(event_counter: 0).dup

set :insights, [
  'No anomaly patterns observed in this window.',
  'Unusual cluster of repeated low-risk events detected.',
  'Potential drift spike in network packet timing observed.',
  'AI baseline stable; no intervention needed.',
]

set :ui_mode, :live

CARD_DEFS = [
  { name: 'Core', key: :system_status, tone: 'core' },
  { name: 'Network', key: :peers_count, tone: 'network', label: 'Peers' },
  { name: 'Relay', key: :relay_status, tone: 'relay' },
  { name: 'AI', key: :ai_last_insight, tone: 'ai' },
  { name: 'Hash Pulse', key: :recent_event_hash, tone: 'hash', mono: true },
  { name: 'Events', key: :events, tone: :events, mono: true },
  { name: 'Live Flow', key: :recent_flow, tone: 'flow', mono: true },
  { name: 'Global Chat', key: :recent_chat_messages, tone: 'chat', mono: true },
  { name: 'Integrity', key: :health, tone: 'health', mono: true },
].freeze

helpers do
  def motion_seed_from_state(state, seed_size = CARD_DEFS.length)
    payload = state.to_a.reject { |kv| kv.first == :event_counter }.map { |kv| kv.last.to_s }.join('|')
    digest = Digest::SHA256.digest(payload)

    seed_size.times.map do |i|
      {
        drift_x: digest.getbyte(i) % 8,
        drift_y: digest.getbyte(i + 5) % 8,
        opacity: (65 + (digest.getbyte(i + 10) % 25)) / 100.0,
        flicker: 0.8 + (digest.getbyte(i + 15) % 20) / 10.0,
      }
    end
  end

  def to_payload(state, source, network_cause: nil)
    {
      state: state,
      seed: motion_seed_from_state(state, CARD_DEFS.length),
      last_updated: Time.now.utc.strftime('%Y-%m-%d %H:%M:%S UTC'),
      data_source: source,
      network_cause: network_cause,
    }
  end

  def current_status_state
    CoreAdapter.build_state
  end

  def health_payload(state, source, source_type, adapter_status)
    ui_status = if settings.ui_mode == :demo || source_type == 'fallback'
      'degraded'
    else
      'healthy'
    end

    integrity_message =
      if ui_status == 'unavailable'
        'health source unreachable'
      elsif source_type == 'demo' || adapter_status == 'manual_demo_override'
        'manual demo override active'
      elsif ui_status == 'degraded' && source_type == 'fallback'
        'running from fallback source'
      else
        'reading real source'
      end

    {
      ui_status: ui_status,
      data_source: source,
      source_type: source_type,
      adapter_status: adapter_status,
      integrity_message: integrity_message,
      last_updated: Time.now.utc.strftime('%Y-%m-%d %H:%M:%S UTC'),
      seed: motion_seed_from_state(state),
    }
  end

  def normalized_now
    Time.now.utc.strftime('%Y-%m-%d %H:%M:%S UTC')
  end

  def new_event_payload(type, origin, channel, hash_seed)
    event_hash = Digest::SHA256.hexdigest(hash_seed)[0, 12]
    {
      hash: event_hash,
      type: type,
      timestamp: normalized_now,
      origin: origin,
      channel: channel,
    }
  end

  def new_ai_insight_payload(text, origin = 'ui_simulator_ai')
    {
      text: text,
      timestamp: normalized_now,
      type: 'ui_insight',
      origin: origin,
    }
  end

  def new_chat_message_payload(text, origin = 'ui_simulator_chat', channel = 'global')
    {
      hash: Digest::SHA256.hexdigest("#{origin}|#{channel}|#{text}|#{Time.now.utc.to_f}")[0, 12],
      origin: origin,
      channel: channel,
      text: text,
      timestamp: normalized_now,
    }
  end

  def update_recent_events(state, event)
    list = Array(state[:recent_events]).map(&:dup)
    list.unshift(event)
    state[:recent_events] = list.first(5)

    latest = state[:recent_events].first
    state[:recent_event_hash] = latest[:hash]
    state[:last_event_hash] = latest[:hash]
    state[:event_type] = latest[:type]
    state[:event_timestamp] = latest[:timestamp]
    state[:event_origin] = latest[:origin]
    state[:event_channel] = latest[:channel]
    state[:last_sync] = latest[:timestamp]
  end

  def update_recent_ai_insights(state, insight)
    list = Array(state[:recent_ai_insights]).map(&:dup)
    list.unshift(insight)
    state[:recent_ai_insights] = list.first(3)

    latest = state[:recent_ai_insights]&.first
    return unless latest

    state[:ai_last_insight] = latest[:text]
  end

  def update_recent_chat_messages(state, chat_message)
    list = Array(state[:recent_chat_messages]).map(&:dup)
    list.unshift(chat_message)
    state[:recent_chat_messages] = list.first(5)
  end

  def flow_candidates_from_event(event, index)
    {
      kind: 'event',
      origin: event[:origin] || event['origin'] || 'unknown',
      summary: event[:type] || event['type'] || 'event',
      timestamp: event[:timestamp] || event['timestamp'] || 'n/a',
      hash: event[:hash] || event['hash'] || event[:event_hash] || event['event_hash'],
      channel: event[:channel] || event['channel'] || event[:event_channel] || event['event_channel'],
      _time: parse_flow_timestamp(event[:timestamp] || event['timestamp']),
      _rank: 0,
      _index: index,
    }
  end

  def flow_candidates_from_ai(insight, index)
    {
      kind: 'ai',
      origin: insight[:origin] || insight['origin'] || 'ui_simulator_ai',
      summary: insight[:text] || insight['text'] || 'AI insight',
      timestamp: insight[:timestamp] || insight['timestamp'] || 'n/a',
      hash: insight[:hash] || insight['hash'],
      channel: insight[:type] || insight['type'] || 'ui_insight',
      _time: parse_flow_timestamp(insight[:timestamp] || insight['timestamp']),
      _rank: 1,
      _index: index,
    }
  end

  def flow_candidates_from_chat(message, index)
    {
      kind: 'chat',
      origin: message[:origin] || message['origin'] || 'ui_simulator_chat',
      summary: message[:text] || message['text'] || '(empty)',
      timestamp: message[:timestamp] || message['timestamp'] || 'n/a',
      hash: message[:hash] || message['hash'],
      channel: message[:channel] || message['channel'] || 'global',
      _time: parse_flow_timestamp(message[:timestamp] || message['timestamp']),
      _rank: 2,
      _index: index,
    }
  end

  def parse_flow_timestamp(raw_timestamp)
    return raw_timestamp.to_i if raw_timestamp.is_a?(Integer)
    return raw_timestamp.to_f if raw_timestamp.is_a?(Float)

    text = raw_timestamp.to_s
    stripped = text.strip
    return stripped.to_i if stripped =~ /\A\d+\z/

    begin
      Time.parse(stripped).to_i
    rescue StandardError
      0
    end
  end

  def build_live_flow(state)
    events = Array(state[:recent_events] || []).each_with_index.map { |event, index| flow_candidates_from_event(event, index) }
    insights = Array(state[:recent_ai_insights] || []).each_with_index.map { |insight, index| flow_candidates_from_ai(insight, index) }
    messages = Array(state[:recent_chat_messages] || []).each_with_index.map { |message, index| flow_candidates_from_chat(message, index) }

    candidates = (events + insights + messages).sort_by { |item| [-item[:_time], item[:_rank], item[:_index]] }
    candidates.first(5).map do |item|
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
end

post '/api/simulate' do
  content_type :json

  payload = request.body.read
  if payload.empty?
    data = {}
  else
    begin
      data = JSON.parse(payload)
    rescue JSON::ParserError
      halt 400, { error: 'invalid_json' }.to_json
    end
  end
  action = data['action'].to_s

  state = settings.state
  state[:event_counter] ||= 0
  state[:event_counter] += 1
  network_cause = nil

  case action
  when 'event'
    update_recent_events(
      state,
      new_event_payload(
        'ui_event',
        'cli_simulator',
        'ui',
        "event-#{state[:event_counter]}-#{state[:last_sync]}",
      ),
    )
    state[:system_status] = 'event_processed'
    state[:recent_flow] = build_live_flow(state)
  when 'peer_join'
    network_cause = 'peer joined'
    state[:peers_count] = state[:peers_count].to_i + 1
    update_recent_events(
      state,
      new_event_payload(
        'peer_join',
        'ui_simulator_peer',
        'control',
        "peer-#{state[:event_counter]}-#{state[:peers_count]}",
      ),
    )
    state[:system_status] = 'peer_joined'
    state[:recent_flow] = build_live_flow(state)
  when 'relay_toggle'
    network_cause = 'relay path changed'
    state[:relay_enabled] = !state[:relay_enabled]
    state[:relay_status] = state[:relay_enabled] ? 'sync-bridge online' : 'sync-bridge disabled'
    update_recent_events(
      state,
      new_event_payload(
        'relay_toggle',
        'ui_simulator_relay',
        'control',
        "relay-#{state[:event_counter]}-#{state[:relay_status]}",
      ),
    )
    state[:recent_flow] = build_live_flow(state)
  when 'ai_insight'
    state[:ai_last_insight] = settings.insights[state[:event_counter] % settings.insights.length]
    update_recent_ai_insights(
      state,
      new_ai_insight_payload(
        state[:ai_last_insight],
        'ui_simulator_ai',
      ),
    )
    update_recent_events(
      state,
      new_event_payload(
        'ai_insight',
        'ui_simulator_ai',
        'ai',
        "insight-#{state[:event_counter]}-#{state[:ai_last_insight]}",
      ),
    )
    state[:system_status] = 'insight_generated'
    state[:recent_flow] = build_live_flow(state)
  when 'chat_message'
    text = data['text'].to_s
    if text.bytesize > 32
      halt 400, { error: 'chat_message_too_long', max_bytes: 32 }.to_json
    end

    update_recent_chat_messages(
      state,
      new_chat_message_payload(
        text,
        data['origin'] || 'ui_simulator_chat',
        data['channel'] || 'global',
      ),
    )
    update_recent_events(
      state,
      new_event_payload(
        'chat_message',
        data['origin'] || 'ui_simulator_chat',
        data['channel'] || 'global',
        "chat-msg-#{state[:event_counter]}-#{text}",
      ),
    )
    state[:system_status] = 'chat_message_sent'
    state[:recent_flow] = build_live_flow(state)
  else
    halt 400, { error: 'unknown action' }.to_json
  end

  content_type :json
  settings.ui_mode = :demo
  to_payload(
    state.reject { |k, _v| k == :event_counter },
    'fallback_simulated',
    network_cause: network_cause,
  ).to_json
end

get '/' do
  settings.ui_mode = :live
  @state, @data_source, @source_type, @adapter_status = current_status_state
  @cards = CARD_DEFS
  @seed = motion_seed_from_state(@state, @cards.length)

  @health = health_payload(@state, @data_source, @source_type, @adapter_status)
  @health[:source_type] = @source_type

  erb :index
end

get '/api/status' do
  content_type :json
  settings.ui_mode = :live
  state, source, source_type, adapter_status = current_status_state
  to_payload(state, source).to_json
end

get '/api/health' do
  content_type :json
  if settings.ui_mode == :demo
    state = settings.state
    health = health_payload(
      state,
      'fallback_simulated',
      'demo',
      'manual_demo_override',
    )
    return health.to_json
  end

  state, source, source_type, adapter_status = current_status_state
  health_payload(state, source, source_type, adapter_status).to_json
end
