require 'sinatra'
require 'json'
require 'digest'
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

helpers do
  def motion_seed_from_state(state)
    seed_size = 7
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

  def to_payload(state, source)
    {
      state: state,
      seed: motion_seed_from_state(state),
      last_updated: Time.now.utc.strftime('%Y-%m-%d %H:%M:%S UTC'),
      data_source: source,
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
  when 'peer_join'
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
  when 'relay_toggle'
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
  else
    halt 400, { error: 'unknown action' }.to_json
  end

  content_type :json
  settings.ui_mode = :demo
  to_payload(
    state.reject { |k, _v| k == :event_counter },
    'fallback_simulated',
  ).to_json
end

get '/' do
  settings.ui_mode = :live
  @state, @data_source, @source_type, @adapter_status = current_status_state
  @seed = motion_seed_from_state(@state)
  @cards = [
    { name: 'Core', key: :system_status, tone: 'core' },
    { name: 'Network', key: :peers_count, tone: 'network', label: 'Peers' },
    { name: 'Relay', key: :relay_status, tone: 'relay' },
    { name: 'AI', key: :ai_last_insight, tone: 'ai' },
    { name: 'Hash Pulse', key: :recent_event_hash, tone: 'hash', mono: true },
    { name: 'Events', key: :events, tone: :events, mono: true },
    { name: 'Integrity', key: :health, tone: 'health', mono: true },
  ]

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
