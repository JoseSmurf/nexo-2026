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

set :state, CoreAdapter::FALLBACK_STATE.merge(event_counter: 0).dup

set :insights, [
  'No anomaly patterns observed in this window.',
  'Unusual cluster of repeated low-risk events detected.',
  'Potential drift spike in network packet timing observed.',
  'AI baseline stable; no intervention needed.',
]

set :ui_mode, :live

helpers do
  def motion_seed_from_state(state)
    seed_size = 6
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

    {
      ui_status: ui_status,
      data_source: source,
      source_type: source_type,
      adapter_status: adapter_status,
      last_updated: Time.now.utc.strftime('%Y-%m-%d %H:%M:%S UTC'),
      seed: motion_seed_from_state(state),
    }
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
    state[:recent_event_hash] = Digest::SHA256.hexdigest("event-#{state[:event_counter]}-#{state[:last_sync]}")[0, 12]
    state[:system_status] = 'event_processed'
    state[:last_sync] = Time.now.utc.strftime('%Y-%m-%d %H:%M:%S UTC')
  when 'peer_join'
    state[:peers_count] = state[:peers_count].to_i + 1
    state[:system_status] = 'peer_joined'
    state[:last_sync] = Time.now.utc.strftime('%Y-%m-%d %H:%M:%S UTC')
  when 'relay_toggle'
    state[:relay_enabled] = !state[:relay_enabled]
    state[:relay_status] = state[:relay_enabled] ? 'sync-bridge online' : 'sync-bridge disabled'
    state[:last_sync] = Time.now.utc.strftime('%Y-%m-%d %H:%M:%S UTC')
  when 'ai_insight'
    state[:ai_last_insight] = settings.insights[state[:event_counter] % settings.insights.length]
    state[:system_status] = 'insight_generated'
    state[:last_sync] = Time.now.utc.strftime('%Y-%m-%d %H:%M:%S UTC')
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
