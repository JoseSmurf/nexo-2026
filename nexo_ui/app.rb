require 'sinatra'
require 'json'
require 'digest'

set :public_folder, File.join(__dir__, 'public')
set :views, File.join(__dir__, 'views')

configure do
  set :bind, '0.0.0.0'
  set :port, 4567
end

set :state, {
  system_status: 'operational',
  peers_count: 8,
  relay_status: 'sync-bridge online',
  ai_last_insight: 'No anomaly patterns observed in this window.',
  recent_event_hash: 'bf5cfda1e218837d2f8a597f8011b4096',
  relay_enabled: true,
  last_sync: Time.now.utc.strftime('%Y-%m-%d %H:%M:%S UTC'),
  event_counter: 0,
}

set :insights, [
  'No anomaly patterns observed in this window.',
  'Unusual cluster of repeated low-risk events detected.',
  'Potential drift spike in network packet timing observed.',
  'AI baseline stable; no intervention needed.',
]

set :random_proxy, ['00', 'aa', 'f0', '12', '9c', '7e', '31', '48', 'c3', '55']

helpers do
  def current_state
    settings.state.dup
  end

  def state_payload
    state = current_state
    {
      state: state.reject { |k, _v| k == :event_counter },
      seed: motion_seed_from_state(state),
      last_updated: Time.now.utc.strftime('%Y-%m-%d %H:%M:%S UTC'),
    }
  end

  def next_hash(seed)
    digest = Digest::SHA256.hexdigest(seed)
    "#{digest[0, 12]}"
  end

  def motion_seed_from_state(state)
    payload = state.to_a.reject { |kv| kv.first == :event_counter }.map { |kv| kv.last.to_s }.join('|')
    digest = Digest::SHA256.digest(payload)

    5.times.map do |i|
      {
        drift_x: digest.getbyte(i) % 8,
        drift_y: digest.getbyte(i + 5) % 8,
        opacity: (65 + (digest.getbyte(i + 10) % 25)) / 100.0,
        flicker: 0.8 + (digest.getbyte(i + 15) % 20) / 10.0,
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

  case action
  when 'event'
    state[:recent_event_hash] = next_hash("event-#{state[:event_counter]}-#{state[:last_sync]}")
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

  state_payload.to_json
end

get '/' do
  @state = current_state
  @state = @state.reject { |k, _v| k == :event_counter }
  @seed = motion_seed_from_state(settings.state)
  @cards = [
    { name: 'Core', key: :system_status, tone: 'core' },
    { name: 'Network', key: :peers_count, tone: 'network', label: 'Peers' },
    { name: 'Relay', key: :relay_status, tone: 'relay' },
    { name: 'AI', key: :ai_last_insight, tone: 'ai' },
    { name: 'Hash Pulse', key: :recent_event_hash, tone: 'hash', mono: true },
  ]

  erb :index
end

get '/api/status' do
  content_type :json
  state_payload.to_json
end
