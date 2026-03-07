require 'sinatra'
require 'json'
require 'digest'

set :public_folder, File.join(__dir__, 'public')
set :views, File.join(__dir__, 'views')

configure do
  set :bind, '0.0.0.0'
  set :port, 4567
end

helpers do
  def current_state
    {
      system_status: 'operational',
      peers_count: 8,
      relay_status: 'sync-bridge online',
      ai_last_insight: 'No anomaly patterns observed in this window.',
      recent_event_hash: 'bf5cfda1e218837d2f8a597f8011b4096',
      last_sync: Time.now.utc.strftime('%Y-%m-%d %H:%M:%S UTC'),
    }
  end

  def motion_seed_from_state(state)
    payload = state.values.join('|')
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

get '/' do
  @state = current_state
  @seed = motion_seed_from_state(@state)
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
  status = current_state

  {
    state: status,
    seed: motion_seed_from_state(status),
    last_updated: Time.now.utc.strftime('%Y-%m-%d %H:%M:%S UTC')
  }.to_json
end
