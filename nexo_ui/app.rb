require 'sinatra'
require 'digest'

set :public_folder, File.join(__dir__, 'public')
set :views, File.join(__dir__, 'views')

configure do
  set :bind, '0.0.0.0'
  set :port, 4567
end

get '/' do
  system_status = 'operational'
  peers_count = 8
  relay_status = 'sync-bridge online'
  ai_last_insight = 'No anomaly patterns observed this window.'
  recent_event_hash = 'bf5cfda1e218837d2f8a597f8011b4096'
  last_sync = (Time.now.utc - (Time.now.to_i % 300)).utc.strftime('%Y-%m-%d %H:%M:%S UTC')

  state = {
    system_status: system_status,
    peers_count: peers_count,
    relay_status: relay_status,
    ai_last_insight: ai_last_insight,
    recent_event_hash: recent_event_hash,
    last_sync: last_sync,
  }

  motion_seed = motion_seed_from_state(state)
  cards = [
    { name: 'Core', value: system_status, tone: 'core' },
    { name: 'Network', value: "Peers: #{peers_count}", tone: 'network' },
    { name: 'Relay', value: relay_status, tone: 'relay' },
    { name: 'AI', value: ai_last_insight, tone: 'ai' },
    { name: 'Hash Pulse', value: recent_event_hash, tone: 'hash' },
  ]

  @viewport = {
    cards: cards,
    last_sync: last_sync,
    state: state,
    seed: motion_seed,
  }

  erb :index
end

def motion_seed_from_state(state)
  payload = state.values.join('|')
  digest = Digest::SHA256.digest(payload)

  5.times.map do |i|
    {
      drift_x: digest.getbyte(i) % 8,
      drift_y: digest.getbyte(i + 5) % 8,
      opacity: 0.65 + (digest.getbyte(i + 10) % 16) / 100.0,
      flicker: (digest.getbyte(i + 15) % 14) / 10.0,
    }
  end
end
