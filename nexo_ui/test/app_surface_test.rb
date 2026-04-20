# frozen_string_literal: true

ENV['RACK_ENV'] = 'test'
ENV['NEXO_CORE_STATE_URL'] = ''
ENV['NEXO_UI_STATE_PATH'] = File.join(Dir.pwd, 'tmp', 'missing_nexo_ui_state.json')
ENV['NEXO_UI_SQLITE_PATH'] = File.join(Dir.pwd, 'tmp', 'missing_nexo_ui_state.db')

require 'json'
require 'minitest/autorun'
require 'rack/mock'
require_relative '../app'

class AppSurfaceTest < Minitest::Test
  def request(path)
    Rack::MockRequest.new(Sinatra::Application).get(path)
  end

  def test_root_surface_keeps_core_first_hierarchy_and_non_claims
    response = request('/')

    assert_equal(200, response.status)
    body = response.body

    assert_includes(body, 'Primary/Core Surface')
    assert_includes(body, 'Final Decision (Primary)')
    assert_includes(body, 'Secondary/Context Surface')
    assert_includes(body, 'Not runtime authority')
    assert_includes(body, 'Not global truth')
    assert_includes(body, 'Not automatic sync decision')
  end

  def test_status_payload_contains_contract_keys_used_by_v0_surface
    response = request('/api/status')

    assert_equal(200, response.status)
    payload = JSON.parse(response.body)
    state = payload.fetch('state')

    assert_kind_of(Hash, state)
    assert(payload.key?('data_source'))
    assert(payload.key?('source_type'))
    %w[
      system_status
      event_type
      last_event_hash
      recent_event_hash
      latest_change_kind
      latest_change_summary
      latest_change_origin
      latest_change_timestamp
    ].each do |key|
      assert(state.key?(key), "missing state key: #{key}")
    end
  end
end
