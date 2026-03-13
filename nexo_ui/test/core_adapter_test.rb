# frozen_string_literal: true

require 'minitest/autorun'
require_relative '../core_adapter'

class CoreAdapterBoundaryTest < Minitest::Test
  def test_core_state_payload_is_passed_through
    core_payload = {
      'system_status' => 'operational',
      'peers_count' => 7,
      'relay_status' => 'edge relay online',
      'network_mode' => 'hybrid',
      'mesh_status' => 'unstable',
      'ai_last_insight' => 'Core stream shows elevated ai confidence.',
      'recent_event_hash' => 'core-hash-01',
      'last_sync' => '2026-03-13 12:00:00 UTC',
      'last_event_hash' => 'event-hash-01',
      'event_type' => 'system_event:approved',
      'event_timestamp' => '2026-03-13 12:00:00 UTC',
      'event_origin' => 'core_engine',
      'event_channel' => 'system',
      'latest_change_source' => 'core_decision',
      'latest_change_kind' => 'event',
      'latest_change_summary' => 'approved decision',
      'latest_change_origin' => 'core_engine',
      'latest_change_timestamp' => '2026-03-13 12:00:00 UTC',
      'latest_change_channel' => 'system',
      'recent_events' => [
        {
          'hash' => 'event-1',
          'type' => 'system_event:approved',
          'timestamp' => '2026-03-13 12:00:00 UTC',
          'origin' => 'core_engine',
          'channel' => 'system',
        },
      ],
      'recent_ai_insights' => [
        {
          'text' => 'No anomaly patterns observed in this window.',
          'timestamp' => '2026-03-13 11:59:00 UTC',
          'type' => 'bootstrap',
          'origin' => 'core_engine',
        },
      ],
      'recent_chat_messages' => [
        {
          'hash' => 'chat-1',
          'origin' => 'node-a',
          'channel' => 'global',
          'text' => 'hello from core',
          'timestamp' => '2026-03-13 11:58:00 UTC',
        },
      ],
      'recent_flow' => [
        {
          'kind' => 'event',
          'origin' => 'core_engine',
          'summary' => 'approved decision',
          'timestamp' => '2026-03-13 12:00:00 UTC',
          'hash' => 'flow-event-1',
          'channel' => 'system',
        },
        {
          'kind' => 'chat',
          'origin' => 'ui_dashboard',
          'summary' => 'hello message sent',
          'timestamp' => '2026-03-13 11:58:30 UTC',
          'hash' => 'flow-chat-1',
          'channel' => 'global',
        },
      ],
    }

    state = CoreAdapter.normalize(core_payload, source: :core)

    assert_equal('operational', state[:system_status])
    assert_equal(7, state[:peers_count])
    assert_equal('edge relay online', state[:relay_status])
    assert_equal('hybrid', state[:network_mode])
    assert_equal('unstable', state[:mesh_status])
    assert_equal('Core stream shows elevated ai confidence.', state[:ai_last_insight])
    assert_equal('core-hash-01', state[:recent_event_hash])
    assert_equal('2026-03-13 12:00:00 UTC', state[:last_sync])

    assert_equal(1, state[:recent_events].length)
    assert_equal('event-1', state[:recent_events].first[:hash])

    assert_equal(1, state[:recent_ai_insights].length)
    assert_equal('No anomaly patterns observed in this window.', state[:recent_ai_insights].first[:text])

    assert_equal(1, state[:recent_chat_messages].length)
    assert_equal('chat-1', state[:recent_chat_messages].first[:hash])

    assert_equal(2, state[:recent_flow].length)
    assert_equal('event', state[:recent_flow].first[:kind])
    assert_equal('flow-event-1', state[:recent_flow].first[:hash])

    # Core-supplied latest_change_source must be preserved when present.
    assert_equal('core_decision', state[:latest_change_source])
    assert_equal('event', state[:latest_change_kind])
    assert_equal('approved decision', state[:latest_change_summary])
    assert_equal('core_engine', state[:latest_change_origin])
  end

  def test_core_missing_fields_do_not_trigger_fallback
    core_payload = {
      'system_status' => 'operational',
      'peers_count' => 3,
      'relay_status' => 'relay offline',
    }

    state = CoreAdapter.normalize(core_payload, source: :core)

    assert_equal([], state[:recent_events])
    assert_equal([], state[:recent_ai_insights])
    assert_equal([], state[:recent_chat_messages])
    assert_equal([], state[:recent_flow])
    assert_equal('', state[:latest_change_source].to_s)
  end

  def test_non_core_missing_events_are_fallback_and_not_mutated
    file_payload = {
      'system_status' => 'fallback_from_file',
    }

    state = CoreAdapter.normalize(file_payload, source: :file)

    assert_equal('fallback_from_file', state[:system_status])
    assert_equal(3, state[:recent_events].length)
    assert_includes(state[:recent_events].map { |item| item[:origin] }, 'relay')
    assert_equal(2, state[:recent_ai_insights].length)
    assert_equal(2, state[:recent_chat_messages].length)
    assert_equal(5, state[:recent_flow].length)
  end

  def test_file_trace_fields_are_only_secondary_derived_fields_not_rewritten_core_fields
    file_payload = {
      'system_status' => 'operational',
      'recent_flow' => [
        {
          'kind' => 'chat',
          'origin' => 'ui_dashboard',
          'summary' => 'manual review message',
          'timestamp' => '2026-03-13 12:00:00 UTC',
          'hash' => 'chat-flow',
          'channel' => 'global',
        },
      ],
    }

    state = CoreAdapter.normalize(file_payload, source: :file)

    # latest_change_* come from canonical flow synthesis when no core explicit source
    assert_equal('chat', state[:latest_change_kind])
    assert_equal('manual review message', state[:latest_change_summary])
    assert_equal('ui_dashboard', state[:latest_change_origin])
    assert_equal('global', state[:latest_change_channel])

    # latest_change_source is only auto-derived when not explicitly supplied.
    assert_equal('operator_action', state[:latest_change_source])
  end
end
