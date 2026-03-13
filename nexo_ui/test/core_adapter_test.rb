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

  # Contract: when source is :core, first-order core fields are verbatim read-only.
  # UI-derived fields (latest_change_* and write_status family) may only be filled
  # by explicit core values or the documented derivation fallback path.
  def test_core_mode_contract_prevents_core_semantic_reinterpretation
    core_payload = {
      'system_status' => 'operational',
      'peers_count' => 11,
      'relay_status' => 'relay mesh online',
      'network_mode' => 'mesh',
      'mesh_status' => 'stable',
      'ai_last_insight' => 'Operator flow steady across window.',
      'recent_event_hash' => 'core-event-hash',
      'last_sync' => '2026-03-13 12:00:00 UTC',
      'last_event_hash' => 'explicit-last-event',
      'event_type' => 'system_event:blocked',
      'event_timestamp' => '2026-03-13 11:55:00 UTC',
      'event_origin' => 'core_engine',
      'event_channel' => 'system',
      'chat_send_available' => false,
      'chat_send_mode' => 'core_unavailable',
      'chat_send_reason' => 'policy denies writes',
      'recent_events' => [
        {
          'hash' => 'core-event-1',
          'type' => 'system_event:blocked',
          'timestamp' => '2026-03-13 11:55:00 UTC',
          'origin' => 'core_engine',
          'channel' => 'system',
        },
      ],
      'recent_ai_insights' => [
        {
          'text' => 'passive control update.',
          'timestamp' => '2026-03-13 11:54:00 UTC',
          'type' => 'observation',
          'origin' => 'core_system',
        },
      ],
      'recent_chat_messages' => [
        {
          'hash' => 'core-chat-1',
          'origin' => 'node-b',
          'channel' => 'global',
          'text' => 'core chat sample',
          'timestamp' => '2026-03-13 11:53:00 UTC',
        },
      ],
      'recent_flow' => [
        {
          'kind' => 'event',
          'origin' => 'core_engine',
          'summary' => 'blocked decision',
          'timestamp' => '2026-03-13 11:55:00 UTC',
          'hash' => 'core-flow-evt',
          'channel' => 'system',
        },
        {
          'kind' => 'chat',
          'origin' => 'ui_dashboard',
          'summary' => 'operator message',
          'timestamp' => '2026-03-13 11:56:00 UTC',
          'hash' => 'core-flow-chat',
          'channel' => 'global',
        },
      ],
      'latest_change_source' => 'core_decision',
      'latest_change_kind' => 'event',
      'latest_change_summary' => 'core explicit latest',
      'latest_change_origin' => 'core_engine',
      'latest_change_timestamp' => '2026-03-13 11:57:00 UTC',
      'latest_change_channel' => 'system',
    }

    state = CoreAdapter.normalize(core_payload, source: :core)

    core_verbatim_fields = {
      system_status: 'operational',
      peers_count: 11,
      relay_status: 'relay mesh online',
      network_mode: 'mesh',
      mesh_status: 'stable',
      ai_last_insight: 'Operator flow steady across window.',
      recent_event_hash: 'core-event-hash',
      last_sync: '2026-03-13 12:00:00 UTC',
      chat_send_available: false,
      chat_send_mode: 'core_unavailable',
      chat_send_reason: 'policy denies writes',
    }

    core_verbatim_fields.each do |key, value|
      assert_equal(value, state[key], "core-verbatim field was mutated: #{key}")
    end

    # recent_flow should be preserved from core (validated/canonicalized, not rebuilt from events/insights/chat in core mode).
    assert_equal([
      {
        kind: 'event',
        origin: 'core_engine',
        summary: 'blocked decision',
        timestamp: '2026-03-13 11:55:00 UTC',
        hash: 'core-flow-evt',
        channel: 'system',
      },
      {
        kind: 'chat',
        origin: 'ui_dashboard',
        summary: 'operator message',
        timestamp: '2026-03-13 11:56:00 UTC',
        hash: 'core-flow-chat',
        channel: 'global',
      },
    ], state[:recent_flow])

    # Core may provide only latest_change_source explicitly in this adapter contract;
    # the rest follows the documented derivation path from recent_flow.
    assert_equal('core_decision', state[:latest_change_source])
    assert_equal('event', state[:latest_change_kind])
    assert_equal('blocked decision', state[:latest_change_summary])
    assert_equal('core_engine', state[:latest_change_origin])
    assert_equal('2026-03-13 11:55:00 UTC', state[:latest_change_timestamp])
    assert_equal('system', state[:latest_change_channel])
  end
end
