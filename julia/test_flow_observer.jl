using Test
using JSON3

include("flow_observer.jl")

function sample_state(; flow_items, latest_change_source="passive_observation", write_status="read_only", timestamp=1_771_000_000_123)
    return JSON3.read(
        JSON3.write(
            Dict(
                "recent_flow" => flow_items,
                "latest_change_source" => latest_change_source,
                "write_status" => write_status,
                "timestamp" => timestamp,
            ),
        ),
    )
end

@testset "Flow observer" begin
    @testset "counts flow kinds and sources deterministically" begin
        state = sample_state(
            flow_items = [
                Dict("kind" => "chat", "origin" => "ui_dashboard", "summary" => "hello"),
                Dict("kind" => "event", "origin" => "core_engine", "summary" => "approved decision"),
                Dict("kind" => "ai", "origin" => "audit_observer", "summary" => "No anomaly patterns observed in this window."),
            ],
            latest_change_source = "operator_action",
            write_status = "writable",
        )

        obs = observe_state(state)
        @test obs.total_items == 3
        @test obs.kind_counts["chat"] == 1
        @test obs.kind_counts["event"] == 1
        @test obs.kind_counts["ai"] == 1
        @test obs.source_counts["operator_action"] == 1
        @test obs.source_counts["core_decision"] == 1
        @test obs.source_counts["passive_observation"] == 1
        @test obs.source_ratios["operator_action"] == 0.3333
        @test obs.intensity == "normal"
        @test obs.latest_change_source == "operator_action"
        @test obs.write_status == "writable"
    end

    @testset "classifies elevated operator activity" begin
        state = sample_state(
            flow_items = [
                Dict("kind" => "chat", "origin" => "ui_dashboard", "summary" => "a"),
                Dict("kind" => "chat", "origin" => "ui_dashboard", "summary" => "b"),
                Dict("kind" => "chat", "origin" => "ui_dashboard", "summary" => "c"),
                Dict("kind" => "event", "origin" => "core_engine", "summary" => "approved decision"),
                Dict("kind" => "ai", "origin" => "audit_observer", "summary" => "No anomaly patterns observed in this window."),
            ],
            latest_change_source = "operator_action",
        )

        obs = observe_state(state)
        @test obs.intensity == "elevated"
        @test obs.dominant_source == "operator_action"
        @test obs.summary == "operator-driven activity is elevated in the current window"
    end

    @testset "classifies passive observation when no decision or operator action dominates" begin
        state = sample_state(
            flow_items = [
                Dict("kind" => "chat", "origin" => "peer_node", "summary" => "peer hello"),
                Dict("kind" => "ai", "origin" => "audit_observer", "summary" => "No anomaly patterns observed in this window."),
            ],
            latest_change_source = "passive_observation",
        )

        obs = observe_state(state)
        @test obs.source_counts["passive_observation"] == 2
        @test obs.dominant_source == "passive_observation"
        @test obs.summary == "system stable in current window"
    end

    @testset "identical input yields identical output" begin
        state = sample_state(
            flow_items = [
                Dict("kind" => "event", "origin" => "core_engine", "summary" => "blocked decision"),
                Dict("kind" => "ai", "origin" => "audit_observer", "summary" => "No anomaly patterns observed in this window."),
            ],
            latest_change_source = "core_decision",
        )

        obs_a = observe_state(state)
        obs_b = observe_state(state)
        @test obs_a == obs_b
    end

    @testset "builds deterministic observation artifact" begin
        state = sample_state(
            flow_items = [
                Dict("kind" => "chat", "origin" => "ui_dashboard", "summary" => "hello"),
                Dict("kind" => "event", "origin" => "core_engine", "summary" => "approved decision"),
            ],
            latest_change_source = "operator_action",
            timestamp = 1_234_567_890,
        )

        artifact = observation_artifact(state)
        @test artifact.timestamp == 1_234_567_890
        @test artifact.flow_counts == (event = 1, chat = 1, ai = 0)
        @test artifact.source_mix == (
            operator_action = 0.5,
            core_decision = 0.5,
            passive_observation = 0.0,
        )
        @test artifact.dominant_source == "operator_action"
        @test artifact.dominant_kind == "event"
        @test artifact.flow_intensity == "normal"
        @test artifact.summary == "operator-driven activity dominates the current window"
    end

    @testset "writes stable JSON artifact" begin
        state = sample_state(
            flow_items = [
                Dict("kind" => "ai", "origin" => "audit_observer", "summary" => "No anomaly patterns observed in this window."),
                Dict("kind" => "chat", "origin" => "peer_node", "summary" => "peer hello"),
            ],
            latest_change_source = "passive_observation",
            timestamp = 999,
        )

        path = tempname()
        try
            artifact = write_observation_artifact(state, path)
            json = read(path, String)
            @test artifact.timestamp == 999
            @test json == "{\"timestamp\":999,\"flow_counts\":{\"event\":0,\"chat\":1,\"ai\":1},\"source_mix\":{\"operator_action\":0.0,\"core_decision\":0.0,\"passive_observation\":1.0},\"dominant_source\":\"passive_observation\",\"dominant_kind\":\"chat\",\"flow_intensity\":\"normal\",\"summary\":\"system stable in current window\"}"
        finally
            rm(path; force=true)
        end
    end

    @testset "empty flow stays explicit" begin
        state = sample_state(flow_items = Any[], latest_change_source = "", write_status = "read_only")
        obs = observe_state(state)
        @test obs.total_items == 0
        @test obs.intensity == "low"
        @test obs.summary == "no recent flow observed"
        @test obs.dominant_source == ""
    end
end
