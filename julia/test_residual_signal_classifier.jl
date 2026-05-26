using Test
using JSON3

include("residual_signal_classifier.jl")

function _residual_samples_fixture()
    return [
        Dict(
            "node_id" => "node-a",
            "network_type" => "wifi",
            "timestamp_utc_ms" => 1_772_000_000_100,
            "rtt_ms" => 35.0,
            "jitter_ms" => 5.0,
            "loss_pct" => 0.2,
            "retransmission_pct" => 0.5,
            "handoff_count" => 0,
        ),
        Dict(
            "node_id" => "node-b",
            "network_type" => "cellular",
            "timestamp_utc_ms" => 1_772_000_000_300,
            "rtt_ms" => 180.0,
            "jitter_ms" => 45.0,
            "loss_pct" => 3.4,
            "retransmission_pct" => 4.8,
            "handoff_count" => 3,
        ),
        Dict(
            "node_id" => "node-c",
            "network_type" => "wifi",
            "timestamp_utc_ms" => 1_772_000_000_200,
            "rtt_ms" => 80.0,
            "jitter_ms" => 15.0,
            "loss_pct" => 1.2,
            "retransmission_pct" => 1.7,
            "handoff_count" => 1,
        ),
        Dict(
            "node_id" => "node-d",
            "network_type" => "ethernet",
            "timestamp_utc_ms" => 1_772_000_000_000,
            "rtt_ms" => 25.0,
            "jitter_ms" => 2.0,
            "loss_pct" => 0.0,
            "retransmission_pct" => 0.0,
            "handoff_count" => 0,
        ),
    ]
end

@testset "Residual signal classifier" begin
    @testset "normalizes and classifies deterministically" begin
        records = _residual_samples_fixture()
        artifact_a = classify_residual_signals(records)
        artifact_b = classify_residual_signals(reverse(records))

        @test artifact_a == artifact_b
        @test artifact_a.schema_version == RESIDUAL_SIGNAL_SCHEMA_VERSION
        @test artifact_a.classifier_version == RESIDUAL_SIGNAL_CLASSIFIER_VERSION
        @test artifact_a.generated_at_ts_ms == 1_772_000_000_300
        @test artifact_a.feature_order == collect(RESIDUAL_FEATURE_ORDER)
        @test artifact_a.summary.total_samples == 4
        @test artifact_a.summary.retained_samples + artifact_a.summary.discarded_samples == 4
        @test artifact_a.summary.is_runtime_authority == false
        @test artifact_a.summary.is_global_truth == false
    end

    @testset "fails closed on invalid residual fields" begin
        malformed = copy(_residual_samples_fixture())
        malformed[1]["loss_pct"] = -0.1
        @test_throws ArgumentError classify_residual_signals(malformed)

        malformed2 = copy(_residual_samples_fixture())
        malformed2[2]["network_type"] = "satellite"
        @test_throws ArgumentError classify_residual_signals(malformed2)
    end

    @testset "writes stable artifact contract JSON" begin
        path = tempname()
        try
            artifact = write_residual_signal_artifact(_residual_samples_fixture(), path)
            body = read(path, String)
            parsed = JSON3.read(body)

            @test hasproperty(parsed, :schema_version)
            @test String(parsed.schema_version) == RESIDUAL_SIGNAL_SCHEMA_VERSION
            @test hasproperty(parsed, :samples)
            @test length(parsed.samples) == artifact.summary.total_samples
            @test parsed.summary.total_samples == 4
        finally
            rm(path; force=true)
        end
    end
end
