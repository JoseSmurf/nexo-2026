using JSON3

include("residual_signal_classifier.jl")

function residual_samples_fixture()
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

function main()
    output_path = length(ARGS) >= 1 ? ARGS[1] : "artifacts/residual_signal_classifier/generated_from_julia.json"
    mkpath(dirname(output_path))

    artifact = write_residual_signal_artifact(residual_samples_fixture(), output_path)
    println("residual_signal_classifier artifact written: $(output_path)")
    println(
        "schema_version=$(artifact.schema_version) classifier_version=$(artifact.classifier_version) total_samples=$(artifact.summary.total_samples)",
    )
end

main()
