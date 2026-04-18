using Test
using JSON3

include("observe_sync_economics.jl")

function _sync_economics_sample_record(;
    schema_version::String="v1",
    scenario_id::String="comparable_equivalent_fresh",
    since_ts_ms::Int=100,
    until_ts_ms::Int=200,
    left_event_count::Int=4,
    right_event_count::Int=4,
    left_digest_bytes::Int=57,
    right_digest_bytes::Int=57,
    compared_digest_bytes_total::Int=114,
    estimated_bytes_per_event::Int=128,
    estimated_full_sync_bytes::Int=512,
    saved_bytes_if_sync_skipped::Int=398,
    comparability::String="Comparable",
    outcome::String="EquivalentLocalSlice",
    freshness=nothing,
    diagnostic_actionability::String="DiagnosticOnly",
    is_runtime_authority::Bool=false,
    is_global_truth::Bool=false,
    reason::String="diagnostic only",
)
    return Dict(
        "schema_version" => schema_version,
        "scenario_id" => scenario_id,
        "since_ts_ms" => since_ts_ms,
        "until_ts_ms" => until_ts_ms,
        "left_event_count" => left_event_count,
        "right_event_count" => right_event_count,
        "left_digest_bytes" => left_digest_bytes,
        "right_digest_bytes" => right_digest_bytes,
        "compared_digest_bytes_total" => compared_digest_bytes_total,
        "estimated_bytes_per_event" => estimated_bytes_per_event,
        "estimated_full_sync_bytes" => estimated_full_sync_bytes,
        "saved_bytes_if_sync_skipped" => saved_bytes_if_sync_skipped,
        "comparability" => comparability,
        "outcome" => outcome,
        "freshness" => freshness,
        "diagnostic_actionability" => diagnostic_actionability,
        "is_runtime_authority" => is_runtime_authority,
        "is_global_truth" => is_global_truth,
        "reason" => reason,
    )
end

function _write_jsonl(path::AbstractString, records::Vector{<:AbstractDict})
    open(path, "w") do io
        for record in records
            write(io, JSON3.write(record))
            write(io, "\n")
        end
    end
end

@testset "Sync economics observer" begin
    @testset "reads canonical JSONL artifact" begin
        dir = mktempdir()
        path = joinpath(dir, "two_snapshot_sync_economics.jsonl")
        _write_jsonl(
            path,
            [
                _sync_economics_sample_record(scenario_id="s1"),
                _sync_economics_sample_record(scenario_id="s2"),
            ],
        )

        records = read_two_snapshot_sync_economics_jsonl(path)
        @test length(records) == 2
        @test records[1].schema_version == "v1"
        @test records[2].scenario_id == "s2"

        rm(dir; recursive=true, force=true)
    end

    @testset "schema version validation fails closed" begin
        record = _sync_economics_sample_record(schema_version="v0")
        @test_throws ArgumentError normalize_two_snapshot_sync_economics_record(record)
    end

    @testset "missing required field fails closed in parser" begin
        dir = mktempdir()
        path = joinpath(dir, "two_snapshot_sync_economics_missing_required.jsonl")

        malformed = _sync_economics_sample_record()
        delete!(malformed, "outcome")
        _write_jsonl(path, [malformed])

        @test_throws ArgumentError read_two_snapshot_sync_economics_jsonl(path)

        rm(dir; recursive=true, force=true)
    end

    @testset "computes mean/median/percentiles deterministically" begin
        records = [
            normalize_two_snapshot_sync_economics_record(
                _sync_economics_sample_record(
                    scenario_id="s1",
                    compared_digest_bytes_total=100,
                    estimated_full_sync_bytes=200,
                    saved_bytes_if_sync_skipped=0,
                ),
            ),
            normalize_two_snapshot_sync_economics_record(
                _sync_economics_sample_record(
                    scenario_id="s2",
                    compared_digest_bytes_total=200,
                    estimated_full_sync_bytes=300,
                    saved_bytes_if_sync_skipped=10,
                ),
            ),
            normalize_two_snapshot_sync_economics_record(
                _sync_economics_sample_record(
                    scenario_id="s3",
                    compared_digest_bytes_total=300,
                    estimated_full_sync_bytes=400,
                    saved_bytes_if_sync_skipped=20,
                ),
            ),
        ]

        summary = build_two_snapshot_sync_economics_summary(records)
        @test summary.total_scenarios == 3
        @test summary.mean_compared_digest_bytes_total == 200.0
        @test summary.mean_estimated_full_sync_bytes == 300.0
        @test summary.mean_saved_bytes_if_sync_skipped == 10.0
        @test summary.median_saved_bytes_if_sync_skipped == 10.0
        @test summary.p50_saved_bytes_if_sync_skipped == 10
        @test summary.p95_saved_bytes_if_sync_skipped == 20
    end

    @testset "protects saved/full ratio from division by zero" begin
        @test safe_saved_full_ratio(5, 0) === nothing
        @test safe_saved_full_ratio(0, 0) === nothing
        @test safe_saved_full_ratio(5, 10) == 0.5

        records = [
            normalize_two_snapshot_sync_economics_record(
                _sync_economics_sample_record(
                    scenario_id="zero_full",
                    estimated_full_sync_bytes=0,
                    saved_bytes_if_sync_skipped=10,
                ),
            ),
            normalize_two_snapshot_sync_economics_record(
                _sync_economics_sample_record(
                    scenario_id="normal",
                    estimated_full_sync_bytes=200,
                    saved_bytes_if_sync_skipped=50,
                ),
            ),
        ]
        ratios = ratio_saved_full_by_scenario(records)
        @test ratios["zero_full"] === nothing
        @test ratios["normal"] == 0.25
    end

    @testset "groups by scenario and outcome and writes summary CSV" begin
        dir = mktempdir()
        input_path = joinpath(dir, "two_snapshot_sync_economics.jsonl")
        output_path = joinpath(dir, "two_snapshot_sync_economics_summary.csv")

        _write_jsonl(
            input_path,
            [
                _sync_economics_sample_record(
                    scenario_id="comparable_equivalent_fresh",
                    outcome="EquivalentLocalSlice",
                    freshness="FreshEnoughLocalDiagnostic",
                ),
                _sync_economics_sample_record(
                    scenario_id="comparable_divergent_fresh",
                    outcome="DivergentLocalSlice",
                    freshness="FreshEnoughLocalDiagnostic",
                ),
                _sync_economics_sample_record(
                    scenario_id="not_comparable_context_mismatch",
                    outcome="NotComparableLocalSlice",
                    freshness=nothing,
                ),
            ],
        )

        result = observe_sync_economics(input_path; output_csv_path=output_path)
        summary = result.summary

        @test summary.count_by_scenario_id["comparable_equivalent_fresh"] == 1
        @test summary.count_by_scenario_id["comparable_divergent_fresh"] == 1
        @test summary.count_by_outcome["EquivalentLocalSlice"] == 1
        @test summary.count_by_outcome["DivergentLocalSlice"] == 1
        @test summary.count_by_outcome["NotComparableLocalSlice"] == 1
        @test summary.count_by_freshness["FreshEnoughLocalDiagnostic"] == 2
        @test summary.count_by_freshness["none"] == 1

        @test isfile(output_path)
        csv_body = read(output_path, String)
        @test occursin("scenario_id,record_count,saved_bytes_sum,estimated_full_sync_bytes_sum,saved_full_ratio", csv_body)
        @test occursin("comparable_equivalent_fresh", csv_body)
        @test occursin("not_comparable_context_mismatch", csv_body)
        @test occursin("direct_measure_fields=", result.summary_text)
        @test occursin("estimated_or_derived_fields=", result.summary_text)

        rm(dir; recursive=true, force=true)
    end
end
