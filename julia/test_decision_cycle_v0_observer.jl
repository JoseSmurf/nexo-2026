using Test
using JSON3

include("observe_decision_cycle_v0.jl")

function _decision_cycle_sample_record(;
    schema_version::String="v1",
    run_id::String="run_v0",
    cycle_id::String="cycle_001",
    policy_mode::String="Blind",
    work_item_id::String="work_001",
    observed_at_ts_ms::Int=1000,
    decision_at_ts_ms::Int=1001,
    cycle_closed_at_ts_ms::Int=1002,
    structural_state::String="StructurallyValid",
    comparability_state::String="Comparable",
    freshness_state::String="FreshEnough",
    actionability::String="DiagnosticOnly",
    decision_intent::String="Continue",
    decision_overhead_ms::Int=1,
    stale_detected::Bool=false,
    is_runtime_authority::Bool=false,
    is_global_truth::Bool=false,
    reason_code::String="blind_fixed_continue",
)
    return Dict(
        "schema_version" => schema_version,
        "run_id" => run_id,
        "cycle_id" => cycle_id,
        "policy_mode" => policy_mode,
        "work_item_id" => work_item_id,
        "observed_at_ts_ms" => observed_at_ts_ms,
        "decision_at_ts_ms" => decision_at_ts_ms,
        "cycle_closed_at_ts_ms" => cycle_closed_at_ts_ms,
        "structural_state" => structural_state,
        "comparability_state" => comparability_state,
        "freshness_state" => freshness_state,
        "actionability" => actionability,
        "decision_intent" => decision_intent,
        "decision_overhead_ms" => decision_overhead_ms,
        "stale_detected" => stale_detected,
        "is_runtime_authority" => is_runtime_authority,
        "is_global_truth" => is_global_truth,
        "reason_code" => reason_code,
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

@testset "Decision cycle v0 observer" begin
    @testset "reads canonical JSONL and validates AB pairing" begin
        dir = mktempdir()
        path = joinpath(dir, "decision_cycles.jsonl")
        _write_jsonl(
            path,
            [
                _decision_cycle_sample_record(policy_mode="Blind"),
                _decision_cycle_sample_record(
                    policy_mode="EvidenceGuided",
                    decision_intent="Continue",
                    decision_overhead_ms=2,
                    reason_code="evidence_fresh_enough_continue",
                ),
            ],
        )

        records = read_decision_cycle_v0_jsonl(path)
        @test length(records) == 2
        @test records[1].schema_version == "v1"
        @test validate_decision_cycle_v0_ab_pairing(records) == true

        rm(dir; recursive=true, force=true)
    end

    @testset "fails closed on incompatible schema version" begin
        record = _decision_cycle_sample_record(schema_version="v0")
        @test_throws ArgumentError normalize_decision_cycle_v0_record(record)
    end

    @testset "fails closed on semantic authority/global-truth violation" begin
        runtime_authority = _decision_cycle_sample_record(is_runtime_authority=true)
        global_truth = _decision_cycle_sample_record(is_global_truth=true)
        @test_throws ArgumentError normalize_decision_cycle_v0_record(runtime_authority)
        @test_throws ArgumentError normalize_decision_cycle_v0_record(global_truth)
    end

    @testset "fails closed when structural invalid is reclassified as normal diagnostics" begin
        record = _decision_cycle_sample_record(
            structural_state="StructuralInvalid",
            comparability_state="NotComparable",
            freshness_state="FreshnessNotAssessable",
            decision_intent="Discard",
            stale_detected=false,
            reason_code="structural_invalid_fail_closed",
        )
        @test_throws ArgumentError normalize_decision_cycle_v0_record(record)
    end

    @testset "summary computes requested metrics conservatively" begin
        records = [
            normalize_decision_cycle_v0_record(
                _decision_cycle_sample_record(
                    cycle_id="cycle_001",
                    policy_mode="Blind",
                    decision_intent="Continue",
                    freshness_state="FreshEnough",
                    stale_detected=false,
                    decision_overhead_ms=1,
                ),
            ),
            normalize_decision_cycle_v0_record(
                _decision_cycle_sample_record(
                    cycle_id="cycle_001",
                    policy_mode="EvidenceGuided",
                    decision_intent="Continue",
                    freshness_state="FreshEnough",
                    stale_detected=false,
                    decision_overhead_ms=2,
                ),
            ),
            normalize_decision_cycle_v0_record(
                _decision_cycle_sample_record(
                    cycle_id="cycle_002",
                    policy_mode="Blind",
                    decision_intent="Refresh",
                    freshness_state="Stale",
                    stale_detected=true,
                    decision_overhead_ms=1,
                ),
            ),
            normalize_decision_cycle_v0_record(
                _decision_cycle_sample_record(
                    cycle_id="cycle_002",
                    policy_mode="EvidenceGuided",
                    decision_intent="Abandon",
                    freshness_state="FreshnessNotAssessable",
                    stale_detected=false,
                    decision_overhead_ms=2,
                ),
            ),
            normalize_decision_cycle_v0_record(
                _decision_cycle_sample_record(
                    cycle_id="cycle_003",
                    policy_mode="Blind",
                    structural_state="StructuralInvalid",
                    comparability_state="NotEvaluated",
                    freshness_state="NotEvaluated",
                    decision_intent="Discard",
                    stale_detected=false,
                    decision_overhead_ms=1,
                    reason_code="structural_invalid_fail_closed",
                ),
            ),
            normalize_decision_cycle_v0_record(
                _decision_cycle_sample_record(
                    cycle_id="cycle_003",
                    policy_mode="EvidenceGuided",
                    structural_state="StructuralInvalid",
                    comparability_state="NotEvaluated",
                    freshness_state="NotEvaluated",
                    decision_intent="Discard",
                    stale_detected=false,
                    decision_overhead_ms=2,
                    reason_code="structural_invalid_fail_closed",
                ),
            ),
        ]

        summary = build_decision_cycle_v0_summary(records)
        @test summary.total_records == 6
        @test summary.count_by_policy_mode["Blind"] == 3
        @test summary.count_by_policy_mode["EvidenceGuided"] == 3
        @test summary.count_by_decision_intent["Discard"] == 2
        @test summary.structural_invalid_rate == (2 / 6)
        @test summary.stale_rate == (1 / 6)
        @test summary.freshness_not_assessable_rate == (1 / 6)
        @test summary.mean_overhead_ms_by_policy["Blind"] == 1.0
        @test summary.mean_overhead_ms_by_policy["EvidenceGuided"] == 2.0
        @test summary.paired_cycle_count == 3
        @test summary.paired_intent_match_count == 2
        @test summary.paired_intent_mismatch_count == 1
    end

    @testset "fails closed when AB pairing is incomplete" begin
        records = [
            normalize_decision_cycle_v0_record(_decision_cycle_sample_record(policy_mode="Blind")),
        ]
        @test_throws ArgumentError validate_decision_cycle_v0_ab_pairing(records)
    end

    @testset "writes summary csv and emits readable text" begin
        dir = mktempdir()
        input_path = joinpath(dir, "decision_cycles.jsonl")
        output_path = joinpath(dir, "decision_cycles_summary.csv")

        _write_jsonl(
            input_path,
            [
                _decision_cycle_sample_record(
                    cycle_id="cycle_001",
                    policy_mode="Blind",
                    decision_intent="Continue",
                ),
                _decision_cycle_sample_record(
                    cycle_id="cycle_001",
                    policy_mode="EvidenceGuided",
                    decision_intent="Continue",
                    decision_overhead_ms=2,
                    reason_code="evidence_fresh_enough_continue",
                ),
            ],
        )

        result = observe_decision_cycle_v0(input_path; output_csv_path=output_path)
        @test isfile(output_path)
        csv_body = read(output_path, String)
        @test occursin(
            "cycle_id,blind_decision_intent,evidence_guided_decision_intent,intent_match",
            csv_body,
        )
        @test occursin("cycle_001,Continue,Continue,true", csv_body)
        @test occursin("Decision Cycle V0 Offline Summary", result.summary_text)
        @test occursin("count_by_policy_mode:", result.summary_text)

        rm(dir; recursive=true, force=true)
    end
end
