using JSON3
using Statistics

const REPO_ROOT_PATH = normpath(joinpath(@__DIR__, ".."))
const DECISION_CYCLE_ARTIFACT_ENV_VAR = "NEXO_DECISION_CYCLE_V0_ARTIFACT_PATH"
const DECISION_CYCLE_SUMMARY_CSV_ENV_VAR = "NEXO_DECISION_CYCLE_V0_SUMMARY_CSV_PATH"

const DEFAULT_DECISION_CYCLE_JSONL_PATH = joinpath(
    "artifacts",
    "bitcoin_logistics_experiment",
    "decision_cycles.jsonl",
)
const DEFAULT_DECISION_CYCLE_SUMMARY_CSV_PATH = joinpath(
    "artifacts",
    "bitcoin_logistics_experiment",
    "decision_cycles_summary.csv",
)
const REPO_DEFAULT_DECISION_CYCLE_JSONL_PATH = joinpath(
    REPO_ROOT_PATH,
    "artifacts",
    "bitcoin_logistics_experiment",
    "decision_cycles.jsonl",
)
const REPO_DEFAULT_DECISION_CYCLE_SUMMARY_CSV_PATH = joinpath(
    REPO_ROOT_PATH,
    "artifacts",
    "bitcoin_logistics_experiment",
    "decision_cycles_summary.csv",
)

const DECISION_CYCLE_SCHEMA_VERSION = "v1"
const DECISION_CYCLE_POLICY_MODES = ("Blind", "EvidenceGuided")
const DECISION_CYCLE_STRUCTURAL_STATES = ("StructurallyValid", "StructuralInvalid")
const DECISION_CYCLE_COMPARABILITY_STATES = ("Comparable", "NotComparable", "NotEvaluated")
const DECISION_CYCLE_FRESHNESS_STATES = ("FreshEnough", "Stale", "FreshnessNotAssessable", "NotEvaluated")
const DECISION_CYCLE_ACTIONABILITY = "DiagnosticOnly"
const DECISION_CYCLE_INTENTS = ("Continue", "Refresh", "Rebuild", "Discard", "SubmitAttempt", "Abandon")

const DECISION_CYCLE_REQUIRED_FIELDS = (
    "schema_version",
    "run_id",
    "cycle_id",
    "policy_mode",
    "work_item_id",
    "observed_at_ts_ms",
    "decision_at_ts_ms",
    "cycle_closed_at_ts_ms",
    "structural_state",
    "comparability_state",
    "freshness_state",
    "actionability",
    "decision_intent",
    "decision_overhead_ms",
    "stale_detected",
    "is_runtime_authority",
    "is_global_truth",
    "reason_code",
)

function _missing_field_error(field::Symbol)
    throw(ArgumentError("missing required decision-cycle field: $(String(field))"))
end

function _field_value(record, field::Symbol)
    if hasproperty(record, field)
        return getproperty(record, field)
    end
    if record isa AbstractDict
        if haskey(record, field)
            return record[field]
        end
        key = String(field)
        if haskey(record, key)
            return record[key]
        end
    end
    _missing_field_error(field)
end

function _required_string(record, field::Symbol)::String
    value = _field_value(record, field)
    value === nothing && throw(ArgumentError("field $(String(field)) cannot be null"))
    return String(value)
end

function _required_bool(record, field::Symbol)::Bool
    value = _field_value(record, field)
    value isa Bool && return value
    throw(ArgumentError("field $(String(field)) must be boolean"))
end

function _required_int128(record, field::Symbol)::Int128
    value = _field_value(record, field)
    value isa Integer && return Int128(value)
    throw(ArgumentError("field $(String(field)) must be integer"))
end

function _required_enum(record, field::Symbol, allowed)::String
    value = _required_string(record, field)
    value in allowed || throw(ArgumentError(
        "field $(String(field)) has unsupported value=$(value); allowed=" * join(allowed, ","),
    ))
    return value
end

function validate_decision_cycle_v0_record(record)
    for field_name in DECISION_CYCLE_REQUIRED_FIELDS
        _field_value(record, Symbol(field_name))
    end

    schema_version = _required_string(record, :schema_version)
    schema_version == DECISION_CYCLE_SCHEMA_VERSION || throw(
        ArgumentError(
            "unsupported schema_version=$(schema_version), expected $(DECISION_CYCLE_SCHEMA_VERSION)",
        ),
    )

    _required_enum(record, :policy_mode, DECISION_CYCLE_POLICY_MODES)
    structural_state = _required_enum(record, :structural_state, DECISION_CYCLE_STRUCTURAL_STATES)
    comparability_state = _required_enum(record, :comparability_state, DECISION_CYCLE_COMPARABILITY_STATES)
    freshness_state = _required_enum(record, :freshness_state, DECISION_CYCLE_FRESHNESS_STATES)
    actionability = _required_string(record, :actionability)
    actionability == DECISION_CYCLE_ACTIONABILITY || throw(
        ArgumentError("field actionability must be $(DECISION_CYCLE_ACTIONABILITY)"),
    )
    _required_enum(record, :decision_intent, DECISION_CYCLE_INTENTS)

    observed_at_ts_ms = _required_int128(record, :observed_at_ts_ms)
    decision_at_ts_ms = _required_int128(record, :decision_at_ts_ms)
    cycle_closed_at_ts_ms = _required_int128(record, :cycle_closed_at_ts_ms)
    decision_overhead_ms = _required_int128(record, :decision_overhead_ms)

    observed_at_ts_ms >= 0 || throw(ArgumentError("observed_at_ts_ms must be >= 0"))
    decision_at_ts_ms >= observed_at_ts_ms || throw(
        ArgumentError("decision_at_ts_ms must be >= observed_at_ts_ms"),
    )
    cycle_closed_at_ts_ms >= decision_at_ts_ms || throw(
        ArgumentError("cycle_closed_at_ts_ms must be >= decision_at_ts_ms"),
    )
    decision_overhead_ms >= 0 || throw(ArgumentError("decision_overhead_ms must be >= 0"))

    stale_detected = _required_bool(record, :stale_detected)
    expected_stale = freshness_state == "Stale"
    stale_detected == expected_stale || throw(
        ArgumentError(
            "stale_detected must match freshness_state==Stale (freshness_state=$(freshness_state), stale_detected=$(stale_detected))",
        ),
    )

    is_runtime_authority = _required_bool(record, :is_runtime_authority)
    is_runtime_authority && throw(
        ArgumentError("field is_runtime_authority must be false for diagnostic artifacts"),
    )
    is_global_truth = _required_bool(record, :is_global_truth)
    is_global_truth &&
        throw(ArgumentError("field is_global_truth must be false for diagnostic artifacts"))

    if structural_state == "StructuralInvalid"
        comparability_state == "NotEvaluated" || throw(
            ArgumentError(
                "structural invalid record must keep comparability_state=NotEvaluated",
            ),
        )
        freshness_state == "NotEvaluated" || throw(
            ArgumentError("structural invalid record must keep freshness_state=NotEvaluated"),
        )
    end

    return true
end

function normalize_decision_cycle_v0_record(record)
    validate_decision_cycle_v0_record(record)
    return (
        schema_version = _required_string(record, :schema_version),
        run_id = _required_string(record, :run_id),
        cycle_id = _required_string(record, :cycle_id),
        policy_mode = _required_string(record, :policy_mode),
        work_item_id = _required_string(record, :work_item_id),
        observed_at_ts_ms = _required_int128(record, :observed_at_ts_ms),
        decision_at_ts_ms = _required_int128(record, :decision_at_ts_ms),
        cycle_closed_at_ts_ms = _required_int128(record, :cycle_closed_at_ts_ms),
        structural_state = _required_string(record, :structural_state),
        comparability_state = _required_string(record, :comparability_state),
        freshness_state = _required_string(record, :freshness_state),
        actionability = _required_string(record, :actionability),
        decision_intent = _required_string(record, :decision_intent),
        decision_overhead_ms = _required_int128(record, :decision_overhead_ms),
        stale_detected = _required_bool(record, :stale_detected),
        is_runtime_authority = _required_bool(record, :is_runtime_authority),
        is_global_truth = _required_bool(record, :is_global_truth),
        reason_code = _required_string(record, :reason_code),
    )
end

function read_decision_cycle_v0_jsonl(path::AbstractString)
    isfile(path) || throw(ArgumentError("decision-cycle artifact not found: $(path)"))
    records = NamedTuple[]
    for line in eachline(path)
        stripped = strip(line)
        isempty(stripped) && continue
        parsed = JSON3.read(stripped)
        push!(records, normalize_decision_cycle_v0_record(parsed))
    end
    isempty(records) && throw(ArgumentError("decision-cycle artifact is empty: $(path)"))
    return records
end

function _non_empty_string_or_nothing(value)::Union{Nothing, String}
    text = strip(String(value))
    isempty(text) && return nothing
    return text
end

function resolve_decision_cycle_v0_input_path(
    explicit_path::Union{Nothing, AbstractString}=nothing,
)::String
    explicit = explicit_path === nothing ? nothing : _non_empty_string_or_nothing(explicit_path)
    explicit !== nothing && return explicit

    from_env = _non_empty_string_or_nothing(get(ENV, DECISION_CYCLE_ARTIFACT_ENV_VAR, ""))
    from_env !== nothing && return from_env

    if isfile(DEFAULT_DECISION_CYCLE_JSONL_PATH)
        return DEFAULT_DECISION_CYCLE_JSONL_PATH
    end
    return REPO_DEFAULT_DECISION_CYCLE_JSONL_PATH
end

function resolve_decision_cycle_v0_output_csv_path(
    explicit_path::Union{Nothing, AbstractString}=nothing,
)::String
    explicit = explicit_path === nothing ? nothing : _non_empty_string_or_nothing(explicit_path)
    explicit !== nothing && return explicit

    from_env = _non_empty_string_or_nothing(get(ENV, DECISION_CYCLE_SUMMARY_CSV_ENV_VAR, ""))
    from_env !== nothing && return from_env

    if ispath(dirname(DEFAULT_DECISION_CYCLE_SUMMARY_CSV_PATH))
        return DEFAULT_DECISION_CYCLE_SUMMARY_CSV_PATH
    end
    return REPO_DEFAULT_DECISION_CYCLE_SUMMARY_CSV_PATH
end

function _group_counts(records::Vector{<:NamedTuple}, field::Symbol)
    counts = Dict{String, Int}()
    for record in records
        key = String(getproperty(record, field))
        counts[key] = get(counts, key, 0) + 1
    end
    return counts
end

function _safe_rate(numerator::Integer, denominator::Integer)::Float64
    denominator <= 0 && return 0.0
    return Float64(numerator) / Float64(denominator)
end

function _mean_int(values::Vector{Int128})::Float64
    isempty(values) && return 0.0
    return mean(Float64.(values))
end

function validate_decision_cycle_v0_ab_pairing(records::Vector{<:NamedTuple})
    grouped = Dict{String, Dict{String, NamedTuple}}()
    for record in records
        by_policy = get!(grouped, record.cycle_id, Dict{String, NamedTuple}())
        haskey(by_policy, record.policy_mode) && throw(
            ArgumentError(
                "duplicate policy_mode=$(record.policy_mode) for cycle_id=$(record.cycle_id)",
            ),
        )
        by_policy[record.policy_mode] = record
    end

    for (cycle_id, by_policy) in grouped
        length(by_policy) == 2 || throw(
            ArgumentError("cycle_id=$(cycle_id) must contain exactly 2 policy records"),
        )
        haskey(by_policy, "Blind") || throw(
            ArgumentError("cycle_id=$(cycle_id) missing Blind policy record"),
        )
        haskey(by_policy, "EvidenceGuided") || throw(
            ArgumentError("cycle_id=$(cycle_id) missing EvidenceGuided policy record"),
        )
    end
    return true
end

function _paired_ab_cycle_summary(records::Vector{<:NamedTuple})
    grouped = Dict{String, Dict{String, NamedTuple}}()
    for record in records
        by_policy = get!(grouped, record.cycle_id, Dict{String, NamedTuple}())
        by_policy[record.policy_mode] = record
    end

    rows = NamedTuple[]
    for cycle_id in sort(collect(keys(grouped)))
        by_policy = grouped[cycle_id]
        blind = by_policy["Blind"]
        evidence = by_policy["EvidenceGuided"]
        push!(
            rows,
            (
                cycle_id = cycle_id,
                blind_decision_intent = blind.decision_intent,
                evidence_guided_decision_intent = evidence.decision_intent,
                intent_match = blind.decision_intent == evidence.decision_intent,
            ),
        )
    end
    return rows
end

function _mean_overhead_by_policy(records::Vector{<:NamedTuple})
    grouped = Dict{String, Vector{Int128}}()
    for record in records
        push!(get!(grouped, record.policy_mode, Int128[]), record.decision_overhead_ms)
    end
    out = Dict{String, Float64}()
    for key in sort(collect(keys(grouped)))
        out[key] = _mean_int(grouped[key])
    end
    return out
end

function build_decision_cycle_v0_summary(records::Vector{<:NamedTuple})
    validate_decision_cycle_v0_ab_pairing(records)
    total = length(records)
    count_by_policy_mode = _group_counts(records, :policy_mode)
    count_by_decision_intent = _group_counts(records, :decision_intent)
    structural_invalid_count = count(
        record -> record.structural_state == "StructuralInvalid",
        records,
    )
    stale_count = count(record -> record.freshness_state == "Stale", records)
    freshness_not_assessable_count = count(
        record -> record.freshness_state == "FreshnessNotAssessable",
        records,
    )
    mean_overhead_ms_by_policy = _mean_overhead_by_policy(records)
    paired_rows = _paired_ab_cycle_summary(records)
    paired_match_count = count(row -> row.intent_match, paired_rows)
    paired_mismatch_count = length(paired_rows) - paired_match_count

    return (
        total_records = total,
        count_by_policy_mode = count_by_policy_mode,
        count_by_decision_intent = count_by_decision_intent,
        structural_invalid_rate = _safe_rate(structural_invalid_count, total),
        stale_rate = _safe_rate(stale_count, total),
        freshness_not_assessable_rate = _safe_rate(freshness_not_assessable_count, total),
        mean_overhead_ms_by_policy = mean_overhead_ms_by_policy,
        paired_cycle_count = length(paired_rows),
        paired_intent_match_count = paired_match_count,
        paired_intent_mismatch_count = paired_mismatch_count,
        paired_rows = paired_rows,
    )
end

function _sorted_lines_from_counts(label::String, counts::Dict{String, Int})
    lines = String["$(label):"]
    for key in sort(collect(keys(counts)))
        push!(lines, "  - $(key): $(counts[key])")
    end
    return lines
end

function format_decision_cycle_v0_summary(summary)::String
    lines = String[
        "Decision Cycle V0 Offline Summary",
        "total_records=$(summary.total_records)",
        "structural_invalid_rate=$(round(summary.structural_invalid_rate; digits=6))",
        "stale_rate=$(round(summary.stale_rate; digits=6))",
        "freshness_not_assessable_rate=$(round(summary.freshness_not_assessable_rate; digits=6))",
        "paired_cycle_count=$(summary.paired_cycle_count)",
        "paired_intent_match_count=$(summary.paired_intent_match_count)",
        "paired_intent_mismatch_count=$(summary.paired_intent_mismatch_count)",
        "mean_overhead_ms_by_policy:",
    ]

    for key in sort(collect(keys(summary.mean_overhead_ms_by_policy)))
        value = summary.mean_overhead_ms_by_policy[key]
        push!(lines, "  - $(key): $(round(value; digits=6))")
    end

    append!(lines, _sorted_lines_from_counts("count_by_policy_mode", summary.count_by_policy_mode))
    append!(
        lines,
        _sorted_lines_from_counts(
            "count_by_decision_intent",
            summary.count_by_decision_intent,
        ),
    )
    return join(lines, "\n")
end

function write_decision_cycle_v0_summary_csv(
    path::AbstractString,
    summary,
)
    dir = dirname(path)
    isempty(dir) || mkpath(dir)

    open(path, "w") do io
        write(io, "cycle_id,blind_decision_intent,evidence_guided_decision_intent,intent_match\n")
        for row in summary.paired_rows
            write(
                io,
                string(
                    row.cycle_id,
                    ",",
                    row.blind_decision_intent,
                    ",",
                    row.evidence_guided_decision_intent,
                    ",",
                    row.intent_match,
                    "\n",
                ),
            )
        end
    end
    return path
end

function observe_decision_cycle_v0(
    input_path::AbstractString=DEFAULT_DECISION_CYCLE_JSONL_PATH;
    output_csv_path::AbstractString=DEFAULT_DECISION_CYCLE_SUMMARY_CSV_PATH,
)
    records = read_decision_cycle_v0_jsonl(input_path)
    summary = build_decision_cycle_v0_summary(records)
    summary_text = format_decision_cycle_v0_summary(summary)
    csv_path = write_decision_cycle_v0_summary_csv(output_csv_path, summary)
    return (records = records, summary = summary, summary_text = summary_text, csv_path = csv_path)
end

function main(args=ARGS)
    explicit_input = length(args) >= 1 ? args[1] : nothing
    explicit_output = length(args) >= 2 ? args[2] : nothing
    input_path = resolve_decision_cycle_v0_input_path(explicit_input)
    output_csv_path = resolve_decision_cycle_v0_output_csv_path(explicit_output)

    result = observe_decision_cycle_v0(input_path; output_csv_path=output_csv_path)
    println(result.summary_text)
    println("summary_csv_path=$(result.csv_path)")
    return nothing
end

if abspath(PROGRAM_FILE) == @__FILE__
    try
        main()
    catch err
        println(stderr, "decision-cycle observer failed: $(err)")
        rethrow(err)
    end
end
