using JSON3
using Statistics

const DEFAULT_SYNC_ECONOMICS_JSONL_PATH = joinpath(
    "artifacts",
    "sync_economics",
    "two_snapshot_sync_economics.jsonl",
)
const DEFAULT_SYNC_ECONOMICS_SUMMARY_CSV_PATH = joinpath(
    "artifacts",
    "sync_economics",
    "two_snapshot_sync_economics_summary.csv",
)
const SYNC_ECONOMICS_SCHEMA_VERSION = "v1"

const SYNC_ECONOMICS_METADATA_FIELDS = (
    "schema_version",
    "scenario_id",
    "since_ts_ms",
    "until_ts_ms",
    "comparability",
    "outcome",
    "freshness",
    "diagnostic_actionability",
    "is_runtime_authority",
    "is_global_truth",
    "reason",
)
const SYNC_ECONOMICS_DIRECT_MEASURE_FIELDS = (
    "left_event_count",
    "right_event_count",
    "left_digest_bytes",
    "right_digest_bytes",
    "compared_digest_bytes_total",
)
const SYNC_ECONOMICS_ESTIMATED_OR_DERIVED_FIELDS = (
    "estimated_bytes_per_event",
    "estimated_full_sync_bytes",
    "saved_bytes_if_sync_skipped",
)
const SYNC_ECONOMICS_REQUIRED_FIELDS = (
    SYNC_ECONOMICS_METADATA_FIELDS...,
    SYNC_ECONOMICS_DIRECT_MEASURE_FIELDS...,
    SYNC_ECONOMICS_ESTIMATED_OR_DERIVED_FIELDS...,
)

function _missing_field_error(field::Symbol)
    throw(ArgumentError("missing required sync economics field: $(String(field))"))
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

function _optional_string(record, field::Symbol)::Union{Nothing, String}
    value = _field_value(record, field)
    value === nothing && return nothing
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

function validate_two_snapshot_sync_economics_record(record)
    for field_name in SYNC_ECONOMICS_REQUIRED_FIELDS
        _field_value(record, Symbol(field_name))
    end

    schema_version = _required_string(record, :schema_version)
    schema_version == SYNC_ECONOMICS_SCHEMA_VERSION || throw(
        ArgumentError(
            "unsupported schema_version=$(schema_version), expected $(SYNC_ECONOMICS_SCHEMA_VERSION)",
        ),
    )

    return true
end

function normalize_two_snapshot_sync_economics_record(record)
    validate_two_snapshot_sync_economics_record(record)

    return (
        schema_version = _required_string(record, :schema_version),
        scenario_id = _required_string(record, :scenario_id),
        since_ts_ms = _required_int128(record, :since_ts_ms),
        until_ts_ms = _required_int128(record, :until_ts_ms),
        left_event_count = _required_int128(record, :left_event_count),
        right_event_count = _required_int128(record, :right_event_count),
        left_digest_bytes = _required_int128(record, :left_digest_bytes),
        right_digest_bytes = _required_int128(record, :right_digest_bytes),
        compared_digest_bytes_total = _required_int128(record, :compared_digest_bytes_total),
        estimated_bytes_per_event = _required_int128(record, :estimated_bytes_per_event),
        estimated_full_sync_bytes = _required_int128(record, :estimated_full_sync_bytes),
        saved_bytes_if_sync_skipped = _required_int128(record, :saved_bytes_if_sync_skipped),
        comparability = _required_string(record, :comparability),
        outcome = _required_string(record, :outcome),
        freshness = _optional_string(record, :freshness),
        diagnostic_actionability = _required_string(record, :diagnostic_actionability),
        is_runtime_authority = _required_bool(record, :is_runtime_authority),
        is_global_truth = _required_bool(record, :is_global_truth),
        reason = _required_string(record, :reason),
    )
end

function read_two_snapshot_sync_economics_jsonl(path::AbstractString)
    isfile(path) || throw(ArgumentError("sync economics artifact not found: $(path)"))

    records = NamedTuple[]
    for line in eachline(path)
        stripped = strip(line)
        isempty(stripped) && continue
        parsed = JSON3.read(stripped)
        push!(records, normalize_two_snapshot_sync_economics_record(parsed))
    end

    isempty(records) && throw(ArgumentError("sync economics artifact is empty: $(path)"))
    return records
end

function safe_saved_full_ratio(saved_bytes::Integer, full_bytes::Integer)
    full_bytes <= 0 && return nothing
    return Float64(saved_bytes) / Float64(full_bytes)
end

function _mean_int(values::Vector{Int128})::Float64
    isempty(values) && return 0.0
    return mean(Float64.(values))
end

function _median_int(values::Vector{Int128})::Float64
    isempty(values) && return 0.0
    return median(Float64.(values))
end

function percentile_nearest_rank(values::Vector{Int128}, p::Float64)::Int128
    isempty(values) && return Int128(0)
    p < 0.0 && throw(ArgumentError("percentile p must be >= 0.0"))
    p > 1.0 && throw(ArgumentError("percentile p must be <= 1.0"))

    sorted = sort(values)
    rank = ceil(Int, p * length(sorted))
    rank = clamp(rank, 1, length(sorted))
    return sorted[rank]
end

function _group_counts(records::Vector{<:NamedTuple}, field::Symbol)
    counts = Dict{String, Int}()
    for record in records
        key_value = getproperty(record, field)
        key = key_value === nothing ? "none" : String(key_value)
        counts[key] = get(counts, key, 0) + 1
    end
    return counts
end

function ratio_saved_full_by_scenario(records::Vector{<:NamedTuple})
    sums = Dict{String, NamedTuple{(:saved, :full), Tuple{Int128, Int128}}}()
    for record in records
        scenario = record.scenario_id
        previous = get(sums, scenario, (saved = Int128(0), full = Int128(0)))
        sums[scenario] = (
            saved = previous.saved + record.saved_bytes_if_sync_skipped,
            full = previous.full + record.estimated_full_sync_bytes,
        )
    end

    ratios = Dict{String, Union{Nothing, Float64}}()
    for (scenario, totals) in sums
        ratios[scenario] = safe_saved_full_ratio(totals.saved, totals.full)
    end
    return ratios
end

function build_two_snapshot_sync_economics_summary(records::Vector{<:NamedTuple})
    compared_values = Int128[record.compared_digest_bytes_total for record in records]
    estimated_values = Int128[record.estimated_full_sync_bytes for record in records]
    saved_values = Int128[record.saved_bytes_if_sync_skipped for record in records]

    return (
        total_scenarios = length(records),
        mean_compared_digest_bytes_total = _mean_int(compared_values),
        mean_estimated_full_sync_bytes = _mean_int(estimated_values),
        mean_saved_bytes_if_sync_skipped = _mean_int(saved_values),
        median_saved_bytes_if_sync_skipped = _median_int(saved_values),
        p50_saved_bytes_if_sync_skipped = percentile_nearest_rank(saved_values, 0.50),
        p95_saved_bytes_if_sync_skipped = percentile_nearest_rank(saved_values, 0.95),
        ratio_saved_full_by_scenario = ratio_saved_full_by_scenario(records),
        count_by_scenario_id = _group_counts(records, :scenario_id),
        count_by_comparability = _group_counts(records, :comparability),
        count_by_outcome = _group_counts(records, :outcome),
        count_by_freshness = _group_counts(records, :freshness),
        direct_measure_fields = SYNC_ECONOMICS_DIRECT_MEASURE_FIELDS,
        estimated_or_derived_fields = SYNC_ECONOMICS_ESTIMATED_OR_DERIVED_FIELDS,
    )
end

function _sorted_lines_from_counts(label::String, counts::Dict{String, Int})
    lines = String["$(label):"]
    for key in sort(collect(keys(counts)))
        push!(lines, "  - $(key): $(counts[key])")
    end
    return lines
end

function format_two_snapshot_sync_economics_summary(summary)::String
    lines = String[
        "Two-Snapshot Sync Economics Summary",
        "total_scenarios=$(summary.total_scenarios)",
        "mean_compared_digest_bytes_total=$(round(summary.mean_compared_digest_bytes_total; digits=3))",
        "mean_estimated_full_sync_bytes=$(round(summary.mean_estimated_full_sync_bytes; digits=3))",
        "mean_saved_bytes_if_sync_skipped=$(round(summary.mean_saved_bytes_if_sync_skipped; digits=3))",
        "median_saved_bytes_if_sync_skipped=$(round(summary.median_saved_bytes_if_sync_skipped; digits=3))",
        "p50_saved_bytes_if_sync_skipped=$(summary.p50_saved_bytes_if_sync_skipped)",
        "p95_saved_bytes_if_sync_skipped=$(summary.p95_saved_bytes_if_sync_skipped)",
        "direct_measure_fields=$(join(summary.direct_measure_fields, ","))",
        "estimated_or_derived_fields=$(join(summary.estimated_or_derived_fields, ","))",
        "ratio_saved_full_by_scenario:",
    ]

    for scenario in sort(collect(keys(summary.ratio_saved_full_by_scenario)))
        ratio = summary.ratio_saved_full_by_scenario[scenario]
        ratio_text = ratio === nothing ? "NA" : string(round(ratio; digits=6))
        push!(lines, "  - $(scenario): $(ratio_text)")
    end

    append!(lines, _sorted_lines_from_counts("count_by_scenario_id", summary.count_by_scenario_id))
    append!(
        lines,
        _sorted_lines_from_counts("count_by_comparability", summary.count_by_comparability),
    )
    append!(lines, _sorted_lines_from_counts("count_by_outcome", summary.count_by_outcome))
    append!(lines, _sorted_lines_from_counts("count_by_freshness", summary.count_by_freshness))

    return join(lines, "\n")
end

function write_two_snapshot_sync_economics_summary_csv(
    path::AbstractString,
    records::Vector{<:NamedTuple},
    summary,
)
    dir = dirname(path)
    isempty(dir) || mkpath(dir)

    ratios = summary.ratio_saved_full_by_scenario
    scenario_counts = summary.count_by_scenario_id
    by_scenario = Dict{String, NamedTuple{(:saved_sum, :full_sum), Tuple{Int128, Int128}}}()
    for record in records
        scenario = record.scenario_id
        previous = get(by_scenario, scenario, (saved_sum = Int128(0), full_sum = Int128(0)))
        by_scenario[scenario] = (
            saved_sum = previous.saved_sum + record.saved_bytes_if_sync_skipped,
            full_sum = previous.full_sum + record.estimated_full_sync_bytes,
        )
    end

    open(path, "w") do io
        write(
            io,
            "scenario_id,record_count,saved_bytes_sum,estimated_full_sync_bytes_sum,saved_full_ratio\n",
        )
        for scenario in sort(collect(keys(scenario_counts)))
            totals = by_scenario[scenario]
            ratio = get(ratios, scenario, nothing)
            ratio_text = ratio === nothing ? "NA" : string(round(ratio; digits=6))
            write(
                io,
                string(
                    scenario,
                    ",",
                    scenario_counts[scenario],
                    ",",
                    totals.saved_sum,
                    ",",
                    totals.full_sum,
                    ",",
                    ratio_text,
                    "\n",
                ),
            )
        end
    end

    return path
end

function observe_sync_economics(
    input_path::AbstractString=DEFAULT_SYNC_ECONOMICS_JSONL_PATH;
    output_csv_path::AbstractString=DEFAULT_SYNC_ECONOMICS_SUMMARY_CSV_PATH,
)
    records = read_two_snapshot_sync_economics_jsonl(input_path)
    summary = build_two_snapshot_sync_economics_summary(records)
    summary_text = format_two_snapshot_sync_economics_summary(summary)
    csv_path = write_two_snapshot_sync_economics_summary_csv(output_csv_path, records, summary)
    return (records = records, summary = summary, summary_text = summary_text, csv_path = csv_path)
end

function main(args=ARGS)
    input_path = length(args) >= 1 ? args[1] : DEFAULT_SYNC_ECONOMICS_JSONL_PATH
    output_csv_path = length(args) >= 2 ? args[2] : DEFAULT_SYNC_ECONOMICS_SUMMARY_CSV_PATH

    result = observe_sync_economics(input_path; output_csv_path=output_csv_path)
    println(result.summary_text)
    println("summary_csv_path=$(result.csv_path)")
    return nothing
end

if abspath(PROGRAM_FILE) == @__FILE__
    try
        main()
    catch err
        println(stderr, "sync economics analysis failed: $(err)")
        rethrow(err)
    end
end
