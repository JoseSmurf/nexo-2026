using JSON3
using Statistics

const RESIDUAL_SIGNAL_SCHEMA_VERSION = "nexo_residual_signal_v1"
const RESIDUAL_SIGNAL_CLASSIFIER_VERSION = "julia_residual_signal_classifier_v1"
const RESIDUAL_ALLOWED_NETWORK_TYPES = ("wifi", "cellular", "ethernet", "unknown")
const RESIDUAL_FEATURE_ORDER = (
    "rtt_ms",
    "jitter_ms",
    "loss_pct",
    "retransmission_pct",
    "handoff_count",
    "staleness_s",
)

const RESIDUAL_WEIGHT_RTT = 0.27
const RESIDUAL_WEIGHT_JITTER = 0.21
const RESIDUAL_WEIGHT_LOSS = 0.20
const RESIDUAL_WEIGHT_RETRANSMISSION = 0.16
const RESIDUAL_WEIGHT_HANDOFF = 0.10
const RESIDUAL_WEIGHT_STALENESS = 0.06

function _as_string(value, default::String="")
    value === nothing && return default
    return String(value)
end

function _as_float(value, default::Float64=0.0)
    value === nothing && return default
    value isa AbstractFloat && return Float64(value)
    value isa Integer && return Float64(value)
    parsed = tryparse(Float64, string(value))
    return parsed === nothing ? default : parsed
end

function _as_int(value, default::Int=0)
    value === nothing && return default
    value isa Integer && return Int(value)
    parsed = tryparse(Int, string(value))
    return parsed === nothing ? default : parsed
end

function _required_field(record, field::Symbol)
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
    throw(ArgumentError("missing required residual signal field: $(String(field))"))
end

function _require_nonnegative(name::String, value::Float64)
    value >= 0.0 || throw(ArgumentError("field $(name) must be >= 0"))
end

function _validate_percentage(name::String, value::Float64)
    _require_nonnegative(name, value)
    value <= 100.0 || throw(ArgumentError("field $(name) must be <= 100"))
end

function normalize_residual_signal_sample(record)
    node_id = strip(_as_string(_required_field(record, :node_id)))
    isempty(node_id) &&
        throw(ArgumentError("field node_id must not be empty in residual sample"))

    network_type = lowercase(strip(_as_string(_required_field(record, :network_type))))
    network_type = isempty(network_type) ? "unknown" : network_type
    network_type in RESIDUAL_ALLOWED_NETWORK_TYPES || throw(
        ArgumentError(
            "field network_type must be one of $(join(RESIDUAL_ALLOWED_NETWORK_TYPES, ","))",
        ),
    )

    timestamp_utc_ms = _as_int(_required_field(record, :timestamp_utc_ms), -1)
    timestamp_utc_ms >= 0 || throw(ArgumentError("field timestamp_utc_ms must be >= 0"))

    rtt_ms = _as_float(_required_field(record, :rtt_ms), -1.0)
    jitter_ms = _as_float(_required_field(record, :jitter_ms), -1.0)
    loss_pct = _as_float(_required_field(record, :loss_pct), -1.0)
    retransmission_pct = _as_float(_required_field(record, :retransmission_pct), -1.0)
    handoff_count = _as_int(_required_field(record, :handoff_count), -1)

    _require_nonnegative("rtt_ms", rtt_ms)
    _require_nonnegative("jitter_ms", jitter_ms)
    _validate_percentage("loss_pct", loss_pct)
    _validate_percentage("retransmission_pct", retransmission_pct)
    handoff_count >= 0 || throw(ArgumentError("field handoff_count must be >= 0"))

    return (
        node_id = node_id,
        network_type = network_type,
        timestamp_utc_ms = Int(timestamp_utc_ms),
        rtt_ms = Float64(rtt_ms),
        jitter_ms = Float64(jitter_ms),
        loss_pct = Float64(loss_pct),
        retransmission_pct = Float64(retransmission_pct),
        handoff_count = Int(handoff_count),
    )
end

function robust_center_scale(values::Vector{Float64})
    isempty(values) && return (0.0, 1.0)
    med = median(values)
    deviations = abs.(values .- med)
    mad = median(deviations)
    sigma = max(mad * 1.4826, 1e-9)
    return (Float64(med), Float64(sigma))
end

function robust_z(value::Float64, center::Float64, scale::Float64)
    return (value - center) / scale
end

function stable_sigmoid(value::Float64)
    if value >= 0
        z = exp(-value)
        return 1.0 / (1.0 + z)
    end
    z = exp(value)
    return z / (1.0 + z)
end

function classify_residual_signals(
    records;
    reference_ts_ms::Union{Nothing, Int}=nothing,
    retain_threshold::Float64=0.55,
)
    retain_threshold >= 0.0 && retain_threshold <= 1.0 || throw(
        ArgumentError("retain_threshold must be in [0, 1]"),
    )

    normalized = [normalize_residual_signal_sample(record) for record in records]
    sort!(
        normalized;
        by=x -> (x.timestamp_utc_ms, x.node_id, x.network_type, x.rtt_ms, x.jitter_ms),
    )

    ref_ts = if reference_ts_ms === nothing
        isempty(normalized) ? 0 : maximum(item.timestamp_utc_ms for item in normalized)
    else
        reference_ts_ms
    end

    rtt_values = Float64[item.rtt_ms for item in normalized]
    jitter_values = Float64[item.jitter_ms for item in normalized]
    loss_values = Float64[item.loss_pct for item in normalized]
    retransmission_values = Float64[item.retransmission_pct for item in normalized]
    handoff_values = Float64[item.handoff_count for item in normalized]

    rtt_center, rtt_scale = robust_center_scale(rtt_values)
    jitter_center, jitter_scale = robust_center_scale(jitter_values)
    loss_center, loss_scale = robust_center_scale(loss_values)
    retransmission_center, retransmission_scale = robust_center_scale(retransmission_values)
    handoff_center, handoff_scale = robust_center_scale(handoff_values)

    samples = map(normalized) do sample
        staleness_s = max(0.0, (Float64(ref_ts) - Float64(sample.timestamp_utc_ms)) / 1000.0)
        z_rtt = robust_z(sample.rtt_ms, rtt_center, rtt_scale)
        z_jitter = robust_z(sample.jitter_ms, jitter_center, jitter_scale)
        z_loss = robust_z(sample.loss_pct, loss_center, loss_scale)
        z_retransmission = robust_z(
            sample.retransmission_pct,
            retransmission_center,
            retransmission_scale,
        )
        z_handoff = robust_z(Float64(sample.handoff_count), handoff_center, handoff_scale)
        staleness_component = staleness_s / 60.0

        linear_score = (
            RESIDUAL_WEIGHT_RTT * z_rtt +
            RESIDUAL_WEIGHT_JITTER * z_jitter +
            RESIDUAL_WEIGHT_LOSS * z_loss +
            RESIDUAL_WEIGHT_RETRANSMISSION * z_retransmission +
            RESIDUAL_WEIGHT_HANDOFF * z_handoff +
            RESIDUAL_WEIGHT_STALENESS * staleness_component
        )
        residual_value_score = stable_sigmoid(linear_score)
        residual_class = residual_value_score >= retain_threshold ? "retain" : "discard"

        return (
            node_id = sample.node_id,
            network_type = sample.network_type,
            timestamp_utc_ms = sample.timestamp_utc_ms,
            rtt_ms = round(sample.rtt_ms; digits=6),
            jitter_ms = round(sample.jitter_ms; digits=6),
            loss_pct = round(sample.loss_pct; digits=6),
            retransmission_pct = round(sample.retransmission_pct; digits=6),
            handoff_count = sample.handoff_count,
            staleness_s = round(staleness_s; digits=6),
            robust_z = (
                rtt = round(z_rtt; digits=6),
                jitter = round(z_jitter; digits=6),
                loss = round(z_loss; digits=6),
                retransmission = round(z_retransmission; digits=6),
                handoff = round(z_handoff; digits=6),
            ),
            residual_value_score = round(residual_value_score; digits=6),
            residual_class = residual_class,
        )
    end

    retained_samples = count(sample -> sample.residual_class == "retain", samples)
    total_samples = length(samples)
    discarded_samples = total_samples - retained_samples
    retention_ratio = total_samples == 0 ? 0.0 : retained_samples / total_samples
    mean_score = total_samples == 0 ? 0.0 : mean(sample.residual_value_score for sample in samples)

    artifact = (
        schema_version = RESIDUAL_SIGNAL_SCHEMA_VERSION,
        classifier_version = RESIDUAL_SIGNAL_CLASSIFIER_VERSION,
        generated_at_ts_ms = Int(ref_ts),
        feature_order = collect(RESIDUAL_FEATURE_ORDER),
        weights = (
            rtt = RESIDUAL_WEIGHT_RTT,
            jitter = RESIDUAL_WEIGHT_JITTER,
            loss = RESIDUAL_WEIGHT_LOSS,
            retransmission = RESIDUAL_WEIGHT_RETRANSMISSION,
            handoff = RESIDUAL_WEIGHT_HANDOFF,
            staleness = RESIDUAL_WEIGHT_STALENESS,
        ),
        retain_threshold = retain_threshold,
        samples = samples,
        summary = (
            total_samples = total_samples,
            retained_samples = retained_samples,
            discarded_samples = discarded_samples,
            retention_ratio = round(retention_ratio; digits=6),
            mean_residual_value_score = round(mean_score; digits=6),
            is_runtime_authority = false,
            is_global_truth = false,
            reason = "Residual signal classifier is diagnostic-only and never runtime authority.",
        ),
    )
    return artifact
end

function write_residual_signal_artifact(records, output_path::AbstractString; kwargs...)
    artifact = classify_residual_signals(records; kwargs...)
    open(output_path, "w") do io
        write(io, JSON3.write(artifact))
    end
    return artifact
end
