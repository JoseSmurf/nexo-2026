using JSON3
using HTTP

const STATE_API_URL = get(ENV, "NEXO_STATE_API_URL", "http://127.0.0.1:3000/api/state")
const FLOW_KIND_KEYS = ("event", "chat", "ai")
const FLOW_SOURCE_KEYS = ("operator_action", "core_decision", "passive_observation")

function _as_string(value, default::String="")
    value === nothing && return default
    return String(value)
end

function _as_int(value, default::Int=0)
    value === nothing && return default
    value isa Integer && return Int(value)
    parsed = tryparse(Int, string(value))
    return parsed === nothing ? default : parsed
end

function _flow_items(payload)::Vector{Any}
    flow = hasproperty(payload, :recent_flow) ? payload.recent_flow : get(payload, :recent_flow, Any[])
    flow isa AbstractVector || return Any[]
    return collect(flow)
end

function _flow_kind(item)::String
    hasproperty(item, :kind) && return _as_string(item.kind)
    item isa AbstractDict && return _as_string(get(item, "kind", get(item, :kind, "")))
    return ""
end

function _flow_origin(item)::String
    hasproperty(item, :origin) && return _as_string(item.origin)
    item isa AbstractDict && return _as_string(get(item, "origin", get(item, :origin, "")))
    return ""
end

function _flow_summary(item)::String
    hasproperty(item, :summary) && return _as_string(item.summary)
    item isa AbstractDict && return _as_string(get(item, "summary", get(item, :summary, "")))
    return ""
end

function classify_flow_source(item)::String
    kind = _flow_kind(item)
    origin = _flow_origin(item)
    summary = _flow_summary(item)

    if kind == "chat" && origin == "ui_dashboard"
        return "operator_action"
    end

    if kind == "event" && summary in ("approved decision", "flagged for review", "blocked decision")
        return "core_decision"
    end

    return "passive_observation"
end

function count_flow_kinds(flow_items)::Dict{String, Int}
    counts = Dict(key => 0 for key in FLOW_KIND_KEYS)
    for item in flow_items
        kind = _flow_kind(item)
        haskey(counts, kind) || continue
        counts[kind] += 1
    end
    return counts
end

function count_flow_sources(flow_items)::Dict{String, Int}
    counts = Dict(key => 0 for key in FLOW_SOURCE_KEYS)
    for item in flow_items
        counts[classify_flow_source(item)] += 1
    end
    return counts
end

function movement_mix_ratios(source_counts::Dict{String, Int})::Dict{String, Float64}
    total = sum(values(source_counts))
    if total == 0
        return Dict(key => 0.0 for key in FLOW_SOURCE_KEYS)
    end

    return Dict(
        key => round(get(source_counts, key, 0) / total; digits=4)
        for key in FLOW_SOURCE_KEYS
    )
end

function classify_flow_intensity(total_items::Int)::String
    total_items <= 1 && return "low"
    total_items <= 3 && return "normal"
    return "elevated"
end

function dominant_source(source_counts::Dict{String, Int})::String
    best = "passive_observation"
    best_count = -1
    for key in ("operator_action", "core_decision", "passive_observation")
        count = get(source_counts, key, 0)
        if count > best_count
            best = key
            best_count = count
        end
    end
    return best_count <= 0 ? "" : best
end

function dominant_kind(kind_counts::Dict{String, Int})::String
    best = "event"
    best_count = -1
    for key in ("event", "chat", "ai")
        count = get(kind_counts, key, 0)
        if count > best_count
            best = key
            best_count = count
        end
    end
    return best_count <= 0 ? "" : best
end

function summarize_flow_observation(total_items::Int, source_counts::Dict{String, Int}, intensity::String)::String
    total_items == 0 && return "no recent flow observed"

    dominant = dominant_source(source_counts)
    if dominant == "operator_action"
        return intensity == "elevated" ?
            "operator-driven activity is elevated in the current window" :
            "operator-driven activity dominates the current window"
    end
    if dominant == "core_decision"
        return intensity == "elevated" ?
            "core decisions are elevated in the current window" :
            "core decision activity dominates the current window"
    end

    return intensity == "elevated" ?
        "passive observation is elevated in the current window" :
        "system stable in current window"
end

function observe_state(payload)
    flow_items = _flow_items(payload)
    kind_counts = count_flow_kinds(flow_items)
    source_counts = count_flow_sources(flow_items)
    ratios = movement_mix_ratios(source_counts)
    total_items = length(flow_items)
    intensity = classify_flow_intensity(total_items)
    latest_source = hasproperty(payload, :latest_change_source) ?
        _as_string(payload.latest_change_source) :
        ""

    return (
        total_items = total_items,
        kind_counts = kind_counts,
        source_counts = source_counts,
        source_ratios = ratios,
        dominant_kind = dominant_kind(kind_counts),
        dominant_source = dominant_source(source_counts),
        intensity = intensity,
        latest_change_source = latest_source,
        write_status = hasproperty(payload, :write_status) ? _as_string(payload.write_status) : "",
        summary = summarize_flow_observation(total_items, source_counts, intensity),
    )
end

function observation_timestamp(payload)::Int
    if hasproperty(payload, :timestamp)
        return _as_int(payload.timestamp, 0)
    end
    if hasproperty(payload, :latest_change_timestamp)
        return _as_int(payload.latest_change_timestamp, 0)
    end
    return 0
end

function observation_artifact(payload)
    observation = observe_state(payload)
    kind_counts = observation.kind_counts
    source_ratios = observation.source_ratios

    return (
        timestamp = observation_timestamp(payload),
        flow_counts = (
            event = get(kind_counts, "event", 0),
            chat = get(kind_counts, "chat", 0),
            ai = get(kind_counts, "ai", 0),
        ),
        source_mix = (
            operator_action = get(source_ratios, "operator_action", 0.0),
            core_decision = get(source_ratios, "core_decision", 0.0),
            passive_observation = get(source_ratios, "passive_observation", 0.0),
        ),
        dominant_source = observation.dominant_source,
        dominant_kind = observation.dominant_kind,
        flow_intensity = observation.intensity,
        summary = observation.summary,
    )
end

function write_observation_artifact(payload, path::AbstractString)
    artifact = observation_artifact(payload)
    open(path, "w") do io
        write(io, JSON3.write(artifact))
    end
    return artifact
end

function fetch_state_payload(; state_url::String=STATE_API_URL, timeout_seconds::Int=2)
    resp = HTTP.request(
        "GET",
        state_url;
        status_exception=false,
        connect_timeout=timeout_seconds,
        readtimeout=timeout_seconds,
    )
    resp.status == 200 || error("state request failed with status $(resp.status)")
    return JSON3.read(String(resp.body))
end

function main()
    state_url = length(ARGS) >= 1 ? ARGS[1] : STATE_API_URL
    output_path = length(ARGS) >= 2 ? ARGS[2] : ""
    payload = fetch_state_payload(; state_url=state_url)
    artifact = observation_artifact(payload)
    if !isempty(output_path)
        write_observation_artifact(payload, output_path)
    end
    println(JSON3.write(artifact))
end

if abspath(PROGRAM_FILE) == @__FILE__
    main()
end
