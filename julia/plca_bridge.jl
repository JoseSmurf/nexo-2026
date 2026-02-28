using Dates
using HTTP
using JSON3
using UUIDs
using Logging
using Blake3Hash

const API_URL = get(ENV, "NEXO_API_URL", "http://127.0.0.1:3000/evaluate")

const PESO_UTILIDADE  = 2//1
const PESO_PROBLEMA   = 3//5
const PESO_ESCALA     = 2//5
const PESO_TECNOLOGIA = 3//10
const SCORE_MAX       = BigFloat(20)

struct PlcaInput
    user_id::String
    problema::Int
    escala::Int
    tecnologia::Int
    ruido::Int
end

function validar_input(p::PlcaInput)::Bool
    isempty(strip(p.user_id)) && return false
    for v in (p.problema, p.escala, p.tecnologia, p.ruido)
        (v < 1 || v > 10) && return false
    end
    return true
end

function fator_ruido_rational(ruido::Int)::Rational{Int64}
    ruido >= 9 && return 1//2
    ruido <= 3 && return 3//2
    return 1//1
end

function plca_score_precise(p::PlcaInput)::BigFloat
    validar_input(p) || throw(ArgumentError("Invalid PLCA input (fields must be in 1..10)."))

    setprecision(BigFloat, 256) do
        utilidade = (p.problema * PESO_PROBLEMA) + (p.escala * PESO_ESCALA)
        score_r = (utilidade + (p.tecnologia * PESO_TECNOLOGIA)) * fator_ruido_rational(p.ruido) * PESO_UTILIDADE
        score_bf = BigFloat(numerator(score_r)) / BigFloat(denominator(score_r))
        return min(score_bf, SCORE_MAX)
    end
end

function score_to_risk_bps(score::BigFloat)::UInt16
    setprecision(BigFloat, 256) do
        ratio = clamp(score / SCORE_MAX, BigFloat(0), BigFloat("0.9999"))
        scaled = ratio * BigFloat(10_000)
        bps = Int(round(scaled, RoundNearestTiesAway))
        return UInt16(clamp(bps, 0, 9_999))
    end
end

function build_evaluate_request(
    p::PlcaInput;
    amount_cents::UInt64=50_000,
    is_pep::Bool=false,
    has_active_kyc::Bool=true,
    ui_hash_valid::Bool=true,
)
    score = plca_score_precise(p)
    risk_bps = score_to_risk_bps(score)
    now_ms = UInt64(round(Dates.datetime2unix(now(UTC)) * 1000))

    request_id = string(uuid4())
    payload = Dict(
        "user_id" => p.user_id,
        "amount_cents" => amount_cents,
        "is_pep" => is_pep,
        "has_active_kyc" => has_active_kyc,
        "timestamp_utc_ms" => now_ms,
        "risk_bps" => Int(risk_bps),
        "ui_hash_valid" => ui_hash_valid,
        "request_id" => request_id,
    )
    return payload, score, risk_bps, request_id, now_ms
end

function nexo_key_id()::String
    key_id = strip(get(ENV, "NEXO_HMAC_KEY_ID", "active"))
    isempty(key_id) && error("NEXO_HMAC_KEY_ID must not be empty")
    key_id
end

function read_secret_value(env_key::String)::String
    direct = strip(get(ENV, env_key, ""))
    if !isempty(direct)
        return direct
    end
    file_key = env_key * "_FILE"
    file_path = strip(get(ENV, file_key, ""))
    if !isempty(file_path)
        if !isfile(file_path)
            error("$(file_key) points to missing file: $(file_path)")
        end
        value = strip(read(file_path, String))
        isempty(value) && error("$(file_key) file is empty: $(file_path)")
        return value
    end
    error("$(env_key) is required (or $(file_key))")
end

function env_int(name::String, default::Int)::Int
    raw = strip(get(ENV, name, ""))
    isempty(raw) && return default
    parsed = tryparse(Int, raw)
    parsed === nothing && error("$(name) must be an integer")
    parsed <= 0 && error("$(name) must be > 0")
    parsed
end

function u32le(n::UInt32)
    UInt8[
        UInt8((n >> 0) & 0xff),
        UInt8((n >> 8) & 0xff),
        UInt8((n >> 16) & 0xff),
        UInt8((n >> 24) & 0xff),
    ]
end

function signing_message(key_id::String, request_id::String, timestamp_ms::UInt64, body::String)::Vector{UInt8}
    out = UInt8[]
    for part in (Vector{UInt8}(codeunits(key_id)),
                 Vector{UInt8}(codeunits(request_id)),
                 Vector{UInt8}(codeunits(string(timestamp_ms))),
                 Vector{UInt8}(codeunits(body)))
        append!(out, u32le(UInt32(length(part))))
        append!(out, part)
    end
    return out
end

function blake3_digest(data::Vector{UInt8})::Vector{UInt8}
    ctx = Blake3Ctx()
    update!(ctx, data)
    digest(ctx)
end

function hmac_blake3(body::String, secret::String, key_id::String, request_id::String, timestamp_ms::UInt64)::String
    block_size = 64
    key = Vector{UInt8}(codeunits(secret))
    if length(key) > block_size
        key = blake3_digest(key)
    end
    if length(key) < block_size
        key = vcat(key, zeros(UInt8, block_size - length(key)))
    end

    ipad = UInt8[(key[i] ⊻ 0x36) for i in 1:block_size]
    opad = UInt8[(key[i] ⊻ 0x5c) for i in 1:block_size]

    msg = signing_message(key_id, request_id, timestamp_ms, body)
    inner = blake3_digest(vcat(ipad, msg))
    outer = blake3_digest(vcat(opad, inner))
    bytes2hex(outer)
end

function write_canonical_json(io::IO, value)
    if value isa AbstractDict
        key_map = Dict{String, Any}()
        for original_key in keys(value)
            key_map[string(original_key)] = original_key
        end
        keys_sorted = sort!(collect(keys(key_map)))
        write(io, UInt8('{'))
        for (i, k) in enumerate(keys_sorted)
            i > 1 && write(io, UInt8(','))
            write(io, JSON3.write(k))
            write(io, UInt8(':'))
            write_canonical_json(io, value[key_map[k]])
        end
        write(io, UInt8('}'))
        return
    end
    if value isa AbstractVector
        write(io, UInt8('['))
        for (i, item) in enumerate(value)
            i > 1 && write(io, UInt8(','))
            write_canonical_json(io, item)
        end
        write(io, UInt8(']'))
        return
    end
    write(io, JSON3.write(value))
end

function canonical_json(payload::Dict{String, Any})::String
    io = IOBuffer()
    write_canonical_json(io, payload)
    String(take!(io))
end

function post_evaluate(payload::Dict{String, Any}, request_id::String, timestamp_ms::UInt64; api_url::String=API_URL, timeout_ms::Int=env_int("NEXO_HTTP_TIMEOUT_MS", 2500), max_retries::Int=env_int("NEXO_HTTP_MAX_RETRIES", 2))
    max_retries < 0 && error("max_retries must be >= 0")
    secret = read_secret_value("NEXO_HMAC_SECRET")
    key_id = nexo_key_id()
    body = canonical_json(payload)
    signature = hmac_blake3(body, secret, key_id, request_id, timestamp_ms)
    headers = [
        "Content-Type" => "application/json",
        "X-Signature" => signature,
        "X-Request-Id" => request_id,
        "X-Timestamp" => string(timestamp_ms),
        "X-Key-Id" => key_id,
    ]

    @info "julia_bridge_request_start" request_id=request_id timestamp_ms=timestamp_ms key_id=key_id timeout_ms=timeout_ms max_retries=max_retries payload_bytes=sizeof(body)
    timeout_s = max(1, cld(timeout_ms, 1000))
    attempts = max_retries + 1
    for attempt in 1:attempts
        started = time_ns()
        try
            resp = HTTP.request(
                "POST",
                api_url,
                headers,
                body;
                status_exception=false,
                connect_timeout=timeout_s,
                readtimeout=timeout_s,
            )
            elapsed_ms = round(Int, (time_ns() - started) / 1_000_000)
            code = resp.status
            if (code == 429 || code == 503) && attempt < attempts
                @warn "julia_bridge_request_retry" request_id=request_id status=code attempt=attempt elapsed_ms=elapsed_ms
                sleep(0.05 * attempt)
                continue
            end
            @info "julia_bridge_request_end" request_id=request_id status=code attempt=attempt elapsed_ms=elapsed_ms
            return code, String(resp.body)
        catch err
            elapsed_ms = round(Int, (time_ns() - started) / 1_000_000)
            if attempt < attempts
                @warn "julia_bridge_request_retry_error" request_id=request_id attempt=attempt elapsed_ms=elapsed_ms error=sprint(showerror, err)
                sleep(0.05 * attempt)
                continue
            end
            @error "julia_bridge_request_failed" request_id=request_id attempt=attempt elapsed_ms=elapsed_ms error=sprint(showerror, err)
            rethrow(err)
        end
    end

    error("unreachable: retries exhausted")
end

function main()
    # Deterministic self-check for the conversion boundaries.
    @assert score_to_risk_bps(BigFloat(0)) == 0
    @assert score_to_risk_bps(BigFloat(20)) == 9_999

    input = PlcaInput("julia_bridge_user", 8, 7, 9, 4)
    payload, score, risk_bps, request_id, timestamp_ms = build_evaluate_request(input; amount_cents=UInt64(150_000))

    println("PLCA score (BigFloat): ", score)
    println("risk_bps (UInt16): ", risk_bps)
    println("POST ", API_URL)

    status, body = post_evaluate(payload, request_id, timestamp_ms)
    println("HTTP status: ", status)
    println("Response: ", body)
end

if abspath(PROGRAM_FILE) == @__FILE__
    main()
end
