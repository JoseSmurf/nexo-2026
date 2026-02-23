using Dates
using HTTP
using JSON3
using UUIDs
using Blake3Hash

const API_URL = get(ENV, "NEXO_API_URL", "http://127.0.0.1:3000/evaluate")
const NEXO_KEY_ID = get(ENV, "NEXO_HMAC_KEY_ID", "active")

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

function post_evaluate(payload::Dict{String, Any}, request_id::String, timestamp_ms::UInt64; api_url::String=API_URL)
    secret = get(ENV, "NEXO_HMAC_SECRET", "")
    isempty(secret) && error("NEXO_HMAC_SECRET is required")
    body = JSON3.write(payload)
    signature = hmac_blake3(body, secret, NEXO_KEY_ID, request_id, timestamp_ms)
    headers = [
        "Content-Type" => "application/json",
        "X-Signature" => signature,
        "X-Request-Id" => request_id,
        "X-Timestamp" => string(timestamp_ms),
        "X-Key-Id" => NEXO_KEY_ID,
    ]
    resp = HTTP.request("POST", api_url, headers, body)
    return resp.status, String(resp.body)
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
