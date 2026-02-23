using Dates
using HTTP
using JSON3

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

    payload = Dict(
        "user_id" => p.user_id,
        "amount_cents" => amount_cents,
        "is_pep" => is_pep,
        "has_active_kyc" => has_active_kyc,
        "timestamp_utc_ms" => now_ms,
        "risk_bps" => Int(risk_bps),
        "ui_hash_valid" => ui_hash_valid,
    )
    return payload, score, risk_bps
end

function post_evaluate(payload::Dict{String, Any}; api_url::String=API_URL)
    body = JSON3.write(payload)
    resp = HTTP.request("POST", api_url, ["Content-Type" => "application/json"], body)
    return resp.status, String(resp.body)
end

function main()
    # Deterministic self-check for the conversion boundaries.
    @assert score_to_risk_bps(BigFloat(0)) == 0
    @assert score_to_risk_bps(BigFloat(20)) == 9_999

    input = PlcaInput("julia_bridge_user", 8, 7, 9, 4)
    payload, score, risk_bps = build_evaluate_request(input; amount_cents=UInt64(150_000))

    println("PLCA score (BigFloat): ", score)
    println("risk_bps (UInt16): ", risk_bps)
    println("POST ", API_URL)

    status, body = post_evaluate(payload)
    println("HTTP status: ", status)
    println("Response: ", body)
end

if abspath(PROGRAM_FILE) == @__FILE__
    main()
end
