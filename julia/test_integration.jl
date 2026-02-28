using Test
using HTTP
using JSON3

include("plca_bridge.jl")

const ROOT_DIR = normpath(joinpath(@__DIR__, ".."))
const API_BASE = "http://127.0.0.1:3000"
const API_EVAL = API_BASE * "/evaluate"

function wait_for_health(url::String; timeout_seconds::Int=420)
    deadline = time() + timeout_seconds
    while time() < deadline
        try
            resp = HTTP.request(
                "GET",
                url;
                status_exception=false,
                connect_timeout=1,
                readtimeout=1,
            )
            if resp.status == 200
                return true
            end
        catch
        end
        sleep(1.0)
    end
    return false
end

@testset "Julia bridge integration -> Rust API" begin
    secret_path = tempname()
    write(secret_path, "integration-secret\n")

    server_env = copy(ENV)
    server_env["NEXO_HMAC_SECRET"] = "integration-secret"
    server_env["NEXO_HMAC_KEY_ID"] = "active"
    server_env["RUST_LOG"] = "warn"

    cmd = Cmd(`cargo run --quiet --bin syntax-engine`; dir=ROOT_DIR)
    server_log = tempname()
    log_io = open(server_log, "w")
    proc = run(
        pipeline(setenv(cmd, server_env), stdout=log_io, stderr=log_io);
        wait=false,
    )

    try
        healthy = wait_for_health(API_BASE * "/healthz")
        @test healthy
        healthy || error("API did not become healthy. Server log:\n" * read(server_log, String))

        old_secret = get(ENV, "NEXO_HMAC_SECRET", nothing)
        old_secret_file = get(ENV, "NEXO_HMAC_SECRET_FILE", nothing)
        old_key_id = get(ENV, "NEXO_HMAC_KEY_ID", nothing)

        try
            if haskey(ENV, "NEXO_HMAC_SECRET")
                delete!(ENV, "NEXO_HMAC_SECRET")
            end
            ENV["NEXO_HMAC_SECRET_FILE"] = secret_path
            ENV["NEXO_HMAC_KEY_ID"] = "active"

            input = PlcaInput("julia_integration_user", 8, 6, 7, 4)
            payload, _score, _risk, request_id, ts = build_evaluate_request(
                input;
                amount_cents=UInt64(150_000),
                has_active_kyc=true,
                is_pep=false,
                ui_hash_valid=true,
            )
            status, body = post_evaluate(
                payload,
                request_id,
                ts;
                api_url=API_EVAL,
                timeout_ms=2_500,
                max_retries=1,
            )

            @test status == 200
            parsed = JSON3.read(body)
            @test hasproperty(parsed, :final_decision)
            @test hasproperty(parsed, :trace)
            @test hasproperty(parsed, :audit_hash)
            @test hasproperty(parsed, :auth_key_id)
            @test String(parsed.auth_key_id) == "active"
        finally
            if old_secret === nothing
                if haskey(ENV, "NEXO_HMAC_SECRET")
                    delete!(ENV, "NEXO_HMAC_SECRET")
                end
            else
                ENV["NEXO_HMAC_SECRET"] = old_secret
            end
            if old_secret_file === nothing
                if haskey(ENV, "NEXO_HMAC_SECRET_FILE")
                    delete!(ENV, "NEXO_HMAC_SECRET_FILE")
                end
            else
                ENV["NEXO_HMAC_SECRET_FILE"] = old_secret_file
            end
            if old_key_id === nothing
                if haskey(ENV, "NEXO_HMAC_KEY_ID")
                    delete!(ENV, "NEXO_HMAC_KEY_ID")
                end
            else
                ENV["NEXO_HMAC_KEY_ID"] = old_key_id
            end
        end
    finally
        try
            kill(proc)
        catch
        end
        try
            wait(proc)
        catch
        end
        close(log_io)
        rm(secret_path; force=true)
        rm(server_log; force=true)
    end
end
