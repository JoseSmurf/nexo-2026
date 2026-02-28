using Test

include("plca_bridge.jl")

@testset "PLCA score and risk_bps" begin
    @testset "1) score minimo input" begin
        p_min = PlcaInput("u_min", 1, 1, 1, 1)
        p_max = PlcaInput("u_max", 10, 10, 10, 1)

        s_min = plca_score_precise(p_min)
        s_max = plca_score_precise(p_max)
        r_min = score_to_risk_bps(s_min)
        r_max = score_to_risk_bps(s_max)

        @test s_min < s_max
        @test r_min < r_max
    end

    @testset "2) score maximo input com ruido=1" begin
        p = PlcaInput("u", 10, 10, 10, 1)
        s = plca_score_precise(p)
        r = score_to_risk_bps(s)

        @test s == SCORE_MAX
        @test r == UInt16(9_999)
    end

    @testset "3) ruido alto reduz score pela metade" begin
        p_base = PlcaInput("u", 3, 3, 3, 4)
        p_high_noise = PlcaInput("u", 3, 3, 3, 9)

        s_base = plca_score_precise(p_base)
        s_high_noise = plca_score_precise(p_high_noise)

        @test isapprox(s_high_noise * BigFloat(2), s_base; atol=BigFloat("1e-30"))
    end

    @testset "4) ruido baixo aumenta score" begin
        p_neutral = PlcaInput("u", 3, 3, 3, 4)
        p_low_noise = PlcaInput("u", 3, 3, 3, 3)

        s_neutral = plca_score_precise(p_neutral)
        s_low_noise = plca_score_precise(p_low_noise)

        @test s_low_noise > s_neutral
        @test fator_ruido_rational(3) == 3//2
    end

    @testset "5) conversao deterministica" begin
        p = PlcaInput("u_det", 6, 5, 7, 4)
        s = plca_score_precise(p)
        expected = score_to_risk_bps(s)

        for _ in 1:100
            @test score_to_risk_bps(plca_score_precise(p)) == expected
        end
    end

    @testset "6) boundary score=20.0" begin
        @test score_to_risk_bps(BigFloat(20.0)) == UInt16(9_999)
    end

    @testset "7) boundary score=0.0" begin
        @test score_to_risk_bps(BigFloat(0.0)) == UInt16(0)
    end

    @testset "8) secret vazio gera erro claro" begin
        had_secret = haskey(ENV, "NEXO_HMAC_SECRET")
        old_secret = had_secret ? ENV["NEXO_HMAC_SECRET"] : ""
        had_secret_file = haskey(ENV, "NEXO_HMAC_SECRET_FILE")
        old_secret_file = had_secret_file ? ENV["NEXO_HMAC_SECRET_FILE"] : ""
        try
            if had_secret
                delete!(ENV, "NEXO_HMAC_SECRET")
            end
            if had_secret_file
                delete!(ENV, "NEXO_HMAC_SECRET_FILE")
            end
            payload = Dict{String, Any}(
                "user_id" => "u1",
                "amount_cents" => 1000,
                "is_pep" => false,
                "has_active_kyc" => true,
                "timestamp_utc_ms" => 1,
                "risk_bps" => 10,
                "ui_hash_valid" => true,
                "request_id" => "req-1",
            )
            err = @test_throws Exception post_evaluate(payload, "req-1", UInt64(1); api_url="http://127.0.0.1:9/evaluate")
            msg = sprint(showerror, err.value)
            @test occursin("NEXO_HMAC_SECRET is required", msg)
        finally
            if had_secret
                ENV["NEXO_HMAC_SECRET"] = old_secret
            end
            if had_secret_file
                ENV["NEXO_HMAC_SECRET_FILE"] = old_secret_file
            end
        end
    end

    @testset "9) inputs invalidos sao rejeitados" begin
        @test_throws ArgumentError plca_score_precise(PlcaInput("u", 0, 1, 1, 1))
        @test_throws ArgumentError plca_score_precise(PlcaInput("u", 1, 11, 1, 1))
        @test_throws ArgumentError plca_score_precise(PlcaInput("   ", 1, 1, 1, 1))
    end

    @testset "10) serializacao canonica com chaves ordenadas" begin
        p1 = Dict{String, Any}()
        p1["b"] = 2
        p1["a"] = 1
        p1["c"] = true

        p2 = Dict{String, Any}()
        p2["c"] = true
        p2["a"] = 1
        p2["b"] = 2

        j1 = canonical_json(p1)
        j2 = canonical_json(p2)

        @test j1 == j2
        @test j1 == "{\"a\":1,\"b\":2,\"c\":true}"
    end

    @testset "10.1) serializacao canonica em nested payload" begin
        p1 = Dict{String, Any}()
        p1["z"] = [3, 2, 1]
        p1["inner"] = Dict("b" => 2, "a" => 1)

        p2 = Dict{String, Any}()
        p2["inner"] = Dict("a" => 1, "b" => 2)
        p2["z"] = [3, 2, 1]

        @test canonical_json(p1) == canonical_json(p2)
        @test canonical_json(p1) == "{\"inner\":{\"a\":1,\"b\":2},\"z\":[3,2,1]}"
    end

    @testset "11) arredondamento proximo de 20.0" begin
        @test score_to_risk_bps(BigFloat("19.9999")) == UInt16(9_999)
        @test score_to_risk_bps(BigFloat("19.99999999")) == UInt16(9_999)
    end

    @testset "12) secret por arquivo funciona" begin
        had_secret = haskey(ENV, "NEXO_HMAC_SECRET")
        old_secret = had_secret ? ENV["NEXO_HMAC_SECRET"] : ""
        had_secret_file = haskey(ENV, "NEXO_HMAC_SECRET_FILE")
        old_secret_file = had_secret_file ? ENV["NEXO_HMAC_SECRET_FILE"] : ""
        secret_path = tempname()
        try
            write(secret_path, "file-secret\n")
            had_secret && delete!(ENV, "NEXO_HMAC_SECRET")
            ENV["NEXO_HMAC_SECRET_FILE"] = secret_path
            @test read_secret_value("NEXO_HMAC_SECRET") == "file-secret"
        finally
            isfile(secret_path) && rm(secret_path)
            if had_secret
                ENV["NEXO_HMAC_SECRET"] = old_secret
            elseif haskey(ENV, "NEXO_HMAC_SECRET")
                delete!(ENV, "NEXO_HMAC_SECRET")
            end
            if had_secret_file
                ENV["NEXO_HMAC_SECRET_FILE"] = old_secret_file
            elseif haskey(ENV, "NEXO_HMAC_SECRET_FILE")
                delete!(ENV, "NEXO_HMAC_SECRET_FILE")
            end
        end
    end

    @testset "13) secret file invalido falha fechado" begin
        had_secret = haskey(ENV, "NEXO_HMAC_SECRET")
        old_secret = had_secret ? ENV["NEXO_HMAC_SECRET"] : ""
        had_secret_file = haskey(ENV, "NEXO_HMAC_SECRET_FILE")
        old_secret_file = had_secret_file ? ENV["NEXO_HMAC_SECRET_FILE"] : ""
        try
            had_secret && delete!(ENV, "NEXO_HMAC_SECRET")
            ENV["NEXO_HMAC_SECRET_FILE"] = "/tmp/does-not-exist-nexo.secret"
            err = @test_throws Exception read_secret_value("NEXO_HMAC_SECRET")
            @test occursin("points to missing file", sprint(showerror, err.value))
        finally
            if had_secret
                ENV["NEXO_HMAC_SECRET"] = old_secret
            elseif haskey(ENV, "NEXO_HMAC_SECRET")
                delete!(ENV, "NEXO_HMAC_SECRET")
            end
            if had_secret_file
                ENV["NEXO_HMAC_SECRET_FILE"] = old_secret_file
            elseif haskey(ENV, "NEXO_HMAC_SECRET_FILE")
                delete!(ENV, "NEXO_HMAC_SECRET_FILE")
            end
        end
    end

    @testset "14) retry/timeout fail-closed em erro de rede" begin
        had_secret = haskey(ENV, "NEXO_HMAC_SECRET")
        old_secret = had_secret ? ENV["NEXO_HMAC_SECRET"] : ""
        try
            ENV["NEXO_HMAC_SECRET"] = "retry-secret"
            payload = Dict{String, Any}(
                "user_id" => "u1",
                "amount_cents" => 1000,
                "is_pep" => false,
                "has_active_kyc" => true,
                "timestamp_utc_ms" => 1,
                "risk_bps" => 10,
                "ui_hash_valid" => true,
                "request_id" => "req-2",
            )
            @test_throws Exception post_evaluate(
                payload,
                "req-2",
                UInt64(1);
                api_url="http://127.0.0.1:9/evaluate",
                timeout_ms=150,
                max_retries=1,
            )
        finally
            if had_secret
                ENV["NEXO_HMAC_SECRET"] = old_secret
            elseif haskey(ENV, "NEXO_HMAC_SECRET")
                delete!(ENV, "NEXO_HMAC_SECRET")
            end
        end
    end
end
