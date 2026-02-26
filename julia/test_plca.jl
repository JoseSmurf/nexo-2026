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
end
