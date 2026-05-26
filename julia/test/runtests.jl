using Test

# Canonical Julia unit test entrypoint for CI/local runs.
include("../test_plca.jl")
include("../test_flow_observer.jl")
include("../test_sync_economics_observer.jl")
include("../test_residual_signal_classifier.jl")
