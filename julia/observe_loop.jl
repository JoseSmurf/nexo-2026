include("flow_observer.jl")

function main_loop()
    state_url = length(ARGS) >= 1 ? ARGS[1] : STATE_API_URL
    output_dir = length(ARGS) >= 2 ? ARGS[2] : joinpath(pwd(), "observations")
    interval_seconds = length(ARGS) >= 3 ? something(tryparse(Float64, ARGS[3]), 3.0) : 3.0
    interval_seconds > 0 || error("poll interval must be > 0")

    while true
        payload = fetch_state_payload(; state_url=state_url)
        path, artifact = write_timestamped_observation(payload, output_dir)
        println(JSON3.write((path = path, artifact = artifact)))
        flush(stdout)
        sleep(interval_seconds)
    end
end

if abspath(PROGRAM_FILE) == @__FILE__
    main_loop()
end
