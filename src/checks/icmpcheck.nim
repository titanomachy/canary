import std/times
import ../[common, input_contract, process_runner]

proc checkIcmp*(host: string, count: int = 1, timeoutMs: int = 5000,
                runner: ProcessRunner = nil): CheckResult =
  ## Check ICMP reachability with a direct `ping` argv invocation.
  validateHostname(host)
  validatePacketCount(count)
  validateCommon(timeoutMs, 1)

  when not defined(linux):
    raise newException(
      CanaryConfigError,
      "ICMP checks are supported only on Linux in Canary 0.1.x"
    )
  else:
    let execute = if runner.isNil: runProcess else: runner
    let startTime = epochTime()
    var execution: ProcessResult
    try:
      execution = execute(
        "ping",
        @["-c", $count, "-W", $max(1, timeoutMs div 1000), host],
        "",
        timeoutMs
      )
    except OSError, IOError:
      raise newException(
        CanaryConfigError,
        "ICMP check requires the 'ping' executable on PATH"
      )

    let durationMs = int((epochTime() - startTime) * 1000)
    if execution.timedOut:
      let msg = "ICMP TIMEOUT - " & host & " - After " & $durationMs & "ms"
      return CheckResult(
        kind: "icmp", target: host, isOk: false, message: msg,
        latencyMs: durationMs, details: "Timeout"
      )
    if execution.exitCode == 0:
      let msg = "ICMP OK - " & host & " - Latency: " & $durationMs & "ms"
      return CheckResult(
        kind: "icmp", target: host, isOk: true, message: msg,
        latencyMs: durationMs
      )

    let msg = "ICMP ERROR - " & host & " unreachable - Latency: " &
      $durationMs & "ms"
    CheckResult(
      kind: "icmp", target: host, isOk: false, message: msg,
      latencyMs: durationMs, details: "Ping failed"
    )
