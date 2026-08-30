import std/[monotimes, net]
import ../[common, input_contract, network_target, process_runner]

proc checkIcmp*(host: string, count: int = 1, timeoutMs: int = 5000,
                runner: ProcessRunner = nil): CheckResult =
  ## Check ICMP reachability with a direct `ping` argv invocation.
  let startTime = getMonoTime()
  validateHostname(host)
  validatePacketCount(count)
  validateCommon(timeoutMs, 1)
  let networkHost = normalizedNetworkHost(host)

  when not defined(linux):
    raise newException(
      CanaryConfigError,
      "ICMP checks are supported only on Linux in Canary 0.1.x"
    )
  else:
    let execute = if runner.isNil: runProcess else: runner
    var args: seq[string]
    try:
      if parseIpAddress(networkHost).family == IpAddressFamily.IPv6:
        args.add("-6")
    except ValueError:
      discard
    args.add(@[
      "-c", $count, "-W", $max(1, timeoutMs div 1000), networkHost
    ])
    var execution: ProcessResult
    try:
      execution = execute(
        "ping",
        args,
        "",
        timeoutMs
      )
    except OSError, IOError:
      raise newException(
        CanaryConfigError,
        "ICMP check requires the 'ping' executable on PATH"
      )

    let durationMs = elapsedMilliseconds(startTime)
    if execution.timedOut:
      let msg = "ICMP TIMEOUT - " & networkHost & " - After " &
        $durationMs & "ms"
      return CheckResult(
        kind: "icmp", target: networkHost, isOk: false, message: msg,
        latencyMs: durationMs, details: "Timeout"
      )
    if execution.exitCode == 0:
      let msg = "ICMP OK - " & networkHost & " - Latency: " &
        $durationMs & "ms"
      return CheckResult(
        kind: "icmp", target: networkHost, isOk: true, message: msg,
        latencyMs: durationMs
      )

    let msg = "ICMP ERROR - " & networkHost & " unreachable - Latency: " &
      $durationMs & "ms"
    CheckResult(
      kind: "icmp", target: networkHost, isOk: false, message: msg,
      latencyMs: durationMs, details: "Ping failed"
    )
