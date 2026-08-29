import std/[nativesockets, times]
import ../[common, input_contract]

proc checkDns*(hostname: string, expectedIp: string = ""): CheckResult =
  ## Resolve DNS and optionally verify the IP address.
  validateHostname(hostname)
  validateExpectedIp(expectedIp)
  let startTime = epochTime()
  try:
    let hostEnt = getHostByName(hostname)
    let durationMs = int((epochTime() - startTime) * 1000)

    if hostEnt.addrList.len == 0:
      let msg = "DNS ERROR - " & hostname & " did not resolve to an IP - Latency: " & $durationMs & "ms"
      return CheckResult(kind: "dns", target: hostname, isOk: false, message: msg, latencyMs: durationMs)

    let resolvedIp = hostEnt.addrList[0]

    if expectedIp.len > 0 and expectedIp != resolvedIp:
      let msg = "DNS ERROR - " & hostname & " resolved to " & resolvedIp & " (Expected: " & expectedIp & ") - Latency: " & $durationMs & "ms"
      return CheckResult(
        kind: "dns",
        target: hostname,
        isOk: false,
        message: msg,
        latencyMs: durationMs,
        details: "Resolved: " & resolvedIp & ", Expected: " & expectedIp
      )

    let msg = "DNS OK - " & hostname & " resolved to " & resolvedIp & " - Latency: " & $durationMs & "ms"
    return CheckResult(
      kind: "dns",
      target: hostname,
      isOk: true,
      message: msg,
      latencyMs: durationMs,
      details: "Resolved: " & resolvedIp
    )
  except OSError, IOError, ValueError:
    let durationMs = int((epochTime() - startTime) * 1000)
    let msg = "DNS ERROR - " & hostname & " could not be resolved - Latency: " & $durationMs & "ms"
    return CheckResult(kind: "dns", target: hostname, isOk: false, message: msg, latencyMs: durationMs, details: "Resolution failed")
  except CatchableError:
    let durationMs = int((epochTime() - startTime) * 1000)
    let msg = "DNS ERROR - " & hostname & " - Unexpected resolver error - Latency: " & $durationMs & "ms"
    return CheckResult(kind: "dns", target: hostname, isOk: false, message: msg, latencyMs: durationMs, details: "Unexpected resolver error")
