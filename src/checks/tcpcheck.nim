import std/[net, times]
import ../[common, input_contract]

proc checkTcp*(host: string, port: int, timeoutMs: int = 5000): CheckResult =
  ## Check if a TCP port is open on the given host.
  validateHostname(host)
  validatePort(port)
  validateCommon(timeoutMs, 1)
  let target = host & ":" & $port
  let startTime = epochTime()
  var sock: Socket

  try:
    sock = newSocket()
    sock.connect(host, Port(port), timeoutMs)
    let durationMs = int((epochTime() - startTime) * 1000)
    let msg = "TCP OK - " & target & " - Latency: " & $durationMs & "ms"
    return CheckResult(kind: "tcp", target: target, isOk: true, message: msg, latencyMs: durationMs)
  except TimeoutError:
    let durationMs = int((epochTime() - startTime) * 1000)
    let msg = "TCP TIMEOUT - " & target & " - After " & $durationMs & "ms"
    return CheckResult(kind: "tcp", target: target, isOk: false, message: msg, latencyMs: durationMs, details: "Timeout")
  except OSError, IOError:
    let durationMs = int((epochTime() - startTime) * 1000)
    let msg = "TCP ERROR - " & target & " - Connection failed"
    return CheckResult(kind: "tcp", target: target, isOk: false, message: msg, latencyMs: durationMs, details: "Connection failed")
  except CatchableError:
    let durationMs = int((epochTime() - startTime) * 1000)
    let msg = "TCP ERROR - " & target & " - Unexpected socket error"
    return CheckResult(kind: "tcp", target: target, isOk: false, message: msg, latencyMs: durationMs, details: "Unexpected socket error")
  finally:
    if sock != nil:
      sock.close()
