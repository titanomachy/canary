import std/[nativesockets, net, strutils, times]
import ../[common, input_contract]

proc checkUdp*(host: string, port: int, payload: string = "ping",
               expected: string = "", timeoutMs: int = 5000): CheckResult =
  ## Check UDP reachability by receiving a response before the timeout.
  validateHostname(host)
  validatePort(port)
  validateCommon(timeoutMs, 1)
  let target = host & ":" & $port
  let startTime = epochTime()
  var sock: Socket

  try:
    sock = newSocket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
    sock.sendTo(host, Port(port), payload)
    var readable = @[sock.getFd()]
    if selectRead(readable, timeoutMs) == 0:
      let durationMs = int((epochTime() - startTime) * 1000)
      let msg = "UDP TIMEOUT - " & target & " - After " & $durationMs & "ms"
      return CheckResult(
        kind: "udp", target: target, isOk: false, message: msg,
        latencyMs: durationMs, details: "Timeout"
      )

    var response = ""
    var responseHost = ""
    var responsePort: Port
    discard sock.recvFrom(response, 65_535, responseHost, responsePort)
    let durationMs = int((epochTime() - startTime) * 1000)
    if expected.len > 0 and expected notin response:
      let msg = "UDP ERROR - " & target & " - Expected response not received - Latency: " & $durationMs & "ms"
      return CheckResult(
        kind: "udp", target: target, isOk: false, message: msg,
        latencyMs: durationMs,
        details: "Expected: " & expected & ", Received: " & response.strip()
      )

    let msg = "UDP OK - " & target & " response received - Latency: " & $durationMs & "ms"
    return CheckResult(
      kind: "udp", target: target, isOk: true, message: msg,
      latencyMs: durationMs, details: "Response: " & response.strip()
    )
  except OSError, IOError:
    let durationMs = int((epochTime() - startTime) * 1000)
    let msg = "UDP ERROR - " & target & " - Socket operation failed"
    return CheckResult(kind: "udp", target: target, isOk: false, message: msg, latencyMs: durationMs, details: "Socket operation failed")
  except CatchableError:
    let durationMs = int((epochTime() - startTime) * 1000)
    let msg = "UDP ERROR - " & target & " - Unexpected socket error"
    return CheckResult(kind: "udp", target: target, isOk: false, message: msg, latencyMs: durationMs, details: "Unexpected socket error")
  finally:
    if sock != nil:
      sock.close()
