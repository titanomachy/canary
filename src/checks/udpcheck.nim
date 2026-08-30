import std/[monotimes, nativesockets, net, oserrors, strutils, times]
import ../[common, input_contract, network_target]

proc checkUdp*(host: string, port: int, payload: string = "ping",
               expected: string = "", timeoutMs: int = 5000): CheckResult =
  ## Check UDP reachability by receiving a response before the timeout.
  validateHostname(host)
  validatePort(port)
  validateCommon(timeoutMs, 1)
  let target = formatHostPort(host, port)
  let startTime = getMonoTime()
  var sockets: seq[Socket]

  template elapsedMs(): int =
    (getMonoTime() - startTime).inMilliseconds.int

  try:
    let endpoints = resolveNetworkEndpoints(
      host, port, SOCK_DGRAM, IPPROTO_UDP
    )
    for endpoint in endpoints:
      var candidate: Socket
      try:
        candidate = newSocket(endpoint.domain, SOCK_DGRAM, IPPROTO_UDP)
        candidate.sendTo(endpoint.address, Port(port), payload)
        sockets.add(candidate)
      except OSError, IOError:
        if candidate != nil:
          candidate.close()

    if sockets.len == 0:
      raise newException(IOError, "UDP datagram could not be sent")

    var readable: seq[SocketHandle]
    for socket in sockets:
      readable.add(socket.getFd())
    let waitMs = max(0, timeoutMs - elapsedMs())
    let ready = if waitMs > 0: selectRead(readable, waitMs) else: 0
    if ready == 0:
      let durationMs = elapsedMs()
      let msg = "UDP TIMEOUT - " & target & " - After " & $durationMs & "ms"
      return CheckResult(
        kind: "udp", target: target, isOk: false, message: msg,
        latencyMs: durationMs, details: "Timeout"
      )
    if ready < 0:
      raiseOSError(osLastError())

    var response = ""
    var responseHost = ""
    var responsePort: Port
    for socket in sockets:
      if socket.getFd() in readable:
        discard socket.recvFrom(response, 65_535, responseHost, responsePort)
        break
    let durationMs = elapsedMs()
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
    let durationMs = elapsedMs()
    let msg = "UDP ERROR - " & target & " - Socket operation failed"
    return CheckResult(kind: "udp", target: target, isOk: false, message: msg, latencyMs: durationMs, details: "Socket operation failed")
  except CatchableError:
    let durationMs = elapsedMs()
    let msg = "UDP ERROR - " & target & " - Unexpected socket error"
    return CheckResult(kind: "udp", target: target, isOk: false, message: msg, latencyMs: durationMs, details: "Unexpected socket error")
  finally:
    for socket in sockets:
      socket.close()
