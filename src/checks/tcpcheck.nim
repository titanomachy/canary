import std/[monotimes, nativesockets, net, oserrors, strutils, times]
import ../[common, input_contract, network_target]

const TcpReadChunkBytes = 4096

proc elapsedMilliseconds(startTime: MonoTime): int =
  int((getMonoTime() - startTime).inMilliseconds)

proc remainingMilliseconds(startTime: MonoTime, timeoutMs: int): int =
  result = timeoutMs - elapsedMilliseconds(startTime)
  if result <= 0:
    raise newException(TimeoutError, "TCP probe timed out")

proc sendBeforeDeadline(socket: Socket, request: string,
                        startTime: MonoTime, timeoutMs: int) =
  var offset = 0
  while offset < request.len:
    var writable = @[socket.getFd()]
    let ready = selectWrite(
      writable, remainingMilliseconds(startTime, timeoutMs)
    )
    if ready == 0:
      raise newException(TimeoutError, "TCP probe timed out")
    if ready < 0:
      raiseOSError(osLastError())

    let sent = socket.send(
      cast[pointer](unsafeAddr request[offset]), request.len - offset
    )
    if sent < 0:
      raiseOSError(osLastError())
    if sent == 0:
      raise newException(IOError, "TCP connection closed while sending")
    inc offset, sent

proc receiveExpected(socket: Socket, expected: string,
                     startTime: MonoTime, timeoutMs: int): tuple[
                       matched: bool, bytesRead: int] =
  var response = ""
  while response.len < MaxTcpProbeBytes:
    var chunk = ""
    let received = socket.recv(
      chunk,
      min(TcpReadChunkBytes, MaxTcpProbeBytes - response.len),
      remainingMilliseconds(startTime, timeoutMs)
    )
    if received == 0:
      break
    response.add(chunk)
    if expected in response:
      return (true, response.len)
  (false, response.len)

proc connectBeforeDeadline(host: string, port: int, startTime: MonoTime,
                           timeoutMs: int): Socket =
  ## Try every address family returned by the system resolver while preserving
  ## one deadline for the complete TCP probe.
  let endpoints = resolveNetworkEndpoints(
    host, port, SOCK_STREAM, IPPROTO_TCP
  )
  for endpoint in endpoints:
    var candidate: Socket
    try:
      candidate = newSocket(endpoint.domain, SOCK_STREAM, IPPROTO_TCP)
      candidate.connect(
        endpoint.address,
        Port(port),
        remainingMilliseconds(startTime, timeoutMs)
      )
      return candidate
    except TimeoutError:
      if candidate != nil:
        candidate.close()
      raise
    except OSError, IOError:
      if candidate != nil:
        candidate.close()

  if elapsedMilliseconds(startTime) >= timeoutMs:
    raise newException(TimeoutError, "TCP probe timed out")
  raise newException(IOError, "TCP connection failed")

proc checkTcp*(host: string, port: int, timeoutMs: int = 5000,
               request: string = "", expected: string = ""): CheckResult =
  ## Connect, optionally send a request, and optionally match a response. An
  ## expectation without a request supports server-first banners such as SSH.
  validateHostname(host)
  validatePort(port)
  validateCommon(timeoutMs, 1)
  validateTcpProbe(request, expected)
  let target = formatHostPort(host, port)
  let startTime = getMonoTime()
  var sock: Socket
  var connected = false

  try:
    sock = connectBeforeDeadline(host, port, startTime, timeoutMs)
    connected = true
    if request.len > 0:
      sock.sendBeforeDeadline(request, startTime, timeoutMs)

    var details = ""
    if expected.len > 0:
      let response = sock.receiveExpected(expected, startTime, timeoutMs)
      if not response.matched:
        let durationMs = elapsedMilliseconds(startTime)
        let msg = "TCP ERROR - " & target &
          " - Expected response not received - Latency: " & $durationMs & "ms"
        return CheckResult(
          kind: "tcp", target: target, isOk: false, message: msg,
          latencyMs: durationMs,
          details: "Expected response not received (" & $response.bytesRead &
            " bytes received)"
        )
      details = "Expected response received (" & $response.bytesRead &
        " bytes read)"
    elif request.len > 0:
      details = "Request sent"

    let durationMs = elapsedMilliseconds(startTime)
    let msg = "TCP OK - " & target & " - Latency: " & $durationMs & "ms"
    return CheckResult(
      kind: "tcp", target: target, isOk: true, message: msg,
      latencyMs: durationMs, details: details
    )
  except TimeoutError:
    let durationMs = elapsedMilliseconds(startTime)
    let msg = "TCP TIMEOUT - " & target & " - After " & $durationMs & "ms"
    return CheckResult(
      kind: "tcp", target: target, isOk: false, message: msg,
      latencyMs: durationMs, details: "Timeout"
    )
  except OSError, IOError:
    let durationMs = elapsedMilliseconds(startTime)
    let details = if connected: "Socket operation failed" else: "Connection failed"
    let msg = "TCP ERROR - " & target & " - " & details
    return CheckResult(
      kind: "tcp", target: target, isOk: false, message: msg,
      latencyMs: durationMs, details: details
    )
  except CatchableError:
    let durationMs = elapsedMilliseconds(startTime)
    let msg = "TCP ERROR - " & target & " - Unexpected socket error"
    return CheckResult(
      kind: "tcp", target: target, isOk: false, message: msg,
      latencyMs: durationMs, details: "Unexpected socket error"
    )
  finally:
    if sock != nil:
      sock.close()
