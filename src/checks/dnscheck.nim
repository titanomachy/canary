import std/[algorithm, asyncdispatch, asyncnet, monotimes, net, strutils,
            sysrand, times]
import ../[common, input_contract, network_target]

type DnsProtocolError = object of CatchableError

const
  DnsHeaderLength = 12
  DnsClassInternet = 1

proc addUint16(buffer: var string, value: int) =
  buffer.add(char((value shr 8) and 0xff))
  buffer.add(char(value and 0xff))

proc readUint16(buffer: string, offset: int): int =
  if offset < 0 or offset + 2 > buffer.len:
    raise newException(DnsProtocolError, "Malformed DNS response")
  (ord(buffer[offset]) shl 8) or ord(buffer[offset + 1])

proc encodeDnsName(hostname: string): string =
  let name = hostname.strip(chars = {'.'}, leading = false, trailing = true)
  for label in name.split('.'):
    if label.len == 0 or label.len > 63:
      raise newException(DnsProtocolError, "Invalid DNS query name")
    result.add(char(label.len))
    result.add(label)
  result.add('\0')

proc decodeDnsName(message: string, offset: var int): string =
  var cursor = offset
  var jumped = false
  var jumps = 0
  var labels: seq[string]
  while true:
    if cursor >= message.len:
      raise newException(DnsProtocolError, "Malformed DNS response")
    let length = ord(message[cursor])
    if (length and 0xc0) == 0xc0:
      if cursor + 1 >= message.len:
        raise newException(DnsProtocolError, "Malformed DNS response")
      let pointer = ((length and 0x3f) shl 8) or ord(message[cursor + 1])
      if not jumped:
        offset = cursor + 2
        jumped = true
      cursor = pointer
      inc jumps
      if jumps > 32:
        raise newException(DnsProtocolError, "DNS compression pointer loop")
    elif length == 0:
      if not jumped:
        offset = cursor + 1
      break
    else:
      if (length and 0xc0) != 0 or cursor + 1 + length > message.len:
        raise newException(DnsProtocolError, "Malformed DNS response")
      labels.add(message[cursor + 1 .. cursor + length])
      cursor += length + 1
  labels.join(".").toLowerAscii()

proc dnsTypeCode(recordType: string): int =
  case normalizedDnsRecordType(recordType)
  of "A": 1
  of "CNAME": 5
  of "MX": 15
  of "TXT": 16
  of "AAAA": 28
  else: 0

proc newQueryId(): int =
  let bytes = urandom(2)
  (int(bytes[0]) shl 8) or int(bytes[1])

proc buildDnsQuery(hostname, recordType: string, queryId: int): string =
  result = newStringOfCap(512)
  result.addUint16(queryId)
  result.addUint16(0x0100) # Recursion desired.
  result.addUint16(1)
  result.addUint16(0)
  result.addUint16(0)
  result.addUint16(0)
  result.add(encodeDnsName(hostname))
  result.addUint16(dnsTypeCode(recordType))
  result.addUint16(DnsClassInternet)

proc dnsRcodeDescription(rcode: int): string =
  case rcode
  of 1: "Format error"
  of 2: "Resolver failure"
  of 3: "Name does not exist"
  of 4: "Query type is not supported"
  of 5: "Resolver refused the query"
  else: "DNS error " & $rcode

proc parseDnsResponse*(message: string, queryId: int,
                       recordType: string): seq[string] =
  ## Decode the supported answer RDATA types. Exported so malformed packet
  ## behavior can be unit-tested without network access.
  if message.len < DnsHeaderLength:
    raise newException(DnsProtocolError, "Malformed DNS response")
  if message.readUint16(0) != queryId:
    raise newException(DnsProtocolError, "DNS response ID did not match query")
  let flags = message.readUint16(2)
  if (flags and 0x8000) == 0:
    raise newException(DnsProtocolError, "Resolver returned a non-response packet")
  let rcode = flags and 0x000f
  if rcode != 0:
    raise newException(DnsProtocolError, dnsRcodeDescription(rcode))

  let questionCount = message.readUint16(4)
  let answerCount = message.readUint16(6)
  let requestedType = dnsTypeCode(recordType)
  var offset = DnsHeaderLength
  for _ in 0 ..< questionCount:
    discard decodeDnsName(message, offset)
    if offset + 4 > message.len:
      raise newException(DnsProtocolError, "Malformed DNS response")
    offset += 4

  for _ in 0 ..< answerCount:
    discard decodeDnsName(message, offset)
    if offset + 10 > message.len:
      raise newException(DnsProtocolError, "Malformed DNS response")
    let answerType = message.readUint16(offset)
    let answerClass = message.readUint16(offset + 2)
    let dataLength = message.readUint16(offset + 8)
    offset += 10
    let dataStart = offset
    let dataEnd = dataStart + dataLength
    if dataEnd > message.len:
      raise newException(DnsProtocolError, "Malformed DNS response")

    if answerType == requestedType and answerClass == DnsClassInternet:
      case answerType
      of 1:
        if dataLength != 4:
          raise newException(DnsProtocolError, "Malformed A record")
        var address = IpAddress(family: IpAddressFamily.IPv4)
        for index in 0 .. 3:
          address.address_v4[index] = uint8(ord(message[dataStart + index]))
        result.add($address)
      of 28:
        if dataLength != 16:
          raise newException(DnsProtocolError, "Malformed AAAA record")
        var address = IpAddress(family: IpAddressFamily.IPv6)
        for index in 0 .. 15:
          address.address_v6[index] = uint8(ord(message[dataStart + index]))
        result.add($address)
      of 5:
        var nameOffset = dataStart
        result.add(decodeDnsName(message, nameOffset))
        if nameOffset > dataEnd:
          raise newException(DnsProtocolError, "Malformed CNAME record")
      of 15:
        if dataLength < 3:
          raise newException(DnsProtocolError, "Malformed MX record")
        let priority = message.readUint16(dataStart)
        var nameOffset = dataStart + 2
        result.add($priority & " " & decodeDnsName(message, nameOffset))
        if nameOffset > dataEnd:
          raise newException(DnsProtocolError, "Malformed MX record")
      of 16:
        var textOffset = dataStart
        var value = ""
        while textOffset < dataEnd:
          let chunkLength = ord(message[textOffset])
          inc textOffset
          if textOffset + chunkLength > dataEnd:
            raise newException(DnsProtocolError, "Malformed TXT record")
          value.add(message[textOffset ..< textOffset + chunkLength])
          textOffset += chunkLength
        result.add(value)
      else:
        discard
    offset = dataEnd

  result.sort()
  var uniqueValues: seq[string]
  for value in result:
    if uniqueValues.len == 0 or uniqueValues[^1] != value:
      uniqueValues.add(value)
  result = uniqueValues

proc responseIsTruncated(message: string, queryId: int): bool =
  if message.len < DnsHeaderLength or message.readUint16(0) != queryId or
      (message.readUint16(2) and 0x8000) == 0:
    raise newException(DnsProtocolError, "Malformed DNS response envelope")
  (message.readUint16(2) and 0x0200) != 0

proc remainingMilliseconds(deadline: MonoTime): int =
  max(1, (deadline - getMonoTime()).inMilliseconds.int)

proc udpDnsQuery(query, resolverHost: string, resolverPort: int,
                 deadline: MonoTime): string =
  let family = parseIpAddress(resolverHost).family
  let domain = if family == IpAddressFamily.IPv6: AF_INET6 else: AF_INET
  let socket = newAsyncSocket(domain, SOCK_DGRAM, IPPROTO_UDP)
  defer: socket.close()
  let sendFuture = socket.sendTo(resolverHost, Port(resolverPort), query)
  if not waitFor(sendFuture.withTimeout(remainingMilliseconds(deadline))):
    raise newException(TimeoutError, "DNS query timed out")
  let receiveFuture = socket.recvFrom(65_535)
  if not waitFor(receiveFuture.withTimeout(remainingMilliseconds(deadline))):
    raise newException(TimeoutError, "DNS query timed out")
  receiveFuture.read().data

proc tcpDnsQuery(query, resolverHost: string, resolverPort: int,
                 deadline: MonoTime): string =
  let family = parseIpAddress(resolverHost).family
  let domain = if family == IpAddressFamily.IPv6: AF_INET6 else: AF_INET
  let socket = newSocket(domain, SOCK_STREAM, IPPROTO_TCP)
  defer: socket.close()
  socket.connect(
    resolverHost, Port(resolverPort), remainingMilliseconds(deadline)
  )
  var framed = ""
  framed.addUint16(query.len)
  framed.add(query)
  socket.send(framed)
  let sizeBytes = socket.recv(2, remainingMilliseconds(deadline))
  if sizeBytes.len != 2:
    raise newException(DnsProtocolError, "Incomplete DNS TCP response")
  let responseLength = sizeBytes.readUint16(0)
  if responseLength < DnsHeaderLength:
    raise newException(DnsProtocolError, "Malformed DNS TCP response")
  result = socket.recv(responseLength, remainingMilliseconds(deadline))
  if result.len != responseLength:
    raise newException(DnsProtocolError, "Incomplete DNS TCP response")

proc systemResolver(): string =
  try:
    for line in lines("/etc/resolv.conf"):
      let components = line.splitWhitespace()
      if components.len >= 2 and components[0] == "nameserver":
        var candidate = components[1]
        let zone = candidate.find('%')
        if zone >= 0:
          candidate = candidate[0 ..< zone]
        try:
          discard parseIpAddress(candidate)
          return candidate
        except ValueError:
          discard
  except IOError, OSError:
    discard
  raise newException(DnsProtocolError, "No system DNS resolver is configured")

proc hostsFileValues(hostname, recordType: string): seq[string] =
  if recordType notin ["A", "AAAA"]:
    return
  let requestedName = hostname.strip(
    chars = {'.'}, leading = false, trailing = true
  ).toLowerAscii()
  try:
    for line in lines("/etc/hosts"):
      let content = line.split('#', maxsplit = 1)[0]
      let components = content.splitWhitespace()
      if components.len < 2:
        continue
      var address: IpAddress
      try:
        address = parseIpAddress(components[0])
      except ValueError:
        continue
      let addressType =
        if address.family == IpAddressFamily.IPv4: "A" else: "AAAA"
      if addressType != recordType:
        continue
      for alias in components[1 .. ^1]:
        if alias.toLowerAscii() == requestedName:
          result.add($address)
          break
  except IOError, OSError:
    discard
  result.sort()

proc normalizeExpected(recordType, value: string): string =
  case recordType
  of "A", "AAAA":
    $parseIpAddress(value)
  of "CNAME":
    value.strip(chars = {'.'}, leading = false, trailing = true).toLowerAscii()
  of "MX":
    let components = value.splitWhitespace()
    $parseInt(components[0]) & " " & components[1].strip(
      chars = {'.'}, leading = false, trailing = true
    ).toLowerAscii()
  else:
    value

proc missingExpectedValues(recordType: string, expectedValues,
                           actualValues: openArray[string]): seq[string] =
  for expected in expectedValues:
    let normalized = normalizeExpected(recordType, expected)
    if normalized notin actualValues and normalized notin result:
      result.add(normalized)

proc checkDns*(hostname: string, recordType: string = "A",
               expectedValues: seq[string] = @[], resolver: string = "",
               timeoutMs: int = 5000): CheckResult =
  ## Query a bounded DNS resolver operation and require every configured
  ## expected value. Additional answers are allowed.
  validateHostname(hostname)
  validateCommon(timeoutMs, 1)
  let target = normalizedNetworkHost(hostname)
  let normalizedType = normalizedDnsRecordType(recordType)
  validateDnsExpectedValues(normalizedType, expectedValues)
  let configuredResolver = splitDnsResolver(resolver)
  let startTime = getMonoTime()

  template elapsedMs(): int =
    (getMonoTime() - startTime).inMilliseconds.int

  try:
    var values: seq[string]
    if resolver.len == 0:
      values = hostsFileValues(target, normalizedType)
      if values.len == 0:
        try:
          let literal = parseIpAddress(target)
          if (normalizedType == "A" and
              literal.family == IpAddressFamily.IPv4) or
              (normalizedType == "AAAA" and
              literal.family == IpAddressFamily.IPv6):
            values = @[$literal]
        except ValueError:
          discard

    if values.len == 0:
      let resolverHost =
        if configuredResolver.host.len > 0: configuredResolver.host
        else: systemResolver()
      let queryId = newQueryId()
      let query = buildDnsQuery(target, normalizedType, queryId)
      let deadline = startTime + initDuration(milliseconds = timeoutMs)
      let udpResponse = udpDnsQuery(
        query, resolverHost, configuredResolver.port, deadline
      )
      let response =
        if responseIsTruncated(udpResponse, queryId):
          tcpDnsQuery(query, resolverHost, configuredResolver.port, deadline)
        else:
          udpResponse
      values = parseDnsResponse(response, queryId, normalizedType)

    let durationMs = elapsedMs()
    if values.len == 0:
      let message = "DNS ERROR - " & target & " has no " &
        normalizedType & " records - Latency: " & $durationMs & "ms"
      return CheckResult(
        kind: "dns", target: target, isOk: false, message: message,
        latencyMs: durationMs, details: "Type: " & normalizedType &
          ", Answers: none"
      )

    let missing = missingExpectedValues(
      normalizedType, expectedValues, values
    )
    let answers = values.join(", ")
    if missing.len > 0:
      let message = "DNS ERROR - " & target & " " & normalizedType &
        " records did not include expected values - Latency: " &
        $durationMs & "ms"
      return CheckResult(
        kind: "dns", target: target, isOk: false, message: message,
        latencyMs: durationMs, details: "Answers: " & answers &
          ", Missing: " & missing.join(", ")
      )

    let message = "DNS OK - " & target & " " & normalizedType &
      " records: " & answers & " - Latency: " & $durationMs & "ms"
    CheckResult(
      kind: "dns", target: target, isOk: true, message: message,
      latencyMs: durationMs, details: "Type: " & normalizedType &
        ", Answers: " & answers
    )
  except TimeoutError:
    let durationMs = elapsedMs()
    CheckResult(
      kind: "dns", target: target, isOk: false,
      message: "DNS ERROR - " & target & " query timed out - Latency: " &
        $durationMs & "ms",
      latencyMs: durationMs, details: "Timeout"
    )
  except DnsProtocolError:
    let durationMs = elapsedMs()
    CheckResult(
      kind: "dns", target: target, isOk: false,
      message: "DNS ERROR - " & target & " could not be resolved - Latency: " &
        $durationMs & "ms",
      latencyMs: durationMs, details: getCurrentExceptionMsg()
    )
  except OSError, IOError:
    let durationMs = elapsedMs()
    CheckResult(
      kind: "dns", target: target, isOk: false,
      message: "DNS ERROR - " & target & " could not be resolved - Latency: " &
        $durationMs & "ms",
      latencyMs: durationMs, details: "Resolver transport failed"
    )
  except CatchableError:
    let durationMs = elapsedMs()
    CheckResult(
      kind: "dns", target: target, isOk: false,
      message: "DNS ERROR - " & target &
        " - Unexpected resolver error - Latency: " & $durationMs & "ms",
      latencyMs: durationMs, details: "Unexpected resolver error"
    )
