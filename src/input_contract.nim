import std/[net, re, strutils, uri]
import common
import network_target

const
  MinHttpStatus = 100
  MaxHttpStatus = 599
  MaxIcmpPacketCount* = 100
  MaxTcpProbeBytes* = 65_536

proc configError(message: string) {.noreturn.} =
  raise newException(CanaryConfigError, message)

proc validateCommon*(timeout: int, retries: int) =
  ## Validate options shared by checks with a timeout and retry threshold.
  if timeout <= 0:
    configError("timeout must be greater than zero")
  if retries < 1:
    configError("retries must be at least 1")

proc validateRetries*(retries: int) =
  ## Validate a retry threshold for checks without a timeout option.
  if retries < 1:
    configError("retries must be at least 1")

proc validateRecoveryThreshold*(threshold: int) =
  if threshold < 1:
    configError("recoveryThreshold must be at least 1")

proc validateNotificationInterval*(name: string, seconds: int) =
  if seconds < 0:
    configError(name & " must be zero or greater")

proc validatePort*(port: int) =
  ## Validate a TCP or UDP port number.
  if port < 1 or port > 65535:
    configError("port must be between 1 and 65535")

proc validateTcpProbe*(request, expected: string) =
  ## Bound operator-controlled probe data and the response buffer needed to
  ## search for it. Protocol bytes, including newlines and NULs, stay valid.
  if request.len > MaxTcpProbeBytes:
    configError("TCP request must not exceed " & $MaxTcpProbeBytes & " bytes")
  if expected.len > MaxTcpProbeBytes:
    configError(
      "TCP expected response must not exceed " & $MaxTcpProbeBytes & " bytes"
    )

proc validatePacketCount*(count: int) =
  if count < 1 or count > MaxIcmpPacketCount:
    configError("count must be between 1 and " & $MaxIcmpPacketCount)

proc validateHostname*(hostname: string) =
  ## Accept DNS hostnames and literal IPv4/IPv6 addresses, but no URL syntax,
  ## whitespace, control characters, or command-line fragments.
  if hostname.len == 0 or hostname.len > 253 or hostname != hostname.strip():
    configError("hostname is invalid")

  var ipCandidate = hostname
  if hostname.startsWith('[') and hostname.endsWith(']'):
    ipCandidate = hostname[1 .. ^2]
  try:
    discard parseIpAddress(ipCandidate)
    return
  except ValueError:
    discard

  var dnsName = hostname
  if dnsName.endsWith('.'):
    dnsName.setLen(dnsName.len - 1)
  if dnsName.len == 0:
    configError("hostname is invalid")
  for label in dnsName.split('.'):
    if label.len == 0 or label.len > 63 or label[0] == '-' or label[^1] == '-':
      configError("hostname is invalid")
    for character in label:
      if not character.isAlphaNumeric() and character != '-':
        configError("hostname is invalid")

proc validateExpectedIp*(expectedIp: string) =
  if expectedIp.len == 0:
    return
  try:
    discard parseIpAddress(expectedIp)
  except ValueError:
    configError("expected must be a valid IPv4 or IPv6 address")

proc normalizedDnsRecordType*(recordType: string): string =
  result = recordType.strip().toUpperAscii()
  if result notin ["A", "AAAA", "CNAME", "MX", "TXT"]:
    configError("DNS type must be one of A, AAAA, CNAME, MX, or TXT")

proc splitDnsResolver*(resolver: string): tuple[host: string, port: int] =
  ## Resolver selection deliberately accepts only an IP literal, optionally
  ## followed by a port. Resolving a resolver hostname through DNS would be
  ## recursive and would make the selected resolver ambiguous.
  if resolver.len == 0:
    return ("", 53)

  var host = resolver
  var port = 53
  if resolver.startsWith('['):
    let closing = resolver.find(']')
    if closing < 0:
      configError("resolver must be an IP address with an optional port")
    host = resolver[1 ..< closing]
    if closing + 1 < resolver.len:
      if resolver[closing + 1] != ':' or closing + 2 >= resolver.len:
        configError("resolver must be an IP address with an optional port")
      try:
        port = parseInt(resolver[closing + 2 .. ^1])
      except ValueError:
        configError("resolver port must be between 1 and 65535")
  else:
    try:
      discard parseIpAddress(resolver)
    except ValueError:
      let separator = resolver.rfind(':')
      if separator <= 0:
        configError("resolver must be an IP address with an optional port")
      host = resolver[0 ..< separator]
      try:
        port = parseInt(resolver[separator + 1 .. ^1])
      except ValueError:
        configError("resolver port must be between 1 and 65535")

  try:
    discard parseIpAddress(host)
  except ValueError:
    configError("resolver must be an IP address with an optional port")
  validatePort(port)
  result = (host, port)

proc validateDnsExpectedValues*(recordType: string,
                                expectedValues: openArray[string]) =
  let normalizedType = normalizedDnsRecordType(recordType)
  for expected in expectedValues:
    if expected.len == 0 or expected != expected.strip():
      configError("DNS expected values cannot be empty or contain surrounding whitespace")
    case normalizedType
    of "A":
      try:
        if parseIpAddress(expected).family != IpAddressFamily.IPv4:
          configError("A expectations must be IPv4 addresses")
      except ValueError:
        configError("A expectations must be IPv4 addresses")
    of "AAAA":
      try:
        if parseIpAddress(expected).family != IpAddressFamily.IPv6:
          configError("AAAA expectations must be IPv6 addresses")
      except ValueError:
        configError("AAAA expectations must be IPv6 addresses")
    of "CNAME":
      validateHostname(expected)
      var isIpAddress = false
      try:
        discard parseIpAddress(expected)
        isIpAddress = true
      except ValueError:
        discard
      if isIpAddress:
        configError("CNAME expectations must be domain names")
    of "MX":
      let components = expected.splitWhitespace()
      if components.len != 2:
        configError("MX expectations must use 'priority hostname'")
      try:
        let priority = parseInt(components[0])
        if priority < 0 or priority > 65535:
          configError("MX priority must be between 0 and 65535")
      except ValueError:
        configError("MX priority must be between 0 and 65535")
      validateHostname(components[1])
    of "TXT":
      for character in expected:
        if ord(character) < 32 and character notin {'\t'}:
          configError("TXT expectations must not contain control characters")
    else:
      discard

proc hostnameFromSslTarget*(target: string): string =
  ## SSL accepts either a bare hostname/IP address or an HTTP(S) URL.
  if "://" in target:
    try:
      let parsed = parseUri(target)
      if parsed.scheme notin ["http", "https"] or parsed.hostname.len == 0:
        configError("SSL target must be a hostname or an http(s) URL")
      result = parsed.hostname
    except UriParseError:
      configError("SSL target must be a hostname or an http(s) URL")
  else:
    result = normalizedNetworkHost(target)
  validateHostname(result)

proc validateHttpHeaders*(rawHeaders: string) =
  ## Validate the CLI's comma/semicolon/newline-separated header syntax and
  ## reject malformed names instead of silently ignoring them.
  if rawHeaders.len == 0:
    return
  var lines: seq[string]
  if '\n' in rawHeaders or '\r' in rawHeaders:
    lines = rawHeaders.splitLines()
  elif ';' in rawHeaders:
    lines = rawHeaders.split(';')
  else:
    lines = rawHeaders.split(',')

  for line in lines:
    let trimmed = line.strip()
    if trimmed.len == 0:
      continue
    let separator = trimmed.find(':')
    if separator <= 0:
      configError("each HTTP header must use the 'Name: Value' format")
    for character in trimmed[0 ..< separator]:
      if not character.isAlphaNumeric() and character notin {'-', '_'}:
        configError("HTTP header name is invalid")

proc parseStatusSelector(selector: string): tuple[first, last: int] =
  let value = selector.strip().toLowerAscii()
  if value.len == 3 and value[0] in {'1' .. '5'} and
      value[1] == 'x' and value[2] == 'x':
    result.first = parseInt($value[0]) * 100
    result.last = result.first + 99
  elif '-' in value:
    let bounds = value.split('-', maxsplit = 1)
    if bounds.len != 2:
      configError("HTTP status range is invalid")
    try:
      result = (parseInt(bounds[0].strip()), parseInt(bounds[1].strip()))
    except ValueError:
      configError("HTTP status range is invalid")
  else:
    try:
      result.first = parseInt(value)
      result.last = result.first
    except ValueError:
      configError("HTTP status range is invalid")

  if result.first < MinHttpStatus or result.last > MaxHttpStatus or
      result.first > result.last:
    configError("HTTP status range must contain values between 100 and 599")

proc validateStatusRange*(statusRange: string) =
  ## Accept comma-separated exact codes, inclusive ranges, and classes such
  ## as `2xx`. An empty value leaves the exact `--status` assertion active.
  if statusRange.len == 0:
    return
  for selector in statusRange.split(','):
    if selector.strip().len == 0:
      configError("HTTP status range is invalid")
    discard parseStatusSelector(selector)

proc statusAccepted*(statusCode, expectedStatus: int,
                     statusRange: string): bool =
  if statusRange.len == 0:
    return statusCode == expectedStatus
  for selector in statusRange.split(','):
    let accepted = parseStatusSelector(selector)
    if statusCode >= accepted.first and statusCode <= accepted.last:
      return true

proc expectedStatusDescription*(expectedStatus: int,
                                statusRange: string): string =
  if statusRange.len > 0: statusRange else: $expectedStatus

proc validateResponseHeader*(expectation: string) =
  ## `Name` checks presence; `Name: value` additionally checks that the
  ## response value contains the configured text.
  if expectation.len == 0:
    return
  let separator = expectation.find(':')
  let name = if separator < 0: expectation.strip()
             else: expectation[0 ..< separator].strip()
  if name.len == 0:
    configError("responseHeader must contain a valid header name")
  for character in name:
    if not character.isAlphaNumeric() and character notin {'-', '_'}:
      configError("responseHeader must contain a valid header name")

proc validateJsonField*(expectation: string) =
  ## JSON assertions use `object.path=value`; numeric path elements address
  ## arrays. Values are compared using their plain scalar representation.
  if expectation.len == 0:
    return
  let separator = expectation.find('=')
  if separator <= 0:
    configError("jsonField must use the 'path=value' format")
  let path = expectation[0 ..< separator].strip()
  if path.len == 0:
    configError("jsonField path cannot be empty")
  for part in path.split('.'):
    if part.len == 0:
      configError("jsonField path cannot contain empty elements")

proc validateHttp*(target: string, timeout: int, retries: int,
                   expectedStatus: int, maxRedirects: int,
                   methodStr: string, statusRange: string = "",
                   maxLatencyMs: int = 0, responseHeader: string = "",
                   bodyRegex: string = "", jsonField: string = "") =
  ## Validate HTTP-specific input before opening a network connection.
  validateCommon(timeout, retries)
  if expectedStatus < MinHttpStatus or expectedStatus > MaxHttpStatus:
    configError("HTTP status must be between 100 and 599")
  if maxRedirects < 0:
    configError("maxRedirects cannot be negative")
  if maxLatencyMs < 0:
    configError("maxLatency cannot be negative")
  if methodStr.toUpperAscii() notin
      ["GET", "POST", "HEAD", "PUT", "DELETE", "PATCH", "OPTIONS"]:
    configError("unsupported HTTP method: " & methodStr)
  validateStatusRange(statusRange)
  validateResponseHeader(responseHeader)
  validateJsonField(jsonField)
  if bodyRegex.len > 0:
    try:
      discard re(bodyRegex)
    except RegexError:
      configError("regex is invalid")

  try:
    let parsed = parseUri(target)
    if parsed.scheme notin ["http", "https"] or parsed.hostname.len == 0:
      configError("URL must contain an http(s) scheme and hostname")
    validateHostname(parsed.hostname)
  except UriParseError:
    configError("URL must contain an http(s) scheme and hostname")

proc makeCheckId*(kind: string, target: string, port: int = 0): string =
  ## Build a stable state-store identifier without URL secrets or query values.
  result = kind & "_" & publicTarget(target)
  if port != 0:
    result.add("_" & $port)
