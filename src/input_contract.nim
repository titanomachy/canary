import std/[net, strutils, uri]
import common

const
  MinHttpStatus = 100
  MaxHttpStatus = 599
  MaxIcmpPacketCount* = 100

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

proc validatePort*(port: int) =
  ## Validate a TCP or UDP port number.
  if port < 1 or port > 65535:
    configError("port must be between 1 and 65535")

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
    result = target
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

proc validateHttp*(target: string, timeout: int, retries: int,
                   expectedStatus: int, maxRedirects: int,
                   methodStr: string) =
  ## Validate HTTP-specific input before opening a network connection.
  validateCommon(timeout, retries)
  if expectedStatus < MinHttpStatus or expectedStatus > MaxHttpStatus:
    configError("HTTP status must be between 100 and 599")
  if maxRedirects < 0:
    configError("maxRedirects cannot be negative")
  if methodStr.toUpperAscii() notin
      ["GET", "POST", "HEAD", "PUT", "DELETE", "PATCH", "OPTIONS"]:
    configError("unsupported HTTP method: " & methodStr)

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
