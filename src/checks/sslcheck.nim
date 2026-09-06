import std/[monotimes, strutils, times]
import ../[common, input_contract, network_target, process_runner]

proc firstCertificate(output: string): string =
  const
    BeginCertificate = "-----BEGIN CERTIFICATE-----"
    EndCertificate = "-----END CERTIFICATE-----"
  let startIndex = output.find(BeginCertificate)
  if startIndex < 0:
    return ""
  let endIndex = output.find(EndCertificate, startIndex)
  if endIndex < 0:
    return ""
  output[startIndex ..< endIndex + EndCertificate.len] & "\n"

proc tlsConnectTarget(hostname: string, port: int): string =
  if ':' in hostname and not hostname.startsWith('['):
    "[" & hostname & "]:" & $port
  else:
    hostname & ":" & $port

proc checkSsl*(hostOrUrl: string, minDays: int = 14, port: int = 443,
               timeoutMs: int = 5000,
               runner: ProcessRunner = nil): CheckResult =
  ## Fetch and inspect a TLS certificate through direct OpenSSL argv calls.
  ## OpenSSL remains a temporary 0.1.x dependency, but neither invocation uses
  ## a shell, redirection, or a pipeline.
  let startTime = getMonoTime()
  let hostname = hostnameFromSslTarget(hostOrUrl)
  let target = formatHostPort(hostname, port)
  validatePort(port)
  validateCommon(timeoutMs, 1)
  if minDays < 0:
    raise newException(CanaryConfigError, "minDays cannot be negative")

  when not (defined(linux) or defined(windows)):
    raise newException(
      CanaryConfigError,
      "SSL checks are supported only on Linux and Windows"
    )
  else:
    let execute = if runner.isNil: runProcess else: runner
    var handshake: ProcessResult
    try:
      handshake = execute(
        "openssl",
        @[
          "s_client", "-connect", tlsConnectTarget(hostname, port),
          "-servername", hostname, "-showcerts"
        ],
        "",
        timeoutMs
      )
    except OSError, IOError:
      raise newException(
        CanaryConfigError,
        "SSL check requires the 'openssl' executable on PATH"
      )

    if handshake.timedOut:
      let latency = elapsedMilliseconds(startTime)
      let msg = "SSL TIMEOUT - " & target & " - After " &
        $latency & "ms"
      return CheckResult(
        kind: "ssl", target: target, isOk: false,
        message: msg, latencyMs: latency, details: "Timeout"
      )

    let certificate = firstCertificate(handshake.output)
    if handshake.exitCode != 0 or certificate.len == 0:
      let latency = elapsedMilliseconds(startTime)
      let msg = "SSL ERROR - " & target &
        " failed to fetch TLS certificate"
      return CheckResult(
        kind: "ssl", target: target, isOk: false,
        message: msg, latencyMs: latency, details: "TLS handshake failed"
      )

    var inspection: ProcessResult
    try:
      inspection = execute(
        "openssl", @["x509", "-noout", "-enddate"], certificate, timeoutMs
      )
    except OSError, IOError:
      raise newException(
        CanaryConfigError,
        "SSL check requires the 'openssl' executable on PATH"
      )
    if inspection.timedOut:
      let latency = elapsedMilliseconds(startTime)
      let msg = "SSL TIMEOUT - " & target &
        " while inspecting certificate"
      return CheckResult(
        kind: "ssl", target: target, isOk: false,
        message: msg, latencyMs: latency, details: "Timeout"
      )
    if inspection.exitCode != 0 or "notAfter=" notin inspection.output:
      let latency = elapsedMilliseconds(startTime)
      let msg = "SSL ERROR - " & hostname &
        " failed to inspect certificate expiration"
      return CheckResult(
        kind: "ssl", target: hostname, isOk: false, message: msg,
        latencyMs: latency, details: "Certificate inspection failed"
      )

    let rawDate = inspection.output.replace("notAfter=", "").strip()
    let normalized = rawDate.replace("  ", " ")
    var expiryTime: Time
    var parsedOk = false
    for formatStr in [
      "MMM d HH:mm:ss yyyy 'GMT'", "MMM d HH:mm:ss yyyy z", "MMM d yyyy"
    ]:
      try:
        expiryTime = parseTime(normalized, formatStr, utc())
        parsedOk = true
        break
      except ValueError:
        discard

    if not parsedOk:
      let latency = elapsedMilliseconds(startTime)
      let msg = "SSL ERROR - " & hostname &
        " returned an invalid certificate expiration date"
      return CheckResult(
        kind: "ssl", target: hostname, isOk: false, message: msg,
        latencyMs: latency, details: "Invalid expiration date"
      )

    let daysRemaining = (expiryTime - getTime()).inDays
    let expirationDetails = "Expiration: " & normalized & " (Days left: " &
      $daysRemaining & ")"
    if daysRemaining < 0:
      let latency = elapsedMilliseconds(startTime)
      let msg = "SSL EXPIRED - " & hostname & " certificate expired " &
        $(-daysRemaining) & " day(s) ago!"
      return CheckResult(
        kind: "ssl", target: hostname, isOk: false, message: msg,
        latencyMs: latency, details: expirationDetails
      )
    if daysRemaining < minDays:
      let latency = elapsedMilliseconds(startTime)
      let msg = "SSL WARNING - " & hostname & " certificate expiring soon (" &
        $daysRemaining & " days left, minimum: " & $minDays & ")"
      return CheckResult(
        kind: "ssl", target: hostname, isOk: false, message: msg,
        latencyMs: latency, details: expirationDetails
      )

    let latency = elapsedMilliseconds(startTime)
    let msg = "SSL OK - " & hostname & " certificate valid (" &
      $daysRemaining & " days left) - Latency: " & $latency & "ms"
    CheckResult(
      kind: "ssl", target: hostname, isOk: true, message: msg,
      latencyMs: latency, details: expirationDetails
    )
