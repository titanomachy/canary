import std/[json, monotimes, os, strutils, times, uri]

type
  CanaryConfigError* = object of ValueError

  HttpPhaseTimings* = object
    ## Independent HTTP transport phases in milliseconds. Values are present
    ## only when the optional timing transport was requested.
    available*: bool
    dnsMs*: float
    tcpConnectMs*: float
    tlsHandshakeMs*: float
    ttfbMs*: float
    transferMs*: float
    totalMs*: float

  CheckResult* = object
    kind*: string
    target*: string
    isOk*: bool
    message*: string
    latencyMs*: int
    details*: string
    httpTimings*: HttpPhaseTimings

proc elapsedMilliseconds*(startTime: MonoTime): int =
  ## Measure elapsed check time independently of adjustments to the wall clock.
  max(0, (getMonoTime() - startTime).inMilliseconds.int)

proc publicTarget*(target: string): string =
  ## Remove URL credentials, query values, and fragments from public output.
  ## The full target remains available to the check itself, but must never be
  ## used as a state ID, notification label, or diagnostic.
  try:
    var parsed = parseUri(target)
    if parsed.scheme notin ["http", "https"] or parsed.hostname.len == 0:
      return target
    parsed.username = ""
    parsed.password = ""
    parsed.query = ""
    parsed.anchor = ""
    result = $parsed
  except ValueError:
    result = "<invalid target>"

proc publicResult*(res: CheckResult): CheckResult =
  ## Apply output redaction defensively, including results assembled by callers.
  result = res
  let safeTarget = publicTarget(res.target)
  if safeTarget != res.target:
    result.target = safeTarget
    result.message = result.message.replace(res.target, safeTarget)
    result.details = result.details.replace(res.target, safeTarget)

proc resolveDbPath*(customPath: string = ""): string =
  ## Resolves the SQLite database path:
  ## 1. Custom CLI path (--db)
  ## 2. CANARY_DB environment variable
  ## 3. Fallback: ~/.config/canary/state.db
  if customPath.len > 0:
    return customPath
  let envDb = getEnv("CANARY_DB")
  if envDb.len > 0:
    return envDb
  let home = getHomeDir()
  let defaultDir = home / ".config" / "canary"
  try:
    createDir(defaultDir)
  except:
    discard
  return defaultDir / "state.db"

proc formatResult*(res: CheckResult, asJson: bool = false): string =
  ## Format a check result without performing I/O.
  let safe = publicResult(res)
  if asJson:
    var j = %*{
      "check": safe.kind,
      "target": safe.target,
      "status": if safe.isOk: "UP" else: "DOWN",
      "latency_ms": safe.latencyMs,
      "message": safe.message,
      "details": safe.details
    }
    if safe.kind == "http":
      # Keep latency_ms for compatibility while naming the complete HTTP
      # measurement precisely for new consumers.
      j["response_time_ms"] = %safe.latencyMs
      if safe.httpTimings.available:
        j["timings_ms"] = %*{
          "dns": safe.httpTimings.dnsMs,
          "tcp_connect": safe.httpTimings.tcpConnectMs,
          "tls_handshake": safe.httpTimings.tlsHandshakeMs,
          "ttfb": safe.httpTimings.ttfbMs,
          "transfer": safe.httpTimings.transferMs,
          "total": safe.httpTimings.totalMs
        }
    result = $j
  else:
    result = safe.message

proc outputResult*(res: CheckResult, asJson: bool = false) =
  ## Print a check result as formatted JSON or human-readable text.
  echo formatResult(res, asJson)
