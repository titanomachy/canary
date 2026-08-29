import std/[json, os, strutils, uri]

type
  CanaryConfigError* = object of ValueError

  CheckResult* = object
    kind*: string
    target*: string
    isOk*: bool
    message*: string
    latencyMs*: int
    details*: string

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
    let j = %*{
      "check": safe.kind,
      "target": safe.target,
      "status": if safe.isOk: "UP" else: "DOWN",
      "latency_ms": safe.latencyMs,
      "message": safe.message,
      "details": safe.details
    }
    result = $j
  else:
    result = safe.message

proc outputResult*(res: CheckResult, asJson: bool = false) =
  ## Print a check result as formatted JSON or human-readable text.
  echo formatResult(res, asJson)
