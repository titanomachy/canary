import std/[httpclient, times, strutils, net]
import ../[common, input_contract]

proc parseCustomHeaders*(rawHeaders: string): HttpHeaders =
  result = newHttpHeaders()
  if rawHeaders.len == 0: return

  var lines: seq[string] = @[]
  if "\n" in rawHeaders:
    lines = rawHeaders.splitLines()
  elif ";" in rawHeaders:
    lines = rawHeaders.split(';')
  else:
    lines = rawHeaders.split(',')

  for line in lines:
    let trimmed = line.strip()
    if trimmed.len == 0: continue
    let parts = trimmed.split(":", 1)
    if parts.len == 2:
      result[parts[0].strip()] = parts[1].strip()

proc stringToHttpMethod*(methodStr: string): HttpMethod =
  case methodStr.toUpperAscii()
  of "GET": HttpGet
  of "POST": HttpPost
  of "HEAD": HttpHead
  of "PUT": HttpPut
  of "DELETE": HttpDelete
  of "PATCH": HttpPatch
  of "OPTIONS": HttpOptions
  else:
    raise newException(
      CanaryConfigError,
      "unsupported HTTP method: " & methodStr
    )

proc checkHttp*(url: string,
               timeoutMs: int = 5000,
               expectedStatus: int = 200,
               search: string = "",
               headers: string = "",
               methodStr: string = "GET",
               body: string = "",
               maxRedirects: int = 5): CheckResult =
  ## Check an HTTP(S) endpoint with headers, methods, redirects, and content matching.
  validateHttp(url, timeoutMs, 1, expectedStatus, maxRedirects, methodStr)
  validateHttpHeaders(headers)
  let displayUrl = publicTarget(url)
  let startTime = epochTime()
  var client: HttpClient

  try:
    let customHeaders = parseCustomHeaders(headers)
    let httpVerb = stringToHttpMethod(methodStr)
    client = newHttpClient(
      timeout = timeoutMs,
      maxRedirects = maxRedirects,
      headers = customHeaders
    )
    let response = client.request(url, httpVerb, body)
    let durationMs = int((epochTime() - startTime) * 1000)
    let statusCode = parseInt(split($response.status, " ")[0])

    if statusCode == expectedStatus:
      if search.len > 0 and search notin response.body:
        let msg = "HTTP ERROR - " & displayUrl & " - Required text not found in body - Latency: " & $durationMs & "ms"
        return CheckResult(
          kind: "http",
          target: displayUrl,
          isOk: false,
          message: msg,
          latencyMs: durationMs,
          details: "Status: " & response.status & ", Required text missing"
        )
      let msg = "HTTP OK - " & displayUrl & " - Status: " & response.status & " - Latency: " & $durationMs & "ms"
      return CheckResult(
        kind: "http",
        target: displayUrl,
        isOk: true,
        message: msg,
        latencyMs: durationMs,
        details: "Status: " & response.status
      )
    else:
      let msg = "HTTP ERROR - " & displayUrl & " - Status: " & response.status & " (Expected: " & $expectedStatus & ") - Latency: " & $durationMs & "ms"
      return CheckResult(
        kind: "http",
        target: displayUrl,
        isOk: false,
        message: msg,
        latencyMs: durationMs,
        details: "Expected status: " & $expectedStatus & ", Received: " & response.status
      )
  except TimeoutError:
    let durationMs = int((epochTime() - startTime) * 1000)
    let msg = "HTTP TIMEOUT - " & displayUrl & " - After " & $durationMs & "ms"
    return CheckResult(kind: "http", target: displayUrl, isOk: false, message: msg, latencyMs: durationMs, details: "Timeout")
  except HttpRequestError, OSError, IOError, ValueError:
    let durationMs = int((epochTime() - startTime) * 1000)
    let msg = "HTTP ERROR - " & displayUrl & " - Request failed"
    return CheckResult(kind: "http", target: displayUrl, isOk: false, message: msg, latencyMs: durationMs, details: "Request failed")
  except CatchableError:
    let durationMs = int((epochTime() - startTime) * 1000)
    let msg = "HTTP ERROR - " & displayUrl & " - Unexpected client error"
    return CheckResult(kind: "http", target: displayUrl, isOk: false, message: msg, latencyMs: durationMs, details: "Unexpected client error")
  finally:
    if client != nil:
      client.close()
