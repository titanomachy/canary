import std/[httpclient, json, monotimes, net, re, strutils]
import ../[common, input_contract]
import http_timing

proc timingSummary(timings: HttpPhaseTimings): string =
  if not timings.available:
    return ""
  " - Timings: DNS " & formatFloat(timings.dnsMs, ffDecimal, 3) &
    "ms, TCP " & formatFloat(timings.tcpConnectMs, ffDecimal, 3) &
    "ms, TLS " & formatFloat(timings.tlsHandshakeMs, ffDecimal, 3) &
    "ms, TTFB " & formatFloat(timings.ttfbMs, ffDecimal, 3) &
    "ms, Transfer " & formatFloat(timings.transferMs, ffDecimal, 3) &
    "ms, Total " & formatFloat(timings.totalMs, ffDecimal, 3) & "ms"

proc failedHttpResult(displayUrl, reason: string, startTime: MonoTime,
                      details: string,
                      timings: HttpPhaseTimings = HttpPhaseTimings()): CheckResult =
  let responseTimeMs = elapsedMilliseconds(startTime)
  CheckResult(
    kind: "http",
    target: displayUrl,
    isOk: false,
    message: "HTTP ERROR - " & displayUrl & " - " & reason &
      " - Response time: " & $responseTimeMs & "ms" & timingSummary(timings),
    latencyMs: responseTimeMs,
    details: details,
    httpTimings: timings
  )

proc responseHeaderExpectation(raw: string): tuple[name, value: string] =
  let separator = raw.find(':')
  if separator < 0:
    result.name = raw.strip()
  else:
    result.name = raw[0 ..< separator].strip()
    result.value = raw[separator + 1 .. ^1].strip()

proc jsonScalar(node: JsonNode): string =
  case node.kind
  of JString: node.getStr()
  of JInt: $node.getInt()
  of JFloat: $node.getFloat()
  of JBool: $node.getBool()
  of JNull: "null"
  else: $node

proc matchesJsonField(body, expectation: string): bool =
  let separator = expectation.find('=')
  let path = expectation[0 ..< separator].strip()
  let expected = expectation[separator + 1 .. ^1]
  var current = parseJson(body)
  for part in path.split('.'):
    case current.kind
    of JObject:
      if not current.hasKey(part):
        return false
      current = current[part]
    of JArray:
      var index: int
      try:
        index = parseInt(part)
      except ValueError:
        return false
      if index < 0 or index >= current.len:
        return false
      current = current[index]
    else:
      return false
  current.jsonScalar() == expected

proc parseCustomHeaders*(rawHeaders: string): HttpHeaders =
  result = newHttpHeaders()
  if rawHeaders.len == 0:
    return

  var lines: seq[string] = @[]
  if "\n" in rawHeaders:
    lines = rawHeaders.splitLines()
  elif ";" in rawHeaders:
    lines = rawHeaders.split(';')
  else:
    lines = rawHeaders.split(',')

  for line in lines:
    let trimmed = line.strip()
    if trimmed.len == 0:
      continue
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
                maxRedirects: int = 5,
                statusRange: string = "",
                maxLatencyMs: int = 0,
                responseHeader: string = "",
                bodyRegex: string = "",
                jsonField: string = "",
                verboseTimings: bool = false): CheckResult =
  ## Check an HTTP(S) endpoint with optional curl-style phase timings.
  let startTime = getMonoTime()
  validateHttp(
    url, timeoutMs, 1, expectedStatus, maxRedirects, methodStr, statusRange,
    maxLatencyMs, responseHeader, bodyRegex, jsonField
  )
  validateHttpHeaders(headers)
  let displayUrl = publicTarget(url)
  var client: HttpClient
  var timings = HttpPhaseTimings(available: verboseTimings)

  try:
    let customHeaders = parseCustomHeaders(headers)
    let httpVerb = stringToHttpMethod(methodStr)
    var responseBody: string
    var responseStatus: string
    var responseHeaders: HttpHeaders
    var statusCode: int

    if verboseTimings:
      let response = timedHttpRequest(
        url, methodStr.toUpperAscii(), body, customHeaders, timeoutMs,
        maxRedirects
      )
      timings = response.timings
      if not response.succeeded:
        let responseTimeMs = elapsedMilliseconds(startTime)
        if response.timedOut:
          return CheckResult(
            kind: "http",
            target: displayUrl,
            isOk: false,
            message: "HTTP TIMEOUT - " & displayUrl & " - Response time: " &
              $responseTimeMs & "ms" & timingSummary(timings),
            latencyMs: responseTimeMs,
            details: "Timeout",
            httpTimings: timings
          )
        return CheckResult(
          kind: "http",
          target: displayUrl,
          isOk: false,
          message: "HTTP ERROR - " & displayUrl &
            " - Request failed - Response time: " & $responseTimeMs & "ms" &
            timingSummary(timings),
          latencyMs: responseTimeMs,
          details: "Request failed",
          httpTimings: timings
        )
      responseBody = response.body
      responseStatus = response.status
      responseHeaders = response.headers
      statusCode = response.statusCode
    else:
      client = newHttpClient(
        timeout = timeoutMs,
        maxRedirects = maxRedirects,
        headers = customHeaders
      )
      let response = client.request(url, httpVerb, body)
      responseBody = response.body
      responseStatus = $response.status
      responseHeaders = response.headers
      statusCode = parseInt(split(responseStatus, " ")[0])

    if not statusAccepted(statusCode, expectedStatus, statusRange):
      let expectation = expectedStatusDescription(expectedStatus, statusRange)
      return failedHttpResult(
        displayUrl,
        "Status: " & responseStatus & " (Expected: " & expectation & ")",
        startTime,
        "Expected status: " & expectation & ", Received: " & responseStatus,
        timings
      )

    if responseHeader.len > 0:
      let expectedHeader = responseHeaderExpectation(responseHeader)
      if not responseHeaders.hasKey(expectedHeader.name):
        return failedHttpResult(
          displayUrl, "Required response header missing", startTime,
          "Status: " & responseStatus & ", Missing response header: " &
            expectedHeader.name, timings
        )
      if expectedHeader.value.len > 0 and
          expectedHeader.value notin responseHeaders[expectedHeader.name]:
        return failedHttpResult(
          displayUrl, "Response header value did not match", startTime,
          "Status: " & responseStatus & ", Response header mismatch: " &
            expectedHeader.name, timings
        )

    if search.len > 0 and search notin responseBody:
      return failedHttpResult(
        displayUrl, "Required text not found in body", startTime,
        "Status: " & responseStatus & ", Required text missing", timings
      )

    if bodyRegex.len > 0 and not responseBody.contains(re(bodyRegex)):
      return failedHttpResult(
        displayUrl, "Response body regex did not match", startTime,
        "Status: " & responseStatus & ", Body regex mismatch", timings
      )

    if jsonField.len > 0:
      try:
        if not matchesJsonField(responseBody, jsonField):
          return failedHttpResult(
            displayUrl, "JSON field did not match", startTime,
            "Status: " & responseStatus & ", JSON field mismatch", timings
          )
      except JsonParsingError:
        return failedHttpResult(
          displayUrl, "Response body is not valid JSON", startTime,
          "Status: " & responseStatus & ", Invalid JSON response", timings
        )

    if maxLatencyMs > 0 and elapsedMilliseconds(startTime) > maxLatencyMs:
      return failedHttpResult(
        displayUrl, "Maximum response time exceeded", startTime,
        "Status: " & responseStatus & ", Maximum response time: " &
          $maxLatencyMs & "ms", timings
      )

    let responseTimeMs = elapsedMilliseconds(startTime)
    let msg = "HTTP OK - " & displayUrl & " - Status: " & responseStatus &
      " - Response time: " & $responseTimeMs & "ms" & timingSummary(timings)
    return CheckResult(
      kind: "http",
      target: displayUrl,
      isOk: true,
      message: msg,
      latencyMs: responseTimeMs,
      details: "Status: " & responseStatus,
      httpTimings: timings
    )
  except TimeoutError:
    let responseTimeMs = elapsedMilliseconds(startTime)
    let msg = "HTTP TIMEOUT - " & displayUrl & " - Response time: " &
      $responseTimeMs & "ms" & timingSummary(timings)
    return CheckResult(
      kind: "http", target: displayUrl, isOk: false, message: msg,
      latencyMs: responseTimeMs, details: "Timeout", httpTimings: timings
    )
  except HttpRequestError, OSError, IOError, ValueError:
    let responseTimeMs = elapsedMilliseconds(startTime)
    let msg = "HTTP ERROR - " & displayUrl &
      " - Request failed - Response time: " & $responseTimeMs & "ms" &
      timingSummary(timings)
    return CheckResult(
      kind: "http", target: displayUrl, isOk: false, message: msg,
      latencyMs: responseTimeMs, details: "Request failed",
      httpTimings: timings
    )
  except CatchableError:
    let responseTimeMs = elapsedMilliseconds(startTime)
    let msg = "HTTP ERROR - " & displayUrl &
      " - Unexpected client error - Response time: " &
      $responseTimeMs & "ms" & timingSummary(timings)
    return CheckResult(
      kind: "http", target: displayUrl, isOk: false, message: msg,
      latencyMs: responseTimeMs, details: "Unexpected client error",
      httpTimings: timings
    )
  finally:
    if client != nil:
      client.close()
