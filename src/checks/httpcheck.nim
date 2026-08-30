import std/[httpclient, json, net, re, strutils, times]
import ../[common, input_contract]

proc failedHttpResult(displayUrl, reason: string, durationMs: int,
                      details: string): CheckResult =
  CheckResult(
    kind: "http",
    target: displayUrl,
    isOk: false,
    message: "HTTP ERROR - " & displayUrl & " - " & reason &
      " - Latency: " & $durationMs & "ms",
    latencyMs: durationMs,
    details: details
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
               maxRedirects: int = 5,
               statusRange: string = "",
               maxLatencyMs: int = 0,
               responseHeader: string = "",
               bodyRegex: string = "",
               jsonField: string = ""): CheckResult =
  ## Check an HTTP(S) endpoint with headers, methods, redirects, and content matching.
  validateHttp(
    url, timeoutMs, 1, expectedStatus, maxRedirects, methodStr, statusRange,
    maxLatencyMs, responseHeader, bodyRegex, jsonField
  )
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
    let responseBody = response.body
    let durationMs = int((epochTime() - startTime) * 1000)
    let statusCode = parseInt(split($response.status, " ")[0])

    if not statusAccepted(statusCode, expectedStatus, statusRange):
      let expectation = expectedStatusDescription(expectedStatus, statusRange)
      return failedHttpResult(
        displayUrl,
        "Status: " & response.status & " (Expected: " & expectation & ")",
        durationMs,
        "Expected status: " & expectation & ", Received: " & response.status
      )

    if maxLatencyMs > 0 and durationMs > maxLatencyMs:
      return failedHttpResult(
        displayUrl, "Maximum latency exceeded", durationMs,
        "Status: " & response.status & ", Maximum latency: " &
          $maxLatencyMs & "ms"
      )

    if responseHeader.len > 0:
      let expectedHeader = responseHeaderExpectation(responseHeader)
      if not response.headers.hasKey(expectedHeader.name):
        return failedHttpResult(
          displayUrl, "Required response header missing", durationMs,
          "Status: " & response.status & ", Missing response header: " &
            expectedHeader.name
        )
      if expectedHeader.value.len > 0 and
          expectedHeader.value notin response.headers[expectedHeader.name]:
        return failedHttpResult(
          displayUrl, "Response header value did not match", durationMs,
          "Status: " & response.status & ", Response header mismatch: " &
            expectedHeader.name
        )

    if search.len > 0 and search notin responseBody:
      return failedHttpResult(
        displayUrl, "Required text not found in body", durationMs,
        "Status: " & response.status & ", Required text missing"
      )

    if bodyRegex.len > 0 and not responseBody.contains(re(bodyRegex)):
      return failedHttpResult(
        displayUrl, "Response body regex did not match", durationMs,
        "Status: " & response.status & ", Body regex mismatch"
      )

    if jsonField.len > 0:
      try:
        if not matchesJsonField(responseBody, jsonField):
          return failedHttpResult(
            displayUrl, "JSON field did not match", durationMs,
            "Status: " & response.status & ", JSON field mismatch"
          )
      except JsonParsingError:
        return failedHttpResult(
          displayUrl, "Response body is not valid JSON", durationMs,
          "Status: " & response.status & ", Invalid JSON response"
        )

    let msg = "HTTP OK - " & displayUrl & " - Status: " & response.status &
      " - Latency: " & $durationMs & "ms"
    return CheckResult(
      kind: "http",
      target: displayUrl,
      isOk: true,
      message: msg,
      latencyMs: durationMs,
      details: "Status: " & response.status
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
