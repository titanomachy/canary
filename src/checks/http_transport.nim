import std/[asyncdispatch, asyncnet, httpclient, monotimes, net, openssl,
            strutils, times, uri]

type HttpResponseData* = object
  body*: string
  status*: string
  headers*: HttpHeaders

proc sslCtxGet0Param(context: SslCtx): pointer {.
  cdecl, dynlib: DLLSSLName, importc: "SSL_CTX_get0_param".}
proc setExpectedHost(param: pointer, host: cstring, length: csize_t): cint {.
  cdecl, dynlib: DLLUtilName, importc: "X509_VERIFY_PARAM_set1_host".}
proc setExpectedIp(param: pointer, host: cstring): cint {.
  cdecl, dynlib: DLLUtilName, importc: "X509_VERIFY_PARAM_set1_ip_asc".}

proc verifiedContext(host: string): SslContext =
  result = newContext(verifyMode = CVerifyPeerUseEnvVars)
  let param = sslCtxGet0Param(result.context)
  let configured = if isIpAddress(host):
    setExpectedIp(param, host.cstring)
  else:
    setExpectedHost(param, host.cstring, host.len.csize_t)
  if configured != 1:
    result.destroyContext()
    raise newException(IOError, "could not configure TLS identity verification")

proc closeConnection(client: AsyncHttpClient) =
  # HttpClient.close only closes an established connection. A timed-out
  # handshake or connection attempt may not have set that flag yet.
  let socket = client.getSocket()
  if socket != nil and not socket.isClosed():
    socket.close()

proc requestBody(client: AsyncHttpClient, url: Uri, httpMethod: HttpMethod,
                 body: string): Future[HttpResponseData] {.async.} =
  let response = await client.request(url, httpMethod, body)
  result.status = response.status
  result.headers = response.headers
  result.body = await response.body()

proc boundedHttpRequest*(url: string, httpMethod: HttpMethod, body: string,
                         headers: HttpHeaders, timeoutMs,
                         maxRedirects: int): HttpResponseData =
  let deadline = getMonoTime() + initDuration(milliseconds = timeoutMs)
  var currentUrl = parseUri(url)
  var currentMethod = httpMethod
  var currentBody = body
  for redirectIndex in 0 .. maxRedirects:
    let context = if currentUrl.scheme == "https":
      verifiedContext(currentUrl.hostname)
    else:
      nil
    let client = if context != nil:
      newAsyncHttpClient(maxRedirects = 0, headers = headers,
                         sslContext = context)
    else:
      newAsyncHttpClient(maxRedirects = 0, headers = headers)
    var deferredCleanup = false
    try:
      let remaining = (deadline - getMonoTime()).inMilliseconds.int
      if remaining <= 0:
        raise newException(TimeoutError, "HTTP request timed out")
      let operation = requestBody(client, currentUrl, currentMethod, currentBody)
      if not waitFor(operation.withTimeout(remaining)):
        # Close now, and also when a pending dial completes after the deadline.
        closeConnection(client)
        deferredCleanup = true
        operation.addCallback(proc() =
          closeConnection(client)
          if context != nil:
            context.destroyContext()
        )
        raise newException(TimeoutError, "HTTP request timed out")
      result = operation.read()
      let code = result.status[0 .. 2]
      if code notin ["301", "302", "303", "307", "308"] or
          redirectIndex == maxRedirects:
        return
      let location = result.headers.getOrDefault("Location")
      if location.len == 0:
        raise newException(HttpRequestError, "redirect location missing")
      let nextUrl = combine(currentUrl, parseUri(location))
      if nextUrl.scheme notin ["http", "https"]:
        raise newException(HttpRequestError, "unsupported redirect scheme")
      if code in ["301", "302", "303"]:
        if currentMethod notin [HttpGet, HttpHead]:
          currentMethod = HttpGet
        currentBody = ""
        headers.del("Content-Length")
        headers.del("Content-Type")
        headers.del("Transfer-Encoding")
      if nextUrl.hostname != currentUrl.hostname and
          not nextUrl.hostname.endsWith("." & currentUrl.hostname):
        headers.del("Host")
        headers.del("Authorization")
      currentUrl = nextUrl
    finally:
      closeConnection(client)
      if context != nil and not deferredCleanup:
        context.destroyContext()
