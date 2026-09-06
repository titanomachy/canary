import std/[dynlib, httpcore, math, os, strutils, uri]
import ../common

type
  CurlLibraryError* = object of LibraryError

  CurlHandle = pointer
  CurlCode = cint
  CurlSlist {.pure, final.} = object
    data: cstring
    next: ptr CurlSlist

  CurlGlobalInitProc = proc(flags: cint): CurlCode {.cdecl.}
  CurlGlobalCleanupProc = proc() {.cdecl.}
  CurlEasyInitProc = proc(): CurlHandle {.cdecl.}
  CurlEasyCleanupProc = proc(handle: CurlHandle) {.cdecl.}
  CurlEasyPerformProc = proc(handle: CurlHandle): CurlCode {.cdecl.}
  CurlEasySetoptProc = proc(handle: CurlHandle,
                            option: cint): CurlCode {.cdecl, varargs.}
  CurlEasyGetinfoProc = proc(handle: CurlHandle,
                             info: cint): CurlCode {.cdecl, varargs.}
  CurlSlistAppendProc = proc(list: ptr CurlSlist,
                             value: cstring): ptr CurlSlist {.cdecl.}
  CurlSlistFreeAllProc = proc(list: ptr CurlSlist) {.cdecl.}

  CurlApi = object
    library: LibHandle
    globalInit: CurlGlobalInitProc
    globalCleanup: CurlGlobalCleanupProc
    easyInit: CurlEasyInitProc
    easyCleanup: CurlEasyCleanupProc
    easyPerform: CurlEasyPerformProc
    easySetopt: CurlEasySetoptProc
    easyGetinfo: CurlEasyGetinfoProc
    slistAppend: CurlSlistAppendProc
    slistFreeAll: CurlSlistFreeAllProc

  TimedHttpResponse* = object
    succeeded*: bool
    timedOut*: bool
    body*: string
    headers*: HttpHeaders
    status*: string
    statusCode*: int
    timings*: HttpPhaseTimings

const
  WindowsCurlLibraryNames* = [
    "libcurl.dll", "libcurl-x64.dll", "libcurl-4.dll", "curl.dll"
  ]
  WindowsCurlInstallHelp* =
    "libcurl is required for HTTP --timing on Windows. Download a libcurl " &
    "DLL matching Canary's architecture, place it and its dependency DLLs " &
    "next to canary.exe, or add their directory to PATH. Installing curl.exe " &
    "alone is not sufficient. Tried: " & WindowsCurlLibraryNames.join(", ")

  CurlGlobalDefault = 3.cint
  CurlOk = 0.cint
  CurlOperationTimedOut = 28.cint

  CurlOptWriteData = 10_001.cint
  CurlOptUrl = 10_002.cint
  CurlOptProxy = 10_004.cint
  CurlOptPostFields = 10_015.cint
  CurlOptHttpHeader = 10_023.cint
  CurlOptHeaderData = 10_029.cint
  CurlOptCustomRequest = 10_036.cint
  CurlOptWriteFunction = 20_011.cint
  CurlOptHeaderFunction = 20_079.cint
  CurlOptPost = 47.cint
  CurlOptNoBody = 44.cint
  CurlOptPostFieldSize = 60.cint
  CurlOptCaInfo = 10_065.cint
  CurlOptNoSignal = 99.cint
  CurlOptTimeoutMs = 155.cint

  CurlInfoResponseCode = 0x20_0002.cint
  CurlInfoTotalTime = 0x30_0003.cint
  CurlInfoNameLookupTime = 0x30_0004.cint
  CurlInfoConnectTime = 0x30_0005.cint
  CurlInfoStartTransferTime = 0x30_0011.cint
  CurlInfoAppConnectTime = 0x30_0021.cint

proc curlInstallHelp(): string =
  when defined(windows):
    WindowsCurlInstallHelp
  elif defined(macosx):
    "libcurl is required for HTTP --timing. Install the libcurl shared " &
      "library and make it available to the dynamic library loader."
  else:
    "libcurl is required for HTTP --timing. Install your distribution's " &
      "libcurl runtime package."

proc loadCurlApi(): CurlApi =
  when defined(windows):
    # Use explicit directories rather than LoadLibrary's implicit search. This
    # guarantees the documented executable-directory and PATH behavior without
    # also accepting a DLL planted in an unrelated working directory.
    var searchDirectories = @[getAppDir()]
    for pathEntry in getEnv("PATH").split(PathSep):
      var directory = pathEntry
      if directory.len >= 2 and directory[0] == '"' and
          directory[^1] == '"':
        directory = directory[1 .. ^2]
      if directory.len > 0 and directory notin searchDirectories:
        searchDirectories.add(directory)
    for directory in searchDirectories:
      for libraryName in WindowsCurlLibraryNames:
        result.library = loadLib(directory / libraryName)
        if result.library != nil:
          break
      if result.library != nil:
        break
  elif defined(macosx):
    result.library = loadLib("libcurl.4.dylib")
    if result.library == nil:
      result.library = loadLib("libcurl.dylib")
  else:
    result.library = loadLib("libcurl.so.4")
    if result.library == nil:
      result.library = loadLib("libcurl.so")
  if result.library == nil:
    raise newException(CurlLibraryError, curlInstallHelp())

  template bindSymbol(field: untyped, symbolName: string,
                      ProcType: typedesc) =
    field = cast[ProcType](symAddr(result.library, symbolName))
    if field == nil:
      unloadLib(result.library)
      raise newException(
        CurlLibraryError,
        "The loaded libcurl library is incompatible or missing required " &
          "symbols. " & curlInstallHelp()
      )

  bindSymbol(result.globalInit, "curl_global_init", CurlGlobalInitProc)
  bindSymbol(result.globalCleanup, "curl_global_cleanup", CurlGlobalCleanupProc)
  bindSymbol(result.easyInit, "curl_easy_init", CurlEasyInitProc)
  bindSymbol(result.easyCleanup, "curl_easy_cleanup", CurlEasyCleanupProc)
  bindSymbol(result.easyPerform, "curl_easy_perform", CurlEasyPerformProc)
  bindSymbol(result.easySetopt, "curl_easy_setopt", CurlEasySetoptProc)
  bindSymbol(result.easyGetinfo, "curl_easy_getinfo", CurlEasyGetinfoProc)
  bindSymbol(result.slistAppend, "curl_slist_append", CurlSlistAppendProc)
  bindSymbol(result.slistFreeAll, "curl_slist_free_all", CurlSlistFreeAllProc)

proc collectBytes(buffer: pointer, size, itemCount: csize_t,
                  destination: pointer): csize_t {.cdecl.} =
  let byteCount = int(size * itemCount)
  if byteCount <= 0:
    return 0
  let output = cast[ptr string](destination)
  let oldLength = output[].len
  output[].setLen(oldLength + byteCount)
  copyMem(addr output[][oldLength], buffer, byteCount)
  csize_t(byteCount)

proc checkedSetopt(api: CurlApi, handle: CurlHandle, option: cint,
                   value: auto) =
  if api.easySetopt(handle, option, value) != CurlOk:
    raise newException(IOError, "failed to configure HTTP timing transport")

proc timingValue(api: CurlApi, handle: CurlHandle, info: cint): float =
  var seconds: cdouble
  if api.easyGetinfo(handle, info, addr seconds) == CurlOk:
    max(0.0, seconds.float * 1000.0)
  else:
    0.0

proc milliseconds(value: float): float =
  round(max(0.0, value) * 1000.0) / 1000.0

proc phaseTimings(api: CurlApi, handle: CurlHandle): HttpPhaseTimings =
  let dnsEnd = timingValue(api, handle, CurlInfoNameLookupTime)
  let connectEnd = timingValue(api, handle, CurlInfoConnectTime)
  let tlsEnd = timingValue(api, handle, CurlInfoAppConnectTime)
  let firstByte = timingValue(api, handle, CurlInfoStartTransferTime)
  let total = timingValue(api, handle, CurlInfoTotalTime)
  let applicationReady = if tlsEnd > 0.0: tlsEnd else: connectEnd
  HttpPhaseTimings(
    available: true,
    dnsMs: milliseconds(dnsEnd),
    tcpConnectMs: milliseconds(connectEnd - dnsEnd),
    tlsHandshakeMs: milliseconds(tlsEnd - connectEnd),
    ttfbMs: milliseconds(firstByte - applicationReady),
    transferMs: milliseconds(total - firstByte),
    totalMs: milliseconds(total)
  )

proc parseResponseHeaders(rawHeaders: string,
                          fallbackCode: int): tuple[status: string,
                                                    headers: HttpHeaders] =
  result.headers = newHttpHeaders()
  for rawLine in rawHeaders.splitLines():
    let line = rawLine.strip(chars = {'\r'})
    if line.startsWith("HTTP/"):
      result.headers = newHttpHeaders()
      let separator = line.find(' ')
      if separator >= 0 and separator + 1 < line.len:
        result.status = line[separator + 1 .. ^1].strip()
    elif line.len > 0:
      let separator = line.find(':')
      if separator > 0:
        result.headers.add(
          line[0 ..< separator].strip(),
          line[separator + 1 .. ^1].strip()
        )
  if result.status.len == 0 and fallbackCode > 0:
    result.status = $fallbackCode

proc performTimedRequest(url, methodName, body: string, headers: HttpHeaders,
                         timeoutMs: int): TimedHttpResponse =
  ## Perform one request through libcurl and expose its cumulative counters as
  ## independent phase durations.
  let api = loadCurlApi()
  defer: unloadLib(api.library)
  if api.globalInit(CurlGlobalDefault) != CurlOk:
    raise newException(IOError, "failed to initialize HTTP timing transport")
  defer: api.globalCleanup()

  let handle = api.easyInit()
  if handle == nil:
    raise newException(IOError, "failed to initialize HTTP timing request")
  defer: api.easyCleanup(handle)

  var rawHeaders = ""
  var headerList: ptr CurlSlist
  defer:
    if headerList != nil:
      api.slistFreeAll(headerList)

  checkedSetopt(api, handle, CurlOptUrl, url.cstring)
  checkedSetopt(api, handle, CurlOptProxy, "".cstring)
  checkedSetopt(api, handle, CurlOptCustomRequest, methodName.cstring)
  checkedSetopt(api, handle, CurlOptTimeoutMs, timeoutMs.clong)
  checkedSetopt(api, handle, CurlOptNoSignal, 1.clong)
  let caBundle =
    if getEnv("CURL_CA_BUNDLE").len > 0: getEnv("CURL_CA_BUNDLE")
    else: getEnv("SSL_CERT_FILE")
  if caBundle.len > 0:
    checkedSetopt(api, handle, CurlOptCaInfo, caBundle.cstring)
  checkedSetopt(api, handle, CurlOptWriteFunction, collectBytes)
  checkedSetopt(api, handle, CurlOptWriteData, addr result.body)
  checkedSetopt(api, handle, CurlOptHeaderFunction, collectBytes)
  checkedSetopt(api, handle, CurlOptHeaderData, addr rawHeaders)

  for key, value in headers:
    let updatedList = api.slistAppend(
      headerList, (key & ": " & value).cstring
    )
    if updatedList == nil:
      raise newException(IOError, "failed to configure HTTP request headers")
    headerList = updatedList
  if headerList != nil:
    checkedSetopt(api, handle, CurlOptHttpHeader, headerList)

  if methodName == "HEAD":
    checkedSetopt(api, handle, CurlOptNoBody, 1.clong)
  elif methodName == "POST" and body.len == 0:
    checkedSetopt(api, handle, CurlOptPost, 1.clong)
  if body.len > 0:
    checkedSetopt(api, handle, CurlOptPostFieldSize, body.len.clong)
    checkedSetopt(api, handle, CurlOptPostFields, body.cstring)

  let code = api.easyPerform(handle)
  var responseCode: clong
  discard api.easyGetinfo(handle, CurlInfoResponseCode, addr responseCode)
  result.statusCode = responseCode.int
  result.timings = phaseTimings(api, handle)
  result.succeeded = code == CurlOk
  result.timedOut = code == CurlOperationTimedOut
  let parsed = parseResponseHeaders(rawHeaders, result.statusCode)
  result.status = parsed.status
  result.headers = parsed.headers

proc copyHeaders(headers: HttpHeaders): HttpHeaders =
  result = newHttpHeaders()
  for key, value in headers:
    result.add(key, value)

proc addTimings(total: var HttpPhaseTimings, current: HttpPhaseTimings) =
  total.available = true
  total.dnsMs = milliseconds(total.dnsMs + current.dnsMs)
  total.tcpConnectMs = milliseconds(
    total.tcpConnectMs + current.tcpConnectMs
  )
  total.tlsHandshakeMs = milliseconds(
    total.tlsHandshakeMs + current.tlsHandshakeMs
  )
  total.ttfbMs = milliseconds(total.ttfbMs + current.ttfbMs)
  total.transferMs = milliseconds(total.transferMs + current.transferMs)
  total.totalMs = milliseconds(total.totalMs + current.totalMs)

proc redirectTarget(currentUrl: Uri, location: string): Uri =
  let parsedLocation = parseUri(location)
  if parsedLocation.hostname.len == 0 and parsedLocation.path.len > 0:
    result = currentUrl
    result.path = parsedLocation.path
    result.query = parsedLocation.query
    result.anchor = parsedLocation.anchor
  else:
    result = parsedLocation

proc timedHttpRequest*(url, methodName, body: string, headers: HttpHeaders,
                       timeoutMs, maxRedirects: int): TimedHttpResponse =
  ## Follow redirects with the same method, body, and sensitive-header rules as
  ## Nim's HttpClient while accumulating every request's transport phases.
  var currentUrl = parseUri(url)
  var currentMethod = methodName
  var currentBody = body
  var currentHeaders = copyHeaders(headers)
  var timings: HttpPhaseTimings

  for redirectIndex in 0 .. maxRedirects:
    result = performTimedRequest(
      $currentUrl, currentMethod, currentBody, currentHeaders, timeoutMs
    )
    timings.addTimings(result.timings)
    result.timings = timings
    if not result.succeeded or
        result.statusCode notin [301, 302, 303, 307, 308] or
        redirectIndex == maxRedirects:
      return

    let location = result.headers.getOrDefault("Location")
    if location.len == 0:
      result.succeeded = false
      return
    let nextUrl = redirectTarget(currentUrl, location)
    if result.statusCode in [301, 302, 303]:
      if currentMethod notin ["GET", "HEAD"]:
        currentMethod = "GET"
      currentBody = ""
      currentHeaders.del("Content-Length")
      currentHeaders.del("Content-Type")
      currentHeaders.del("Transfer-Encoding")

    if nextUrl.hostname != currentUrl.hostname and
        not nextUrl.hostname.endsWith("." & currentUrl.hostname):
      currentHeaders.del("Host")
      currentHeaders.del("Authorization")
    currentUrl = nextUrl
