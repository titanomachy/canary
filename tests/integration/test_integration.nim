import nim_sqlite
import std/[json, monotimes, net, options, os, osproc, streams, strutils,
            times, unittest]
import ../../src/[common, notifier, process_runner]
import ../../src/checks/[dnscheck, httpcheck, sslcheck, tcpcheck, udpcheck]
import ../test_support

proc readState(dbPath: string, jobId: string): tuple[status: string,
                                                     failCount: int] =
  let db = openDatabase(dbPath)
  defer: db.close()
  let row = db.one(
    "SELECT status, fail_count FROM canary_state WHERE id = ?", jobId
  )
  doAssert row.isSome
  result = (
    row.get()[0].fromDb(string),
    row.get()[1].fromDb(int)
  )

suite "local HTTP and UDP checks":
  test "HTTP success and body assertions use a random local port":
    var server = startLocalServer("http-ok")
    defer: server.stop()
    let result = checkHttp(
      "http://127.0.0.1:" & $server.port & "/health",
      timeoutMs = 1000,
      search = "fixture-ok"
    )
    check result.isOk
    check result.details.startsWith("Status: 200")
    check "Response time: " in result.message
    let payload = parseJson(formatResult(result, true))
    check payload["response_time_ms"].getInt() == result.latencyMs
    check payload["latency_ms"].getInt() == result.latencyMs
    server.waitForSuccess()

  test "HTTP verbose mode reports independent transport phases":
    var server = startLocalServer("http-ok", ["--delay-ms=100"])
    defer: server.stop()
    let result = checkHttp(
      "http://127.0.0.1:" & $server.port & "/health",
      timeoutMs = 1000,
      verboseTimings = true
    )
    check result.isOk
    check result.httpTimings.available
    check result.httpTimings.dnsMs >= 0.0
    check result.httpTimings.tcpConnectMs >= 0.0
    check result.httpTimings.tlsHandshakeMs == 0.0
    check result.httpTimings.ttfbMs >= 50.0
    check result.httpTimings.transferMs >= 0.0
    check result.httpTimings.totalMs >= result.httpTimings.ttfbMs
    check "Timings: DNS " in result.message
    let payload = parseJson(formatResult(result, true))
    check payload["timings_ms"]["ttfb"].getFloat() >= 50.0
    check payload["timings_ms"]["total"].getFloat() > 0.0
    server.waitForSuccess()

  test "HTTP timing accumulates redirects without changing assertions":
    var server = startLocalServer("http-redirect")
    defer: server.stop()
    let result = checkHttp(
      "http://127.0.0.1:" & $server.port & "/start",
      timeoutMs = 1000,
      maxRedirects = 1,
      search = "fixture-ok",
      verboseTimings = true
    )
    check result.isOk
    check result.details.startsWith("Status: 200")
    check result.httpTimings.totalMs > 0.0
    server.waitForSuccess()

  test "HTTP result output omits userinfo, query values, and fragments":
    var server = startLocalServer("http-ok")
    defer: server.stop()
    let secretUrl = "http://user:password@127.0.0.1:" & $server.port &
      "/health?token=secret#private"
    let result = checkHttp(secretUrl, timeoutMs = 1000)
    check result.isOk
    let output = formatResult(result, true)
    check "http://127.0.0.1:" & $server.port & "/health" in output
    for secret in ["user", "password", "token", "secret", "private"]:
      check secret notin output
    server.waitForSuccess()

  test "HTTP status and missing content produce DOWN results":
    var statusServer = startLocalServer("http-missing")
    defer: statusServer.stop()
    let statusResult = checkHttp(
      "http://127.0.0.1:" & $statusServer.port & "/missing",
      timeoutMs = 1000
    )
    check not statusResult.isOk
    check "Received: 404" in statusResult.details
    statusServer.waitForSuccess()

    var contentServer = startLocalServer("http-ok")
    defer: contentServer.stop()
    let contentResult = checkHttp(
      "http://127.0.0.1:" & $contentServer.port & "/health",
      timeoutMs = 1000,
      search = "not-present"
    )
    check not contentResult.isOk
    check "Required text missing" in contentResult.details
    contentServer.waitForSuccess()

  test "HTTP range, header, regex, and JSON assertions compose":
    var server = startLocalServer("http-json")
    defer: server.stop()
    let result = checkHttp(
      "http://127.0.0.1:" & $server.port & "/health",
      timeoutMs = 1000,
      statusRange = "2xx,304",
      responseHeader = "X-Canary-State: ready",
      bodyRegex = "\"status\"\\s*:\\s*\"ready\"",
      jsonField = "replicas.0.healthy=true",
      verboseTimings = true
    )
    check result.isOk
    check result.details.startsWith("Status: 202")
    server.waitForSuccess()

  test "HTTP maximum response time and JSON mismatches produce DOWN results":
    var slowServer = startLocalServer("http-ok", ["--delay-ms=100"])
    defer: slowServer.stop()
    let slowResult = checkHttp(
      "http://127.0.0.1:" & $slowServer.port & "/health",
      timeoutMs = 1000,
      maxLatencyMs = 25,
      verboseTimings = true
    )
    check not slowResult.isOk
    check "Maximum response time: 25ms" in slowResult.details
    check "Response time: " in slowResult.message
    check parseJson(formatResult(slowResult, true)).hasKey("timings_ms")
    slowServer.waitForSuccess()

    var jsonServer = startLocalServer("http-json")
    defer: jsonServer.stop()
    let jsonResult = checkHttp(
      "http://127.0.0.1:" & $jsonServer.port & "/health",
      timeoutMs = 1000,
      statusRange = "2xx",
      jsonField = "service.status=down"
    )
    check not jsonResult.isOk
    check "JSON field mismatch" in jsonResult.details
    jsonServer.waitForSuccess()

  test "UDP requires a matching response":
    var successServer = startLocalServer(
      "udp-echo", ["--response=pong:healthy"]
    )
    defer: successServer.stop()
    let successResult = checkUdp(
      "127.0.0.1", successServer.port, "ping", "healthy", 1000
    )
    check successResult.isOk
    check "pong:healthy" in successResult.details
    successServer.waitForSuccess()

    var mismatchServer = startLocalServer(
      "udp-echo", ["--response=pong:other"]
    )
    defer: mismatchServer.stop()
    let mismatchResult = checkUdp(
      "127.0.0.1", mismatchServer.port, "ping", "healthy", 1000
    )
    check not mismatchResult.isOk
    check "Expected: healthy" in mismatchResult.details
    mismatchServer.waitForSuccess()

  test "UDP reports a bounded timeout when no reply arrives":
    let reservation = newSocket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
    defer: reservation.close()
    reservation.bindAddr(Port(0), "127.0.0.1")
    let port = reservation.getLocalAddr()[1]

    let started = getMonoTime()
    let result = checkUdp("127.0.0.1", int(port), "ping", "", 75)
    let elapsed = (getMonoTime() - started).inMilliseconds
    check not result.isOk
    check result.details == "Timeout"
    check elapsed >= 50
    check elapsed < 1000

suite "local TCP checks":
  test "a server-first banner can satisfy an expected response":
    var server = startLocalServer(
      "tcp-banner", ["--response=SSH-2.0-Canary fixture\r\n"]
    )
    defer: server.stop()
    let result = checkTcp(
      "127.0.0.1", server.port, 1000, expected = "SSH-2.0-Canary"
    )
    check result.isOk
    check result.details.startsWith("Expected response received")
    server.waitForSuccess()

  test "a request is sent before matching the response":
    var server = startLocalServer(
      "tcp-request",
      ["--expected-request=PING\r\n", "--response=PONG ready\r\n"]
    )
    defer: server.stop()
    let result = checkTcp(
      "127.0.0.1", server.port, 1000, "PING\r\n", "PONG ready"
    )
    check result.isOk
    check result.details.startsWith("Expected response received")
    server.waitForSuccess()

  test "a closed response without the expected substring is DOWN and redacted":
    var server = startLocalServer(
      "tcp-banner", ["--response=private banner contents"]
    )
    defer: server.stop()
    let result = checkTcp(
      "127.0.0.1", server.port, 1000, expected = "secret expectation"
    )
    check not result.isOk
    check "Expected response not received" in result.details
    for secret in ["private banner contents", "secret expectation"]:
      check secret notin result.message
      check secret notin result.details
    server.waitForSuccess()

  test "the total TCP deadline bounds an unresponsive banner":
    var server = startLocalServer("tcp-silent", ["--delay-ms=250"])
    defer: server.stop()
    let started = getMonoTime()
    let result = checkTcp(
      "127.0.0.1", server.port, 75, expected = "banner"
    )
    let elapsed = (getMonoTime() - started).inMilliseconds
    check not result.isOk
    check result.details == "Timeout"
    check elapsed >= 50
    check elapsed < 1000
    server.waitForSuccess()

suite "IPv6 loopback checks":
  test "HTTP accepts a bracketed IPv6 URL":
    var server = startLocalServer("http-ok", ["--ipv6"])
    defer: server.stop()
    let result = checkHttp(
      "http://[::1]:" & $server.port & "/health",
      timeoutMs = 1000,
      search = "fixture-ok"
    )
    check result.isOk
    check result.target == "http://[::1]:" & $server.port & "/health"
    server.waitForSuccess()

  test "TCP connects and matches a response over IPv6":
    var server = startLocalServer(
      "tcp-request",
      ["--ipv6", "--expected-request=PING", "--response=PONG over IPv6"]
    )
    defer: server.stop()
    let result = checkTcp("::1", server.port, 1000, "PING", "IPv6")
    check result.isOk
    check result.target == "[::1]:" & $server.port
    server.waitForSuccess()

  test "UDP receives and matches a response over IPv6":
    var server = startLocalServer(
      "udp-echo", ["--ipv6", "--response=pong:ipv6"]
    )
    defer: server.stop()
    let result = checkUdp("[::1]", server.port, "ping", "ipv6", 1000)
    check result.isOk
    check result.target == "[::1]:" & $server.port
    server.waitForSuccess()

  test "DNS queries an IPv6 resolver transport":
    var server = startLocalServer("dns", ["--ipv6"])
    defer: server.stop()
    let result = checkDns(
      "fixture.test", "AAAA", @["2001:db8::10"],
      "[::1]:" & $server.port, 1000
    )
    check result.isOk
    check "2001:db8::10" in result.details
    server.waitForSuccess()

suite "local DNS checks":
  test "all supported record types are decoded through a chosen resolver":
    let cases = @[
      ("A", @["192.0.2.10", "192.0.2.11"]),
      ("AAAA", @["2001:db8::10"]),
      ("CNAME", @["alias.fixture.test"]),
      ("MX", @["10 mail1.fixture.test", "20 mail2.fixture.test"]),
      ("TXT", @["canary=ready", "region=eu"])
    ]
    for (recordType, expectedValues) in cases:
      var server = startLocalServer("dns")
      defer: server.stop()
      let result = checkDns(
        "fixture.test", recordType, expectedValues,
        "127.0.0.1:" & $server.port, 1000
      )
      checkpoint(recordType & ": " & result.details)
      check result.isOk
      for expected in expectedValues:
        check expected in result.details
      server.waitForSuccess()

  test "every configured DNS value is required but extra answers are allowed":
    var successServer = startLocalServer("dns")
    defer: successServer.stop()
    let success = checkDns(
      "fixture.test", "A", @["192.0.2.10"],
      "127.0.0.1:" & $successServer.port, 1000
    )
    check success.isOk
    check "192.0.2.11" in success.details
    successServer.waitForSuccess()

    var mismatchServer = startLocalServer("dns")
    defer: mismatchServer.stop()
    let mismatch = checkDns(
      "fixture.test", "A", @["192.0.2.12"],
      "127.0.0.1:" & $mismatchServer.port, 1000
    )
    check not mismatch.isOk
    check "Missing: 192.0.2.12" in mismatch.details
    mismatchServer.waitForSuccess()

  test "DNS timeout bounds an unresponsive selected resolver":
    let reservation = newSocket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
    defer: reservation.close()
    reservation.bindAddr(Port(0), "127.0.0.1")
    let port = reservation.getLocalAddr()[1]
    let started = getMonoTime()
    let result = checkDns(
      "fixture.test", "TXT", @[], "127.0.0.1:" & $port, 75
    )
    let elapsed = (getMonoTime() - started).inMilliseconds
    check not result.isOk
    check result.details == "Timeout"
    check elapsed >= 50
    check elapsed < 1000

suite "local webhook delivery":
  test "successful webhook delivery returns true":
    var server = startLocalServer("webhook-ok")
    defer: server.stop()
    check sendNotifications(
      @["http://127.0.0.1:" & $server.port & "/hook"], "Canary test", 1000
    )
    server.waitForSuccess()

  test "a slow webhook can complete within its timeout":
    var server = startLocalServer("webhook-slow", ["--delay-ms=125"])
    defer: server.stop()
    let started = getMonoTime()
    check sendNotifications(
      @["http://127.0.0.1:" & $server.port & "/hook"], "Canary test", 1000
    )
    check (getMonoTime() - started).inMilliseconds >= 100
    server.waitForSuccess()

  test "HTTP failures and timeouts are delivery failures":
    var failureServer = startLocalServer("webhook-fail")
    defer: failureServer.stop()
    check not sendNotifications(
      @["http://127.0.0.1:" & $failureServer.port & "/hook"],
      "Canary test",
      1000
    )
    failureServer.waitForSuccess()

    var slowServer = startLocalServer("webhook-slow", ["--delay-ms=250"])
    defer: slowServer.stop()
    check not sendNotifications(
      @["http://127.0.0.1:" & $slowServer.port & "/hook"], "Canary test", 50
    )

suite "local TLS certificate check":
  test "OpenSSL fetches and inspects a local certificate without a shell":
    let testDir = newTestDir("tls")
    defer: removeDir(testDir)
    let certFile = testDir / "certificate.pem"
    let keyFile = testDir / "key.pem"
    let generation = runProcess(
      "openssl",
      @[
        "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-sha256",
        "-subj", "/CN=localhost", "-addext",
        "subjectAltName=DNS:localhost", "-days", "2", "-keyout", keyFile,
        "-out", certFile
      ],
      timeoutMs = 5000
    )
    checkpoint(generation.output)
    require generation.exitCode == 0
    require not generation.timedOut

    var server = startLocalServer(
      "tls", ["--cert=" & certFile, "--key=" & keyFile]
    )
    defer: server.stop()
    let result = checkSsl("localhost", 0, server.port, 2000)
    check result.isOk
    check result.details.startsWith("Expiration:")
    server.waitForSuccess()

    var ipv6Server = startLocalServer(
      "tls", ["--ipv6", "--cert=" & certFile, "--key=" & keyFile]
    )
    defer: ipv6Server.stop()
    let ipv6Result = checkSsl(
      "https://[::1]/", 0, ipv6Server.port, 2000
    )
    check ipv6Result.isOk
    check ipv6Result.target == "::1"
    ipv6Server.waitForSuccess()

    let hadCaBundle = existsEnv("CURL_CA_BUNDLE")
    let oldCaBundle = getEnv("CURL_CA_BUNDLE")
    putEnv("CURL_CA_BUNDLE", certFile)
    defer:
      if hadCaBundle:
        putEnv("CURL_CA_BUNDLE", oldCaBundle)
      else:
        delEnv("CURL_CA_BUNDLE")
    var httpsServer = startLocalServer(
      "https-ok", ["--cert=" & certFile, "--key=" & keyFile]
    )
    defer: httpsServer.stop()
    let timedResult = checkHttp(
      "https://localhost:" & $httpsServer.port & "/health",
      timeoutMs = 2000,
      verboseTimings = true
    )
    check timedResult.isOk
    check timedResult.httpTimings.tlsHandshakeMs > 0.0
    check timedResult.httpTimings.totalMs >=
      timedResult.httpTimings.tlsHandshakeMs
    httpsServer.waitForSuccess()

suite "SQLite multiprocess concurrency":
  test "concurrent failures update one shared state row without lost writes":
    let testDir = newTestDir("concurrency")
    defer: removeDir(testDir)
    let dbPath = testDir / "state.db"
    let jobId = "tcp_shared_5432"
    handleStateAndNotify(jobId, true, "", dbPath, 100)

    var workers: seq[Process] = @[]
    for _ in 0 ..< 8:
      workers.add(startProcess(
        StateWorkerBinary,
        workingDir = ProjectRoot,
        args = [dbPath, jobId, "false", "100"],
        options = {}
      ))

    for worker in workers:
      let exitCode = worker.waitForExit()
      let stdout = worker.outputStream.readAll()
      let stderr = worker.errorStream.readAll()
      checkpoint(
        "worker exit: " & $exitCode & "\nstdout:\n" & stdout &
        "\nstderr:\n" & stderr
      )
      check exitCode == 0
      check stdout.len == 0
      check stderr.len == 0
      worker.close()

    check readState(dbPath, jobId) == ("PENDING_DOWN", 8)

  test "concurrent DOWN runs enqueue one due reminder":
    let testDir = newTestDir("concurrent-reminder")
    defer: removeDir(testDir)
    let dbPath = testDir / "state.db"
    let jobId = "shared-reminder"
    let sender: NotificationSender = proc(url, message: string): bool = true
    discard processStateAndNotify(
      jobId, false, "mock://alerts", dbPath, sender = sender,
      repeatIntervalSeconds = 60, timestampOverride = 1_000
    )

    var workers: seq[Process]
    for _ in 0 ..< 8:
      workers.add(startProcess(
        StateWorkerBinary,
        workingDir = ProjectRoot,
        args = [
          dbPath, jobId, "false", "1", "mock://alerts", "60", "2000"
        ],
        options = {}
      ))

    for worker in workers:
      let exitCode = worker.waitForExit()
      let stdout = worker.outputStream.readAll()
      let stderr = worker.errorStream.readAll()
      checkpoint(
        "worker exit: " & $exitCode & "\nstdout:\n" & stdout &
        "\nstderr:\n" & stderr
      )
      check exitCode == 0
      check stdout.len == 0
      worker.close()

    let db = openDatabase(dbPath)
    defer: db.close()
    let row = db.one(
      "SELECT COUNT(*) FROM notification_outbox " &
      "WHERE check_id = ? AND event_kind = 'REMINDER'",
      jobId
    )
    require row.isSome
    check row.get()[0].fromDb(int) == 1
