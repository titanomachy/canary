import nim_sqlite
import std/[monotimes, net, options, os, osproc, streams, strutils, times,
            unittest]
import ../../src/[common, notifier, process_runner]
import ../../src/checks/[httpcheck, sslcheck, udpcheck]
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

suite "local webhook delivery":
  test "successful webhook delivery returns true":
    var server = startLocalServer("webhook-ok")
    defer: server.stop()
    check sendNotifications(
      "http://127.0.0.1:" & $server.port & "/hook", "Canary test", 1000
    )
    server.waitForSuccess()

  test "a slow webhook can complete within its timeout":
    var server = startLocalServer("webhook-slow", ["--delay-ms=125"])
    defer: server.stop()
    let started = getMonoTime()
    check sendNotifications(
      "http://127.0.0.1:" & $server.port & "/hook", "Canary test", 1000
    )
    check (getMonoTime() - started).inMilliseconds >= 100
    server.waitForSuccess()

  test "HTTP failures and timeouts are delivery failures":
    var failureServer = startLocalServer("webhook-fail")
    defer: failureServer.stop()
    check not sendNotifications(
      "http://127.0.0.1:" & $failureServer.port & "/hook",
      "Canary test",
      1000
    )
    failureServer.waitForSuccess()

    var slowServer = startLocalServer("webhook-slow", ["--delay-ms=250"])
    defer: slowServer.stop()
    check not sendNotifications(
      "http://127.0.0.1:" & $slowServer.port & "/hook", "Canary test", 50
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
        "-subj", "/CN=localhost", "-days", "2", "-keyout", keyFile,
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
