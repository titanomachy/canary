import std/[json, os, osproc, streams, strutils, unittest]
import ../../src/canary_contract
import ../../src/process_runner
import ../test_support

when not defined(windows):
  {.error: "The Windows compatibility suite must run on Windows".}

type CliResult = object
  exitCode: int
  stdout: string
  stderr: string

const
  ProjectRoot = currentSourcePath().parentDir.parentDir.parentDir
  CanaryBinary = ProjectRoot / "build" / ("canary" & ExeExt)

proc runCanary(args: openArray[string]): CliResult =
  let process = startProcess(
    CanaryBinary,
    workingDir = ProjectRoot,
    args = args,
    options = {}
  )
  defer: process.close()
  result.exitCode = process.waitForExit()
  result.stdout = process.outputStream.readAll()
  result.stderr = process.errorStream.readAll()

template describe(result: CliResult) =
  checkpoint(
    "exit code: " & $result.exitCode & "\nstdout:\n" & result.stdout &
      "\nstderr:\n" & result.stderr
  )

suite "Windows compatibility":
  test "the Windows executable starts":
    let result = runCanary(["--version"])
    result.describe()
    check result.exitCode == ExitUp
    check CanaryVersion in result.stdout
    check result.stderr.len == 0

  test "HTTP timing loads libcurl and regex assertions load PCRE":
    var timingServer = startLocalServer("http-ok", ["--delay-ms=60"])
    defer: timingServer.stop()
    let timingResult = runCanary([
      "http", "http://127.0.0.1:" & $timingServer.port & "/health",
      "--timeout", "1000", "--timing", "--json"
    ])
    timingResult.describe()
    check timingResult.exitCode == ExitUp
    check timingResult.stderr.len == 0
    let payload = parseJson(timingResult.stdout)
    check payload["timings_ms"]["total"].getFloat() > 0.0
    timingServer.waitForSuccess()

    var regexServer = startLocalServer("http-ok")
    defer: regexServer.stop()
    let regexResult = runCanary([
      "http", "http://127.0.0.1:" & $regexServer.port & "/health",
      "--regex", "fixture-[a-z]+"
    ])
    regexResult.describe()
    check regexResult.exitCode == ExitUp
    check regexResult.stderr.len == 0
    regexServer.waitForSuccess()

  test "TCP UDP and DNS checks use Windows sockets":
    var tcpServer = startLocalServer(
      "tcp-request", ["--expected-request=PING", "--response=PONG ready"]
    )
    defer: tcpServer.stop()
    let tcpResult = runCanary([
      "tcp", "127.0.0.1", "--port", $tcpServer.port,
      "--request", "PING", "--expected", "PONG", "--timeout", "1000"
    ])
    tcpResult.describe()
    check tcpResult.exitCode == ExitUp
    tcpServer.waitForSuccess()

    var udpServer = startLocalServer("udp-echo", ["--response=healthy"])
    defer: udpServer.stop()
    let udpResult = runCanary([
      "udp", "127.0.0.1", "--port", $udpServer.port,
      "--expected", "healthy", "--timeout", "1000"
    ])
    udpResult.describe()
    check udpResult.exitCode == ExitUp
    udpServer.waitForSuccess()

    var dnsServer = startLocalServer("dns")
    defer: dnsServer.stop()
    let dnsResult = runCanary([
      "dns", "fixture.test", "--type", "A", "--expected", "192.0.2.10",
      "--resolver", "127.0.0.1:" & $dnsServer.port, "--timeout", "1000"
    ])
    dnsResult.describe()
    check dnsResult.exitCode == ExitUp
    dnsServer.waitForSuccess()

  test "command checks and timeouts work with Windows exit semantics":
    let commandResult = runCanary([
      "command", "cmd.exe", "--arg", "/d", "--arg", "/c", "--arg",
      "echo ready", "--outputMatch", "ready", "--timeout", "1000"
    ])
    commandResult.describe()
    check commandResult.exitCode == ExitUp

    let timeoutResult = runProcess(
      "ping.exe", @["-n", "3", "127.0.0.1"], timeoutMs = 25
    )
    check timeoutResult.timedOut
    check timeoutResult.exitCode == 137

  test "ICMP uses Windows ping arguments":
    let result = runCanary([
      "icmp", "127.0.0.1", "--count", "1", "--timeout", "1000"
    ])
    result.describe()
    check result.exitCode == ExitUp
    check result.stderr.len == 0

  test "OpenSSL performs a local certificate check":
    let testDir = newTestDir("windows-tls")
    defer: removeDir(testDir)
    let certFile = testDir / "certificate.pem"
    let keyFile = testDir / "key.pem"
    let generation = runProcess(
      "openssl.exe",
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
    let result = runCanary([
      "ssl", "localhost", "--port", $server.port, "--minDays", "0",
      "--timeout", "2000"
    ])
    result.describe()
    check result.exitCode == ExitUp
    check result.stderr.len == 0
    server.waitForSuccess()

    let hadCertFile = existsEnv("SSL_CERT_FILE")
    let oldCertFile = getEnv("SSL_CERT_FILE")
    putEnv("SSL_CERT_FILE", certFile)
    defer:
      if hadCertFile:
        putEnv("SSL_CERT_FILE", oldCertFile)
      else:
        delEnv("SSL_CERT_FILE")
    var httpsServer = startLocalServer(
      "https-ok", ["--cert=" & certFile, "--key=" & keyFile]
    )
    defer: httpsServer.stop()
    let httpsResult = runCanary([
      "http", "https://localhost:" & $httpsServer.port & "/health",
      "--timeout", "2000"
    ])
    httpsResult.describe()
    check httpsResult.exitCode == ExitUp
    check httpsResult.stderr.len == 0
    httpsServer.waitForSuccess()

  test "SQLite state persists on Windows":
    let testDir = newTestDir("windows-state")
    defer: removeDir(testDir)
    let dbPath = testDir / "state.db"
    var server = startLocalServer("http-ok")
    defer: server.stop()
    let result = runCanary([
      "http", "http://127.0.0.1:" & $server.port & "/health",
      "--id", "windows-state", "--db", dbPath
    ])
    result.describe()
    check result.exitCode == ExitUp
    check fileExists(dbPath)
    server.waitForSuccess()
