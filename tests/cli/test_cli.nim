import nim_sqlite
import std/[json, monotimes, nativesockets, net, options, os, osproc, streams,
            strtabs, strutils, times, unittest]
import ../../src/[canary_contract, process_runner]
import ../test_support

type CliResult = object
  exitCode: int
  stdout: string
  stderr: string

const
  ProjectRoot = currentSourcePath().parentDir.parentDir.parentDir
  CanaryBinary = ProjectRoot / "build" / ("canary" & ExeExt)

proc testEnvironment(overrides: seq[(string, string)] = @[]): StringTableRef =
  ## Keep unrelated process settings, but isolate all Canary configuration so
  ## local operator defaults cannot influence black-box contracts.
  result = newStringTable(modeCaseSensitive)
  for key, value in envPairs():
    if not key.startsWith("CANARY_"):
      result[key] = value
  result["XDG_CONFIG_HOME"] = getTempDir() / (
    "canary-cli-empty-config-root-" & $getCurrentProcessId()
  )
  for (key, value) in overrides:
    result[key] = value

proc runCanary(args: openArray[string],
               environment: seq[(string, string)] = @[]): CliResult =
  let process = startProcess(
    CanaryBinary,
    workingDir = ProjectRoot,
    args = args,
    env = testEnvironment(environment),
    options = {}
  )
  defer: process.close()

  result.exitCode = process.waitForExit()
  # These commands have bounded, small output. Reading after waitForExit keeps
  # the harness simple while preserving stdout and stderr as separate channels.
  result.stdout = process.outputStream.readAll()
  result.stderr = process.errorStream.readAll()

template describe(result: CliResult) =
  checkpoint(
    "exit code: " & $result.exitCode & "\n" &
    "stdout:\n" & result.stdout & "\n" &
    "stderr:\n" & result.stderr
  )

proc listeningSocket(): (Socket, Port) =
  let socket = newSocket()
  socket.setSockOpt(OptReuseAddr, true)
  socket.bindAddr(Port(0), "127.0.0.1")
  socket.listen()
  (socket, socket.getLocalAddr()[1])

proc reservedPort(): (Socket, Port) =
  ## Binding without listening reserves a port on which a TCP connect is
  ## deterministically refused while the socket remains open.
  let socket = newSocket()
  socket.setSockOpt(OptReuseAddr, true)
  socket.bindAddr(Port(0), "127.0.0.1")
  (socket, socket.getLocalAddr()[1])

suite "Canary CLI compatibility contract":
  test "no arguments prints general help":
    let result = runCanary([])
    result.describe()
    check result.exitCode == 0
    check result.stdout.contains("Usage:")
    check result.stdout.contains("http")
    check result.stdout.contains("tcp")
    check result.stderr.len == 0

  test "top-level help lists all commands":
    let result = runCanary(["--help"])
    result.describe()
    check result.exitCode == 0
    for command in [
      "http", "ssl", "tcp", "udp", "dns", "icmp", "command", "notify"
    ]:
      check result.stdout.contains(command)
    check result.stderr.len == 0

  test "command help describes command options":
    let result = runCanary(["http", "--help"])
    result.describe()
    check result.exitCode == 0
    check result.stdout.contains("--timeout")
    check result.stdout.contains("--status")
    check result.stdout.contains("--statusRange")
    check result.stdout.contains("--maxLatency")
    check result.stdout.contains("total HTTP response time")
    check result.stdout.contains("--responseHeader")
    check result.stdout.contains("--regex")
    check result.stdout.contains("--jsonField")
    check result.stdout.contains("--verbose")
    check result.stdout.contains("--json")
    check result.stdout.contains("--id")
    check result.stdout.contains("--config")
    check result.stdout.contains("--recoveryThreshold")
    check result.stdout.contains("--cooldown")
    check result.stdout.contains("--repeatInterval")
    check result.stdout.contains("--silenceUntil")
    check result.stderr.len == 0

  test "HTTP verbose JSON exposes phase timings through the CLI":
    var server = startLocalServer("http-ok", ["--delay-ms=75"])
    defer: server.stop()
    let result = runCanary([
      "http", "http://127.0.0.1:" & $server.port & "/health",
      "--timeout", "1000", "--timing", "--json"
    ])
    result.describe()
    check result.exitCode == ExitUp
    check result.stderr.len == 0
    let payload = parseJson(result.stdout)
    check payload["timings_ms"]["dns"].getFloat() >= 0.0
    check payload["timings_ms"]["tcp_connect"].getFloat() >= 0.0
    check payload["timings_ms"]["tls_handshake"].getFloat() == 0.0
    check payload["timings_ms"]["ttfb"].getFloat() >= 40.0
    check payload["timings_ms"]["transfer"].getFloat() >= 0.0
    check payload["timings_ms"]["total"].getFloat() > 0.0
    server.waitForSuccess()

  test "DNS help describes record, resolver, expectation, and timeout options":
    let result = runCanary(["dns", "--help"])
    result.describe()
    check result.exitCode == ExitUp
    for option in ["--type", "--expected", "--resolver", "--timeout"]:
      check option in result.stdout
    check result.stderr.len == 0

  test "TCP help describes request, banner matching, and timeout options":
    let result = runCanary(["tcp", "--help"])
    result.describe()
    check result.exitCode == ExitUp
    for option in ["--request", "--expected", "--timeout"]:
      check option in result.stdout
    check result.stderr.len == 0

  test "command help describes argv, timeout, exit, and output assertions":
    let result = runCanary(["command", "--help"])
    result.describe()
    check result.exitCode == ExitUp
    for option in ["--arg", "--timeout", "--exitCode", "--outputMatch"]:
      check option in result.stdout
    check "combined stdout" in result.stdout
    check "stderr" in result.stdout
    check result.stderr.len == 0

  test "version comes from the canonical contract":
    let result = runCanary(["--version"])
    result.describe()
    check result.exitCode == 0
    check result.stdout == CanaryVersion & "\n"
    check result.stderr.len == 0

  test "a missing default config file is silently ignored":
    let testDir = getTempDir() / (
      "canary-cli-no-default-config-" & $getCurrentProcessId() & "-" &
      $(epochTime() * 1_000_000).int64
    )
    createDir(testDir)
    defer: removeDir(testDir)

    let result = runCanary(
      ["dns", "localhost"],
      @[("XDG_CONFIG_HOME", testDir)]
    )
    result.describe()
    check result.exitCode == ExitUp
    check result.stdout.contains("DNS OK")
    check result.stderr.len == 0

  test "an explicitly requested missing config file is an error":
    let result = runCanary([
      "dns", "localhost", "--config", "/definitely/missing/canary.toml"
    ])
    result.describe()
    check result.exitCode == ExitConfigError
    check result.stdout.len == 0
    check result.stderr.toLowerAscii().contains("configuration")

  test "TOML environment and CLI values follow documented precedence":
    let (server, configuredPort) = listeningSocket()
    defer: server.close()
    let (reservation, environmentPort) = reservedPort()
    defer: reservation.close()
    let testDir = getTempDir() / (
      "canary-cli-precedence-" & $getCurrentProcessId() & "-" &
      $(epochTime() * 1_000_000).int64
    )
    createDir(testDir)
    defer: removeDir(testDir)
    let configPath = testDir / "canary.toml"
    writeFile(configPath,
      "json = true\n" &
      "retries = 2\n\n" &
      "[tcp]\n" &
      "port = " & $configuredPort & "\n" &
      "timeout = 500\n")

    let fromToml = runCanary([
      "tcp", "127.0.0.1", "--config", configPath
    ])
    fromToml.describe()
    check fromToml.exitCode == ExitUp
    check parseJson(fromToml.stdout)["target"].getStr().endsWith(
      ":" & $configuredPort
    )

    let fromEnvironment = runCanary(
      ["tcp", "127.0.0.1", "--config", configPath],
      @[("CANARY_PORT", $environmentPort)]
    )
    fromEnvironment.describe()
    check fromEnvironment.exitCode == ExitDown
    check parseJson(fromEnvironment.stdout)["target"].getStr().endsWith(
      ":" & $environmentPort
    )

    let fromCli = runCanary(
      [
        "tcp", "127.0.0.1", "--config", configPath,
        "--port", $configuredPort
      ],
      @[("CANARY_PORT", $environmentPort)]
    )
    fromCli.describe()
    check fromCli.exitCode == ExitUp
    check parseJson(fromCli.stdout)["target"].getStr().endsWith(
      ":" & $configuredPort
    )

  test "invalid TOML types are configuration errors":
    let testDir = getTempDir() / (
      "canary-cli-invalid-toml-" & $getCurrentProcessId() & "-" &
      $(epochTime() * 1_000_000).int64
    )
    createDir(testDir)
    defer: removeDir(testDir)
    let configPath = testDir / "canary.toml"
    writeFile(configPath, "[tcp]\nport = \"not-an-integer\"\n")

    let result = runCanary([
      "tcp", "127.0.0.1", "--config", configPath
    ])
    result.describe()
    check result.exitCode == ExitConfigError
    check result.stdout.len == 0
    check result.stderr.toLowerAscii().contains("configuration")

  test "TOML values pass through parser-independent validation":
    let testDir = getTempDir() / (
      "canary-cli-invalid-config-value-" & $getCurrentProcessId() & "-" &
      $(epochTime() * 1_000_000).int64
    )
    createDir(testDir)
    defer: removeDir(testDir)
    let configPath = testDir / "canary.toml"
    writeFile(configPath, "[tcp]\nport = 70000\n")

    let result = runCanary([
      "tcp", "127.0.0.1", "--config", configPath
    ])
    result.describe()
    check result.exitCode == ExitConfigError
    check result.stdout.len == 0
    check result.stderr.startsWith("Configuration error:")
    check result.stderr.toLowerAscii().contains("port")

  test "unknown command is a usage error":
    let result = runCanary(["unknown"])
    result.describe()
    check result.exitCode == 2
    check result.stdout.len == 0
    check result.stderr.toLowerAscii().contains("unknown")

  test "unknown option is a usage error":
    let result = runCanary(["http", "https://example.invalid", "--unknown"])
    result.describe()
    check result.exitCode == 2
    check result.stdout.len == 0
    check result.stderr.toLowerAscii().contains("unknown")

  test "missing positional target is a configuration error":
    let result = runCanary(["http"])
    result.describe()
    check result.exitCode == 2
    check result.stdout.len == 0
    check result.stderr.contains("no URL specified")

  test "missing required option is a usage error":
    let result = runCanary(["tcp", "127.0.0.1"])
    result.describe()
    check result.exitCode == 2
    check result.stdout.len == 0
    check result.stderr.toLowerAscii().contains("port")

  test "invalid integer is a usage error":
    let result = runCanary([
      "http", "https://example.invalid", "--timeout", "not-an-integer"
    ])
    result.describe()
    check result.exitCode == 2
    check result.stdout.len == 0
    check result.stderr.toLowerAscii().contains("timeout")

  test "invalid port range is a configuration error":
    let result = runCanary(["tcp", "127.0.0.1", "--port", "70000"])
    result.describe()
    check result.exitCode == 2
    check result.stdout.len == 0
    check result.stderr.toLowerAscii().contains("port")

  test "invalid check parameters are configuration errors":
    for args in [
      @["http", "http://127.0.0.1", "--timeout", "0"],
      @["http", "http://127.0.0.1", "--retries", "0"],
      @["http", "http://127.0.0.1", "--recoveryThreshold", "0"],
      @["http", "http://127.0.0.1", "--cooldown", "-1"],
      @["http", "http://127.0.0.1", "--repeatInterval", "-1"],
      @["http", "http://127.0.0.1", "--silenceUntil", "tomorrow"],
      @["http", "http://127.0.0.1", "--status", "99"],
      @["http", "http://127.0.0.1", "--methodStr", "BREW"],
      @["tcp", "bad host", "--port", "80"],
      @["dns", "example.test", "--expected", "not-an-ip"],
      @["dns", "example.test", "--type", "SRV"],
      @["dns", "example.test", "--resolver", "resolver.example.test"],
      @["dns", "example.test", "--timeout", "0"],
      @["icmp", "127.0.0.1", "--count", "0"],
      @["icmp", "127.0.0.1", "--count", "101"],
      @["command", "/usr/bin/true", "--exitCode", "256"]
    ]:
      let result = runCanary(args)
      result.describe()
      check result.exitCode == ExitConfigError
      check result.stdout.len == 0
      check result.stderr.startsWith("Configuration error:")

  test "DNS record type and repeated expectations work through the CLI":
    var server = startLocalServer("dns")
    defer: server.stop()
    let result = runCanary([
      "dns", "fixture.test", "--type", "MX",
      "--expected", "10 mail1.fixture.test",
      "--expected", "20 mail2.fixture.test",
      "--resolver", "127.0.0.1:" & $server.port,
      "--timeout", "1000", "--json"
    ])
    result.describe()
    check result.exitCode == ExitUp
    let payload = parseJson(result.stdout)
    check payload["status"].getStr() == "UP"
    check "10 mail1.fixture.test" in payload["details"].getStr()
    check "20 mail2.fixture.test" in payload["details"].getStr()
    server.waitForSuccess()

  test "unknown HTTP methods are rejected before network access":
    let result = runCanary([
      "http", "http://127.0.0.1:1/?token=must-not-leak",
      "--methodStr", "BREW"
    ])
    result.describe()
    check result.exitCode == ExitConfigError
    check result.stdout.len == 0
    check "must-not-leak" notin result.stderr

  test "command fragments in hostnames are configuration errors":
    let result = runCanary([
      "icmp", "127.0.0.1;touch-pwned", "--count", "1"
    ])
    result.describe()
    check result.exitCode == ExitConfigError
    check result.stdout.len == 0
    check "hostname is invalid" in result.stderr

  test "local command checks exit code and combined output":
    let result = runCanary([
      "command", "/usr/bin/printf", "--arg", "%s", "--arg", "ready",
      "--outputMatch", "ready", "--timeout", "500", "--json"
    ])
    result.describe()
    check result.exitCode == ExitUp
    check result.stderr.len == 0
    let payload = parseJson(result.stdout)
    check payload["check"].getStr() == "command"
    check payload["target"].getStr() == "/usr/bin/printf"
    check payload["status"].getStr() == "UP"
    check "expected output received" in payload["details"].getStr()

  test "command accepts an expected nonzero exit code":
    let result = runCanary([
      "command", "/usr/bin/false", "--exitCode", "1", "--timeout", "500"
    ])
    result.describe()
    check result.exitCode == ExitUp
    check "COMMAND OK" in result.stdout
    check result.stderr.len == 0

  test "command assertion failures are DOWN without leaking match content":
    let result = runCanary([
      "command", "/usr/bin/printf", "--arg", "actual",
      "--outputMatch", "private-expected-text", "--timeout", "500"
    ])
    result.describe()
    check result.exitCode == ExitDown
    check "Expected output not received" in result.stdout
    check "private-expected-text" notin result.stdout
    check "private-expected-text" notin result.stderr

  test "command timeout is a bounded DOWN result":
    let result = runCanary([
      "command", "/usr/bin/sleep", "--arg", "1", "--timeout", "25"
    ])
    result.describe()
    check result.exitCode == ExitDown
    check "COMMAND TIMEOUT" in result.stdout
    check result.stderr.len == 0

  test "a missing command executable is a configuration error":
    let result = runCanary([
      "command", "/definitely/not/a/canary-executable", "--timeout", "100"
    ])
    result.describe()
    check result.exitCode == ExitConfigError
    check result.stdout.len == 0
    check "could not be started" in result.stderr

  test "documented short option after target is accepted for an UP check":
    let (server, port) = listeningSocket()
    defer: server.close()

    let result = runCanary([
      "tcp", "127.0.0.1", "-p", $port, "--timeout", "500"
    ])
    result.describe()
    check result.exitCode == 0
    check result.stdout.contains("TCP OK")
    check result.stderr.len == 0

  test "TCP request and expected response work through the CLI":
    var server = startLocalServer(
      "tcp-request",
      ["--expected-request=PING", "--response=PONG: healthy"]
    )
    defer: server.stop()
    let result = runCanary([
      "tcp", "127.0.0.1", "--port", $server.port,
      "--request", "PING", "--expected", "healthy", "--timeout", "1000",
      "--json"
    ])
    result.describe()
    check result.exitCode == ExitUp
    let payload = parseJson(result.stdout)
    check payload["status"].getStr() == "UP"
    check payload["details"].getStr().startsWith(
      "Expected response received"
    )
    server.waitForSuccess()

  test "an IPv6 TCP target works through the CLI and JSON contract":
    var server = startLocalServer(
      "tcp-banner", ["--ipv6", "--response=IPv6 ready"]
    )
    defer: server.stop()
    let result = runCanary([
      "tcp", "::1", "--port", $server.port, "--expected", "IPv6",
      "--timeout", "1000", "--json"
    ])
    result.describe()
    check result.exitCode == ExitUp
    let payload = parseJson(result.stdout)
    check payload["target"].getStr() == "[::1]:" & $server.port
    check payload["status"].getStr() == "UP"
    server.waitForSuccess()

  test "refused connection is a completed DOWN check":
    let (reservation, port) = reservedPort()
    defer: reservation.close()

    let result = runCanary([
      "tcp", "127.0.0.1", "--port=" & $port, "--timeout=500"
    ])
    result.describe()
    check result.exitCode == 1
    check result.stdout.contains("TCP ERROR")
    check result.stderr.len == 0

  test "notification errors do not expose webhook credentials or paths":
    let (reservation, port) = reservedPort()
    defer: reservation.close()
    let testDir = getTempDir() / (
      "canary-cli-redaction-" & $getCurrentProcessId() & "-" &
      $(epochTime() * 1_000_000).int64
    )
    createDir(testDir)
    defer: removeDir(testDir)
    let notifyUrl =
      "http://user:password@127.0.0.1:1/private-hook?token=secret"

    let result = runCanary([
      "tcp", "127.0.0.1", "--port", $port, "--timeout", "500",
      "--db", testDir / "state.db", "--notify", notifyUrl
    ])
    result.describe()
    check result.exitCode == ExitDown
    check result.stdout.contains("TCP ERROR")
    check result.stderr.contains("http://127.0.0.1")
    for secret in ["user", "password", "private-hook", "token", "secret"]:
      check secret notin result.stderr

  test "JSON mode writes one valid object to stdout":
    let (server, port) = listeningSocket()
    defer: server.close()

    let result = runCanary([
      "tcp", "127.0.0.1", "--port", $port, "--timeout", "500", "--json"
    ])
    result.describe()
    check result.exitCode == 0
    check result.stderr.len == 0

    let payload = parseJson(result.stdout)
    check payload["check"].getStr() == "tcp"
    check payload["status"].getStr() == "UP"
    check payload["target"].getStr() == "127.0.0.1:" & $port

  test "JSON mode includes redacted outbox delivery results":
    let (reservation, port) = reservedPort()
    defer: reservation.close()
    let testDir = getTempDir() / (
      "canary-cli-delivery-json-" & $getCurrentProcessId() & "-" &
      $(epochTime() * 1_000_000).int64
    )
    createDir(testDir)
    defer: removeDir(testDir)

    let result = runCanary([
      "tcp", "127.0.0.1", "--port", $port, "--timeout", "500",
      "--json", "--db", testDir / "state.db",
      "--notify", "mock://must-not-leak"
    ])
    result.describe()
    check result.exitCode == ExitDown
    let payload = parseJson(result.stdout)
    check payload["notifications"].len == 1
    check payload["notifications"][0]["status"].getStr() == "retry"
    check payload["notifications"][0]["attempt"].getInt() == 1
    check "must-not-leak" notin result.stdout
    check "must-not-leak" notin result.stderr

  test "repeated notify options create separate outbox events":
    let (reservation, port) = reservedPort()
    defer: reservation.close()
    let testDir = getTempDir() / (
      "canary-cli-repeated-notify-" & $getCurrentProcessId() & "-" &
      $(epochTime() * 1_000_000).int64
    )
    createDir(testDir)
    defer: removeDir(testDir)

    let result = runCanary([
      "tcp", "127.0.0.1", "--port", $port, "--timeout", "500",
      "--json", "--db", testDir / "state.db",
      "--notify", "mock://first-secret",
      "--notify", "mock://second-secret"
    ])
    result.describe()
    check result.exitCode == ExitDown
    let payload = parseJson(result.stdout)
    check payload["notifications"].len == 2
    for secret in ["first-secret", "second-secret"]:
      check secret notin result.stdout
      check secret notin result.stderr

  test "a maintenance silence updates state without attempting delivery":
    let (reservation, port) = reservedPort()
    defer: reservation.close()
    let testDir = getTempDir() / (
      "canary-cli-silence-" & $getCurrentProcessId() & "-" &
      $(epochTime() * 1_000_000).int64
    )
    createDir(testDir)
    defer: removeDir(testDir)

    let result = runCanary([
      "tcp", "127.0.0.1", "--port", $port, "--timeout", "500",
      "--json", "--db", testDir / "state.db",
      "--notify", "mock://must-not-leak", "--silenceUntil",
      "2099-01-01T00:00:00Z"
    ])
    result.describe()
    check result.exitCode == ExitDown
    check result.stderr.len == 0
    let payload = parseJson(result.stdout)
    check payload["notifications"].len == 0

    let db = openDatabase(testDir / "state.db")
    defer: db.close()
    let row = db.one(
      "SELECT status, incident_alerted, silenced_until FROM canary_state"
    )
    require row.isSome
    check row.get()[0].fromDb(string) == "DOWN"
    check row.get()[1].fromDb(int) == 0
    check row.get()[2].fromDb(int64) > getTime().toUnix()

  test "notification test loads its secret from the environment":
    var webhook = startLocalServer("webhook-ok")
    defer: webhook.stop()
    let notifyUrl = "http://127.0.0.1:" & $webhook.port &
      "/private-hook?token=secret"

    let result = runCanary(
      ["notify", "test", "webhook"],
      @[("CANARY_NOTIFY", notifyUrl)]
    )
    result.describe()
    check result.exitCode == ExitUp
    check result.stdout.contains("Notification test delivered via webhook")
    for secret in ["private-hook", "token", "secret"]:
      check secret notin result.stdout
      check secret notin result.stderr
    webhook.waitForSuccess()

  test "notification test rejects a provider mismatch before delivery":
    let result = runCanary([
      "notify", "test", "slack",
      "--notify", "https://discord.com/api/webhooks/must-not-leak"
    ])
    result.describe()
    check result.exitCode == ExitConfigError
    check result.stdout.len == 0
    check result.stderr.contains("Slack notification URLs")
    check "must-not-leak" notin result.stderr

  test "explicit IDs keep state separate for checks on the same target":
    let (server, port) = listeningSocket()
    defer: server.close()
    let testDir = getTempDir() / (
      "canary-cli-id-" & $getCurrentProcessId() & "-" &
      $(epochTime() * 1_000_000).int64
    )
    createDir(testDir)
    defer: removeDir(testDir)
    let dbPath = testDir / "state.db"

    for checkId in ["api-status", "api-content"]:
      let result = runCanary([
        "tcp", "127.0.0.1", "--port", $port, "--timeout", "500",
        "--db", dbPath, "--id", checkId
      ])
      result.describe()
      check result.exitCode == ExitUp
      check result.stderr.len == 0

    let db = openDatabase(dbPath)
    defer: db.close()
    for checkId in ["api-status", "api-content"]:
      check db.one(
        "SELECT id FROM canary_state WHERE id = ?", checkId
      ).isSome

suite "sequential multi-port checks":
  test "TCP prints one line per unique port and aggregates failures":
    let (reservation, closedPort) = reservedPort()
    defer: reservation.close()
    let (server, openPort) = listeningSocket()
    defer: server.close()
    let result = runCanary([
      "tcp", "127.0.0.1", "--port", $closedPort & "," & $openPort &
        "," & $closedPort, "--timeout", "500"
    ])
    result.describe()
    check result.exitCode == ExitDown
    check result.stderr.len == 0
    let lines = result.stdout.strip().splitLines()
    require lines.len == 2
    check "TCP ERROR - 127.0.0.1:" & $closedPort in lines[0]
    check "TCP OK - 127.0.0.1:" & $openPort in lines[1]

  test "all successful ports yield UP and one ordered JSON object":
    let (first, firstPort) = listeningSocket()
    defer: first.close()
    let (second, secondPort) = listeningSocket()
    defer: second.close()
    let result = runCanary([
      "tcp", "127.0.0.1", "-p", $secondPort & "," & $firstPort, "--json"
    ])
    result.describe()
    check result.exitCode == ExitUp
    check result.stderr.len == 0
    let payload = parseJson(result.stdout)
    check payload["status"].getStr() == "UP"
    require payload["results"].len == 2
    check payload["results"][0]["target"].getStr() == "127.0.0.1:" & $secondPort
    check payload["results"][1]["target"].getStr() == "127.0.0.1:" & $firstPort

  test "TCP banner timeouts are sequential and apply separately to each port":
    var first = startLocalServer("tcp-silent", ["--delay-ms=300"])
    defer: first.stop()
    var second = startLocalServer("tcp-silent", ["--delay-ms=300"])
    defer: second.stop()
    let started = getMonoTime()
    let result = runCanary([
      "tcp", "127.0.0.1", "--port=" & $first.port & "," & $second.port,
      "--expected", "ready", "--timeout", "100", "--json"
    ])
    let elapsed = (getMonoTime() - started).inMilliseconds
    result.describe()
    check result.exitCode == ExitDown
    check elapsed >= 180
    let payload = parseJson(result.stdout)
    require payload["results"].len == 2
    for item in payload["results"]:
      check item["details"].getStr() == "Timeout"

  test "IPv6 multi-port results retain bracketed endpoints":
    var first = startLocalServer("tcp-banner", ["--ipv6", "--response=ready"])
    defer: first.stop()
    var second = startLocalServer("tcp-banner", ["--ipv6", "--response=ready"])
    defer: second.stop()
    let result = runCanary([
      "tcp", "::1", "--port", $first.port & "," & $second.port,
      "--expected", "ready", "--timeout", "1000", "--json"
    ])
    result.describe()
    check result.exitCode == ExitUp
    let payload = parseJson(result.stdout)
    require payload["results"].len == 2
    check payload["results"][0]["target"].getStr() == "[::1]:" & $first.port
    check payload["results"][1]["target"].getStr() == "[::1]:" & $second.port
    first.waitForSuccess()
    second.waitForSuccess()

  test "UDP response assertions apply to every port and continue after failure":
    var first = startLocalServer("udp-echo", ["--response=wrong"])
    defer: first.stop()
    var second = startLocalServer("udp-echo", ["--response=pong"])
    defer: second.stop()
    let result = runCanary([
      "udp", "127.0.0.1", "--port", $first.port & "," & $second.port,
      "--payload", "ping", "--expected", "pong", "--timeout", "1000", "--json"
    ])
    result.describe()
    check result.exitCode == ExitDown
    check result.stderr.len == 0
    let payload = parseJson(result.stdout)
    check payload["status"].getStr() == "DOWN"
    require payload["results"].len == 2
    check payload["results"][0]["status"].getStr() == "DOWN"
    check payload["results"][1]["status"].getStr() == "UP"
    check payload["results"][1]["target"].getStr() == "127.0.0.1:" & $second.port
    first.waitForSuccess()
    second.waitForSuccess()

  test "SSL results identify each port in text and JSON and continue after failure":
    let testDir = newTestDir("multi-port-tls")
    defer: removeDir(testDir)
    let certFile = testDir / "certificate.pem"
    let keyFile = testDir / "key.pem"
    let generation = runProcess(
      "openssl", @[
        "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-sha256",
        "-subj", "/CN=localhost", "-days", "2",
        "-keyout", keyFile, "-out", certFile
      ], timeoutMs = 5000
    )
    checkpoint(generation.output)
    require generation.exitCode == 0
    require not generation.timedOut
    let (reservation, closedPort) = reservedPort()
    defer: reservation.close()
    for asJson in [false, true]:
      var server = startLocalServer("tls", ["--cert=" & certFile, "--key=" & keyFile])
      defer: server.stop()
      var args = @[
        "ssl", "127.0.0.1", "--port", $closedPort & "," & $server.port,
        "--minDays", "0", "--timeout", "2000"
      ]
      if asJson: args.add("--json")
      let result = runCanary(args)
      result.describe()
      check result.exitCode == ExitDown
      check result.stderr.len == 0
      if asJson:
        let payload = parseJson(result.stdout)
        require payload["results"].len == 2
        check payload["results"][0]["status"].getStr() == "DOWN"
        check payload["results"][1]["status"].getStr() == "UP"
        check payload["results"][1]["target"].getStr() == "127.0.0.1:" & $server.port
      else:
        let lines = result.stdout.strip().splitLines()
        require lines.len == 2
        check "SSL ERROR - 127.0.0.1:" & $closedPort in lines[0]
        check "SSL OK - 127.0.0.1:" & $server.port in lines[1]
      server.waitForSuccess()

  test "invalid later ports are rejected before probes or state updates":
    let testDir = newTestDir("invalid-port-list")
    defer: removeDir(testDir)
    for command in ["tcp", "udp", "ssl"]:
      let server = if command == "udp":
        newSocket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
      else:
        newSocket()
      defer: server.close()
      server.bindAddr(Port(0), "127.0.0.1")
      if command != "udp": server.listen()
      let port = server.getLocalAddr()[1]
      for suffix in [",0", ",65536", ",nope", ",", ",,465"]:
        let dbPath = testDir / "state.db"
        let result = runCanary([
          command, "127.0.0.1", "--port", $port & suffix, "--db", dbPath
        ])
        result.describe()
        check result.exitCode == ExitConfigError
        check result.stdout.len == 0
        check "port" in result.stderr.toLowerAscii()
        check not fileExists(dbPath)
        var readable = @[server.getFd()]
        check selectRead(readable, 0) == 0

  test "ports retain independent counters and outbox events with generated or explicit IDs":
    for checkId in ["", "mail"]:
      let testDir = newTestDir("port-state")
      defer: removeDir(testDir)
      let dbPath = testDir / "state.db"
      let (reservation, closedPort) = reservedPort()
      defer: reservation.close()
      let (server, openPort) = listeningSocket()
      defer: server.close()
      var args = @[
        "tcp", "127.0.0.1", "--port", $closedPort & "," & $openPort &
          "," & $closedPort, "--db", dbPath, "--retries", "2", "--json",
        "--notify", "mock://multi-port-secret"
      ]
      if checkId.len > 0: args.add(@["--id", checkId])
      for _ in 0 ..< 2:
        let result = runCanary(args)
        result.describe()
        check result.exitCode == ExitDown
        check "multi-port-secret" notin result.stdout
        check "multi-port-secret" notin result.stderr
        let payload = parseJson(result.stdout)
        check payload["results"].len == 2
        check payload["results"][1]["notifications"].len == 0
      let db = openDatabase(dbPath)
      defer: db.close()
      check db.all("SELECT id FROM canary_state").len == 2
      let prefix = if checkId.len == 0: "tcp_127.0.0.1_" else: checkId & ":"
      let failed = db.one(
        "SELECT status, fail_count FROM canary_state WHERE id = ?", prefix & $closedPort
      )
      require failed.isSome
      check failed.get()[0].fromDb(string) == "DOWN"
      check failed.get()[1].fromDb(int) == 2
      let healthy = db.one(
        "SELECT status, fail_count FROM canary_state WHERE id = ?", prefix & $openPort
      )
      require healthy.isSome
      check healthy.get()[0].fromDb(string) == "UP"
      check healthy.get()[1].fromDb(int) == 0
      let events = db.all("SELECT check_id FROM notification_outbox")
      require events.len == 1
      check events[0][0].fromDb(string) == prefix & $closedPort
