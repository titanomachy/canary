import nim_sqlite
import std/[json, net, options, os, osproc, streams, strtabs, strutils, times,
            unittest]
import ../../src/canary_contract

type CliResult = object
  exitCode: int
  stdout: string
  stderr: string

const
  ProjectRoot = currentSourcePath().parentDir.parentDir.parentDir
  CanaryBinary = ProjectRoot / "build" / "canary"

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
    for command in ["http", "ssl", "tcp", "udp", "dns", "icmp"]:
      check result.stdout.contains(command)
    check result.stderr.len == 0

  test "command help describes command options":
    let result = runCanary(["http", "--help"])
    result.describe()
    check result.exitCode == 0
    check result.stdout.contains("--timeout")
    check result.stdout.contains("--status")
    check result.stdout.contains("--json")
    check result.stdout.contains("--id")
    check result.stdout.contains("--config")
    check result.stdout.contains("--recoveryThreshold")
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
      @["http", "http://127.0.0.1", "--status", "99"],
      @["http", "http://127.0.0.1", "--methodStr", "BREW"],
      @["tcp", "bad host", "--port", "80"],
      @["dns", "example.test", "--expected", "not-an-ip"],
      @["icmp", "127.0.0.1", "--count", "0"],
      @["icmp", "127.0.0.1", "--count", "101"]
    ]:
      let result = runCanary(args)
      result.describe()
      check result.exitCode == ExitConfigError
      check result.stdout.len == 0
      check result.stderr.startsWith("Configuration error:")

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
