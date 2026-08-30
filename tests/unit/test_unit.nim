import nim_sqlite
import std/[httpcore, json, monotimes, net, options, os, strutils, unittest]
import ../../src/[common, input_contract, network_target, notifier,
                    process_runner]
import ../../src/canary/[app, cli, config]
import ../../src/checks/[dnscheck, httpcheck, icmpcheck, sslcheck]
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

suite "input parsing and validation":
  test "custom HTTP headers accept documented separators":
    let commaHeaders = parseCustomHeaders(
      "Authorization: Bearer test,User-Agent: Canary"
    )
    check commaHeaders["Authorization"] == "Bearer test"
    check commaHeaders["User-Agent"] == "Canary"

    let lineHeaders = parseCustomHeaders("Accept: application/json\nX-Test: yes")
    check lineHeaders["Accept"] == "application/json"
    check lineHeaders["X-Test"] == "yes"

  test "HTTP methods are parsed case-insensitively":
    check stringToHttpMethod("get") == HttpGet
    check stringToHttpMethod("POST") == HttpPost
    check stringToHttpMethod("patch") == HttpPatch
    expect CanaryConfigError:
      discard stringToHttpMethod("BREW")

  test "Pushover credentials follow the documented URL shape":
    let credentials = parsePushoverCredentials(
      "pushover://user%20key@api-token"
    )
    check credentials.userKey == "user key"
    check credentials.apiToken == "api-token"

  test "webhook payloads use provider-specific fields":
    let slack = webhookPayload(
      "https://hooks.slack.com/services/secret", "message"
    )
    check slack == %*{"text": "message"}
    let discord = webhookPayload(
      "https://discord.com/api/webhooks/secret", "message"
    )
    check discord == %*{"content": "message"}
    let generic = webhookPayload("https://example.test/hook", "message")
    check generic == %*{"text": "message", "content": "message"}

  test "notification retry delays are exponentially bounded with jitter":
    check retryDelaySeconds(1, 1) >= 1
    check retryDelaySeconds(1, 2) >= 2
    check retryDelaySeconds(1, 3) >= 4
    check retryDelaySeconds(1, 100) <= MaxRetryDelaySeconds

  test "common numeric ranges are validated":
    validateCommon(1, 1)
    validatePort(1)
    validatePort(65_535)
    expect ValueError:
      validateCommon(0, 1)
    expect ValueError:
      validateCommon(1, 0)
    expect ValueError:
      validatePort(0)
    expect ValueError:
      validatePort(65_536)
    validatePacketCount(1)
    validatePacketCount(MaxIcmpPacketCount)
    validateRecoveryThreshold(1)
    expect ValueError:
      validatePacketCount(0)
    expect ValueError:
      validatePacketCount(MaxIcmpPacketCount + 1)
    expect ValueError:
      validateRecoveryThreshold(0)

  test "hostnames and expected DNS addresses are validated":
    for hostname in [
      "localhost", "service.example.test", "127.0.0.1", "::1", "[::1]"
    ]:
      validateHostname(hostname)
    for hostname in ["", " bad.example", "bad host", "host;touch-pwned"]:
      expect CanaryConfigError:
        validateHostname(hostname)
    validateExpectedIp("192.0.2.1")
    validateExpectedIp("2001:db8::1")
    expect CanaryConfigError:
      validateExpectedIp("not-an-address")

  test "IPv6 host arguments and endpoint labels use canonical brackets":
    check normalizedNetworkHost("::1") == "::1"
    check normalizedNetworkHost("[2001:db8::1]") == "2001:db8::1"
    check formatHostPort("2001:db8::1", 443) == "[2001:db8::1]:443"
    check formatHostPort("[::1]", 9000) == "[::1]:9000"
    check formatHostPort("example.test", 443) == "example.test:443"

  test "TCP probe payloads are bounded":
    validateTcpProbe("PING\r\n", "PONG")
    expect CanaryConfigError:
      validateTcpProbe(repeat('x', MaxTcpProbeBytes + 1), "")
    expect CanaryConfigError:
      validateTcpProbe("", repeat('x', MaxTcpProbeBytes + 1))

  test "DNS types, resolver selection, and record expectations are validated":
    for recordType in ["A", "aaaa", "CNAME", "MX", "TXT"]:
      check normalizedDnsRecordType(recordType) == recordType.toUpperAscii()
    check splitDnsResolver("192.0.2.53") == ("192.0.2.53", 53)
    check splitDnsResolver("192.0.2.53:5353") == ("192.0.2.53", 5353)
    check splitDnsResolver("[2001:db8::53]:5353") ==
      ("2001:db8::53", 5353)
    validateDnsExpectedValues("A", ["192.0.2.10", "192.0.2.11"])
    validateDnsExpectedValues("AAAA", ["2001:db8::10"])
    validateDnsExpectedValues("CNAME", ["alias.example.test."])
    validateDnsExpectedValues("MX", ["10 mail.example.test."])
    validateDnsExpectedValues("TXT", ["canary=ready"])
    expect CanaryConfigError:
      discard normalizedDnsRecordType("SRV")
    expect CanaryConfigError:
      discard splitDnsResolver("resolver.example.test")
    expect CanaryConfigError:
      validateDnsExpectedValues("AAAA", ["192.0.2.10"])
    expect CanaryConfigError:
      validateDnsExpectedValues("CNAME", ["192.0.2.10"])
    expect CanaryConfigError:
      validateDnsExpectedValues("MX", ["mail.example.test"])

  test "malformed DNS packets are rejected by the decoder":
    expect CatchableError:
      discard parseDnsResponse("too short", 1234, "A")

  test "a bracketed IPv6 literal is a valid local AAAA target":
    let result = checkDns("[::1]", "AAAA", @["::1"], timeoutMs = 100)
    check result.isOk
    check result.target == "::1"

  test "SSL targets are normalized and validated":
    check hostnameFromSslTarget("example.test") == "example.test"
    check hostnameFromSslTarget("[::1]") == "::1"
    check hostnameFromSslTarget("https://[2001:db8::10]/health") ==
      "2001:db8::10"
    check hostnameFromSslTarget("https://user:secret@example.test/path?token=x") ==
      "example.test"
    expect CanaryConfigError:
      discard hostnameFromSslTarget("example.test;touch-pwned")

  test "malformed HTTP headers are rejected":
    validateHttpHeaders("Authorization: Bearer test,X-Trace: yes")
    expect CanaryConfigError:
      validateHttpHeaders("Authorization Bearer test")
    expect CanaryConfigError:
      validateHttpHeaders("Bad Header: value")

  test "HTTP input is validated before network access":
    validateHttp("http://127.0.0.1/health", 100, 1, 200, 0, "HEAD")
    expect ValueError:
      validateHttp("ftp://example.test", 100, 1, 200, 0, "GET")
    expect ValueError:
      validateHttp("http:///missing-host", 100, 1, 200, 0, "GET")
    expect ValueError:
      validateHttp("http://example.test", 100, 1, 99, 0, "GET")
    expect ValueError:
      validateHttp("http://example.test", 100, 1, 200, -1, "GET")
    expect ValueError:
      validateHttp("http://example.test", 100, 1, 200, 0, "BREW")

  test "HTTP status selectors and response assertions are validated":
    for selector in ["2xx", "200-204", "200,202,304-307"]:
      validateStatusRange(selector)
    check statusAccepted(202, 200, "2xx")
    check statusAccepted(304, 200, "200-204,304")
    check not statusAccepted(500, 200, "2xx,304")
    check expectedStatusDescription(200, "2xx") == "2xx"
    validateResponseHeader("X-Canary-State: ready")
    validateJsonField("service.status=ready")
    expect CanaryConfigError:
      validateStatusRange("600-700")
    expect CanaryConfigError:
      validateStatusRange("200-")
    expect CanaryConfigError:
      validateResponseHeader("Bad Header: ready")
    expect CanaryConfigError:
      validateJsonField("missing-separator")
    expect CanaryConfigError:
      validateHttp(
        "http://example.test", 100, 1, 200, 0, "GET",
        maxLatencyMs = -1
      )
    expect CanaryConfigError:
      validateHttp(
        "http://example.test", 100, 1, 200, 0, "GET",
        bodyRegex = "["
      )

suite "result formatting and check IDs":
  let sample = CheckResult(
    kind: "tcp",
    target: "127.0.0.1:80",
    isOk: true,
    message: "TCP OK",
    latencyMs: 7,
    details: "connected"
  )

  test "human-readable formatting returns the message":
    check formatResult(sample) == "TCP OK"

  test "JSON formatting has the public result fields":
    let payload = parseJson(formatResult(sample, true))
    check payload["check"].getStr() == "tcp"
    check payload["target"].getStr() == "127.0.0.1:80"
    check payload["status"].getStr() == "UP"
    check payload["latency_ms"].getInt() == 7
    check payload["message"].getStr() == "TCP OK"
    check payload["details"].getStr() == "connected"
    check not payload.hasKey("response_time_ms")

  test "HTTP JSON names the total measurement as response time":
    let httpResult = CheckResult(
      kind: "http",
      target: "https://example.test/health",
      isOk: true,
      message: "HTTP OK - Response time: 11ms",
      latencyMs: 11,
      details: "Status: 200 OK"
    )
    let payload = parseJson(formatResult(httpResult, true))
    check payload["response_time_ms"].getInt() == 11
    check payload["latency_ms"].getInt() == 11

  test "elapsed duration helper accepts a monotonic start time":
    let started = getMonoTime()
    sleep(10)
    check elapsedMilliseconds(started) >= 5

  test "check IDs are stable across check shapes":
    check makeCheckId("http", "https://example.test/health") ==
      "http_https://example.test/health"
    check makeCheckId("tcp", "127.0.0.1", 5432) ==
      "tcp_127.0.0.1_5432"
    check makeCheckId("dns", "example.test") == "dns_example.test"

  test "URL credentials and query values are absent from output and IDs":
    let secretUrl =
      "https://alice:password@example.test/health?token=secret&check=full#part"
    let safeUrl = "https://example.test/health"
    check publicTarget(secretUrl) == safeUrl
    check makeCheckId("http", secretUrl) == "http_" & safeUrl
    let secretResult = CheckResult(
      kind: "http",
      target: secretUrl,
      isOk: false,
      message: "HTTP ERROR - " & secretUrl,
      details: "Target: " & secretUrl
    )
    let output = formatResult(secretResult, true)
    check safeUrl in output
    for secret in ["alice", "password", "token", "secret", "check=full"]:
      check secret notin output

suite "typed application configuration":
  let commonOptions = CommonConfig(retries: 1, recoveryThreshold: 1)

  test "every check kind has a validated command-specific model":
    let configurations = @[
      CanaryConfig(
        kind: ckHttp,
        common: commonOptions,
        httpConfig: HttpConfig(
          url: "http://127.0.0.1/health",
          timeoutMs: 100,
          expectedStatus: 200,
          httpMethod: "GET"
        )
      ),
      CanaryConfig(
        kind: ckSsl,
        common: commonOptions,
        sslConfig: SslConfig(
          host: "localhost", minDays: 0, port: 443, timeoutMs: 100
        )
      ),
      CanaryConfig(
        kind: ckTcp,
        common: commonOptions,
        tcpConfig: TcpConfig(host: "127.0.0.1", port: 1, timeoutMs: 100)
      ),
      CanaryConfig(
        kind: ckUdp,
        common: commonOptions,
        udpConfig: UdpConfig(host: "127.0.0.1", port: 1, timeoutMs: 100)
      ),
      CanaryConfig(
        kind: ckDns,
        common: commonOptions,
        dnsConfig: DnsConfig(
          host: "localhost", recordType: "A", timeoutMs: 100
        )
      ),
      CanaryConfig(
        kind: ckIcmp,
        common: commonOptions,
        icmpConfig: IcmpConfig(host: "127.0.0.1", count: 1, timeoutMs: 100)
      )
    ]
    for checkConfig in configurations:
      checkConfig.validate()

  test "explicit IDs override generated state identities":
    let explicit = CanaryConfig(
      kind: ckHttp,
      common: CommonConfig(
        checkId: "production-api", retries: 1, recoveryThreshold: 1
      ),
      httpConfig: HttpConfig(
        url: "https://example.test/health?expected=one",
        timeoutMs: 100,
        expectedStatus: 204,
        httpMethod: "GET"
      )
    )
    check explicit.resolvedCheckId() == "production-api"
    expect CanaryConfigError:
      validateCheckId("bad\nid")

  test "bracketed and bare IPv6 hosts share generated state identities":
    let bare = CanaryConfig(
      kind: ckTcp,
      common: commonOptions,
      tcpConfig: TcpConfig(host: "::1", port: 443, timeoutMs: 100)
    )
    let bracketed = CanaryConfig(
      kind: ckTcp,
      common: commonOptions,
      tcpConfig: TcpConfig(host: "[::1]", port: 443, timeoutMs: 100)
    )
    check bare.resolvedCheckId() == bracketed.resolvedCheckId()

  test "app execution accepts config without a CLI parser":
    let server = newSocket()
    defer: server.close()
    server.setSockOpt(OptReuseAddr, true)
    server.bindAddr(Port(0), "127.0.0.1")
    server.listen()
    let port = int(server.getLocalAddr()[1])
    let checkConfig = CanaryConfig(
      kind: ckTcp,
      common: commonOptions,
      tcpConfig: TcpConfig(
        host: "127.0.0.1", port: port, timeoutMs: 500
      )
    )
    let checkResult = executeCheck(checkConfig)
    check checkResult.isOk
    check checkResult.kind == "tcp"

suite "layered CLI configuration":
  test "CLI overrides environment, which overrides TOML and built-ins":
    const EnvironmentKeys = [
      "CANARY_RETRIES", "CANARY_NOTIFY", "CANARY_HEADERS", "CANARY_STATUS",
      "CANARY_TIMEOUT", "CANARY_JSON", "CANARY_RECOVERYTHRESHOLD"
    ]
    var savedEnvironment: seq[tuple[key: string, present: bool, value: string]]
    for key in EnvironmentKeys:
      savedEnvironment.add((key, existsEnv(key), getEnv(key)))
      delEnv(key)
    defer:
      for saved in savedEnvironment:
        if saved.present:
          putEnv(saved.key, saved.value)
        else:
          delEnv(saved.key)

    let testDir = getTempDir() / (
      "canary-unit-config-" & $getCurrentProcessId()
    )
    createDir(testDir)
    let configPath = testDir / "canary.toml"
    defer:
      removeFile(configPath)
      removeDir(testDir)
    writeFile(configPath,
      "retries = 2\n\n" &
      "recoveryThreshold = 2\n\n" &
      "[http]\n" &
      "status = 201\n" &
      "timeout = 1200\n")

    putEnv("CANARY_RETRIES", "3")
    putEnv("CANARY_RECOVERYTHRESHOLD", "3")
    putEnv("CANARY_NOTIFY", "https://env-secret.invalid/hook")
    putEnv("CANARY_HEADERS", "Authorization: Bearer env-secret")
    let parsed = loadCliConfig(@[
      "http", "https://example.test/health", "--config", configPath,
      "--retries", "4", "--recoveryThreshold", "4", "--timeout", "1300"
    ]).toCanaryConfig()

    check parsed.kind == ckHttp
    check parsed.common.retries == 4
    check parsed.common.recoveryThreshold == 4
    check parsed.common.notifyUrls == @["https://env-secret.invalid/hook"]
    check parsed.httpConfig.headers == "Authorization: Bearer env-secret"
    check parsed.httpConfig.expectedStatus == 201
    check parsed.httpConfig.timeoutMs == 1300
    check parsed.httpConfig.maxRedirects == 5

  test "HTTP assertion options map to the parser-independent model":
    let parsed = loadCliConfig(@[
      "http", "https://example.test/health",
      "--statusRange", "2xx,304", "--maxLatency", "250",
      "--responseHeader", "X-Health: ready", "--regex", "ready|ok",
      "--jsonField", "service.status=ready"
    ]).toCanaryConfig()
    check parsed.httpConfig.statusRange == "2xx,304"
    check parsed.httpConfig.maxLatencyMs == 250
    check parsed.httpConfig.responseHeader == "X-Health: ready"
    check parsed.httpConfig.bodyRegex == "ready|ok"
    check parsed.httpConfig.jsonField == "service.status=ready"

  test "TCP request and response options map to the typed model and TOML":
    let fromCli = loadCliConfig(@[
      "tcp", "127.0.0.1", "--port", "2525",
      "--request", "EHLO canary\r\n", "--expected", "250 ready"
    ]).toCanaryConfig()
    check fromCli.tcpConfig.request == "EHLO canary\r\n"
    check fromCli.tcpConfig.expected == "250 ready"

    let testDir = newTestDir("tcp-config")
    defer: removeDir(testDir)
    let configPath = testDir / "canary.toml"
    writeFile(configPath,
      "[tcp]\n" &
      "port = 2525\n" &
      "request = \"PING\\r\\n\"\n" &
      "expected = \"PONG\"\n")
    let fromToml = loadCliConfig(@[
      "tcp", "127.0.0.1", "--config", configPath
    ]).toCanaryConfig()
    check fromToml.tcpConfig.request == "PING\r\n"
    check fromToml.tcpConfig.expected == "PONG"

  test "DNS options map repeatable expectations to the typed model":
    let parsed = loadCliConfig(@[
      "dns", "fixture.test", "--type", "MX",
      "--expected", "10 mail1.fixture.test",
      "--expected", "20 mail2.fixture.test",
      "--resolver", "127.0.0.1:5353", "--timeout", "750"
    ]).toCanaryConfig()
    check parsed.dnsConfig.recordType == "MX"
    check parsed.dnsConfig.expectedValues == @[
      "10 mail1.fixture.test", "20 mail2.fixture.test"
    ]
    check parsed.dnsConfig.resolver == "127.0.0.1:5353"
    check parsed.dnsConfig.timeoutMs == 750

  test "DNS arrays and defaults load from TOML":
    let testDir = newTestDir("dns-config")
    defer: removeDir(testDir)
    let configPath = testDir / "canary.toml"
    writeFile(configPath,
      "[dns]\n" &
      "type = \"TXT\"\n" &
      "expected = [\"canary=ready\", \"region=eu\"]\n" &
      "resolver = \"127.0.0.1:5353\"\n" &
      "timeout = 900\n")
    let parsed = loadCliConfig(@[
      "dns", "fixture.test", "--config", configPath
    ]).toCanaryConfig()
    check parsed.dnsConfig.recordType == "TXT"
    check parsed.dnsConfig.expectedValues == @["canary=ready", "region=eu"]
    check parsed.dnsConfig.resolver == "127.0.0.1:5353"
    check parsed.dnsConfig.timeoutMs == 900

  test "notification targets are lists in TOML and repeatable on the CLI":
    let testDir = newTestDir("notification-config")
    defer: removeDir(testDir)
    let configPath = testDir / "canary.toml"
    writeFile(configPath,
      "notify = [\"https://config-one.invalid/hook\", " &
      "\"https://config-two.invalid/hook\"]\n")

    let fromToml = loadCliConfig(@[
      "dns", "localhost", "--config", configPath
    ]).toCanaryConfig()
    check fromToml.common.notifyUrls == @[
      "https://config-one.invalid/hook",
      "https://config-two.invalid/hook"
    ]

    let fromCli = loadCliConfig(@[
      "dns", "localhost", "--config", configPath,
      "--notify", "https://cli-one.invalid/hook",
      "--notify", "https://cli-two.invalid/hook"
    ]).toCanaryConfig()
    check fromCli.common.notifyUrls == @[
      "https://cli-one.invalid/hook",
      "https://cli-two.invalid/hook"
    ]

suite "argument-safe system checks":
  test "the default process runner treats shell syntax as a literal argument":
    let shellSyntax = "value; echo should-not-run | touch nowhere"
    let execution = runProcess(
      "/usr/bin/printf", @["%s", shellSyntax], timeoutMs = 1000
    )
    check execution.exitCode == 0
    check not execution.timedOut
    check execution.output == shellSyntax

  test "the default process runner enforces its timeout":
    let execution = runProcess(
      "/usr/bin/sleep", @["1"], timeoutMs = 25
    )
    check execution.timedOut
    check execution.exitCode != 0

  test "ICMP passes the host as one argv element without a shell":
    var called = false
    let runner: ProcessRunner = proc(command: string, args: seq[string],
                                     input: string,
                                     timeoutMs: int): ProcessResult =
      called = true
      check command == "ping"
      check args == @["-c", "3", "-W", "2", "127.0.0.1"]
      check input.len == 0
      check timeoutMs == 2500
      ProcessResult(exitCode: 0)
    let result = checkIcmp("127.0.0.1", 3, 2500, runner)
    check called
    check result.isOk

  test "ICMP selects IPv6 explicitly and removes address brackets":
    let runner: ProcessRunner = proc(command: string, args: seq[string],
                                     input: string,
                                     timeoutMs: int): ProcessResult =
      check command == "ping"
      check args == @["-6", "-c", "1", "-W", "1", "::1"]
      check input.len == 0
      check timeoutMs == 1000
      ProcessResult(exitCode: 0)
    let result = checkIcmp("[::1]", 1, 1000, runner)
    check result.isOk

  test "ICMP rejects command fragments before starting a process":
    var called = false
    let runner: ProcessRunner = proc(command: string, args: seq[string],
                                     input: string,
                                     timeoutMs: int): ProcessResult =
      called = true
      ProcessResult(exitCode: 0)
    expect CanaryConfigError:
      discard checkIcmp("127.0.0.1;touch-pwned", 1, 100, runner)
    check not called

  test "SSL uses two direct OpenSSL invocations instead of a pipeline":
    const Certificate = "-----BEGIN CERTIFICATE-----\nfixture\n" &
      "-----END CERTIFICATE-----\n"
    var calls: seq[tuple[command: string, args: seq[string],
                         input: string]] = @[]
    let runner: ProcessRunner = proc(command: string, args: seq[string],
                                     input: string,
                                     timeoutMs: int): ProcessResult =
      calls.add((command, args, input))
      sleep(20)
      if args[0] == "s_client":
        ProcessResult(output: Certificate, exitCode: 0)
      else:
        ProcessResult(
          output: "notAfter=Aug 29 12:00:00 2099 GMT\n", exitCode: 0
        )
    let result = checkSsl("https://example.test/private?token=secret", 14,
                          8443, 1000, runner)
    check result.isOk
    check calls.len == 2
    check calls[0].command == "openssl"
    check calls[0].args == @[
      "s_client", "-connect", "example.test:8443", "-servername",
      "example.test", "-showcerts"
    ]
    check calls[1].command == "openssl"
    check calls[1].args == @["x509", "-noout", "-enddate"]
    check calls[1].input == Certificate
    check result.latencyMs >= 30
    check "secret" notin formatResult(result, true)

  test "SSL formats an IPv6 connection target with brackets":
    const Certificate = "-----BEGIN CERTIFICATE-----\nfixture\n" &
      "-----END CERTIFICATE-----\n"
    var handshakeArgs: seq[string]
    let runner: ProcessRunner = proc(command: string, args: seq[string],
                                     input: string,
                                     timeoutMs: int): ProcessResult =
      if args[0] == "s_client":
        handshakeArgs = args
        ProcessResult(output: Certificate, exitCode: 0)
      else:
        ProcessResult(
          output: "notAfter=Aug 29 12:00:00 2099 GMT\n", exitCode: 0
        )
    let result = checkSsl("https://[2001:db8::10]/health", 14, 8443,
                          1000, runner)
    check result.isOk
    check handshakeArgs == @[
      "s_client", "-connect", "[2001:db8::10]:8443", "-servername",
      "2001:db8::10", "-showcerts"
    ]

  test "a failed TLS handshake is a completed DOWN check":
    let runner: ProcessRunner = proc(command: string, args: seq[string],
                                     input: string,
                                     timeoutMs: int): ProcessResult =
      ProcessResult(output: "connection refused", exitCode: 1)
    let result = checkSsl("example.test", runner = runner)
    check not result.isOk
    check result.details == "TLS handshake failed"

suite "state transition table":
  test "UNKNOWN advances through PENDING_DOWN, DOWN, and recovery":
    let testDir = newTestDir("state-table")
    defer: removeDir(testDir)
    let dbPath = testDir / "state.db"
    var notifications: seq[string] = @[]
    let sender: NotificationSender = proc(urls: string,
                                          message: string): bool =
      check urls == "mock://alerts"
      notifications.add(message)
      true

    handleStateAndNotify(
      "tcp_service_80", false, "mock://alerts", dbPath, 3, sender
    )
    check readState(dbPath, "tcp_service_80") == ("PENDING_DOWN", 1)
    check notifications.len == 0

    handleStateAndNotify(
      "tcp_service_80", false, "mock://alerts", dbPath, 3, sender
    )
    check readState(dbPath, "tcp_service_80") == ("PENDING_DOWN", 2)
    check notifications.len == 0

    handleStateAndNotify(
      "tcp_service_80", false, "mock://alerts", dbPath, 3, sender
    )
    check readState(dbPath, "tcp_service_80") == ("DOWN", 3)
    check notifications.len == 1
    check "[ALERT]" in notifications[0]

    handleStateAndNotify(
      "tcp_service_80", false, "mock://alerts", dbPath, 3, sender
    )
    check readState(dbPath, "tcp_service_80") == ("DOWN", 4)
    check notifications.len == 1

    handleStateAndNotify(
      "tcp_service_80", true, "mock://alerts", dbPath, 3, sender
    )
    check readState(dbPath, "tcp_service_80") == ("UP", 0)
    check notifications.len == 2
    check "[RECOVERY]" in notifications[1]

  test "UP enters PENDING_DOWN and resets after success":
    let testDir = newTestDir("state-up")
    defer: removeDir(testDir)
    let dbPath = testDir / "state.db"
    var notificationCount = 0
    let sender: NotificationSender = proc(urls: string,
                                          message: string): bool =
      notificationCount.inc()
      true

    handleStateAndNotify("http_service", true, "mock://alerts", dbPath, 2,
                         sender)
    check readState(dbPath, "http_service") == ("UP", 0)

    handleStateAndNotify("http_service", false, "mock://alerts", dbPath, 2,
                         sender)
    check readState(dbPath, "http_service") == ("PENDING_DOWN", 1)
    check notificationCount == 0

    handleStateAndNotify("http_service", true, "mock://alerts", dbPath, 2,
                         sender)
    check readState(dbPath, "http_service") == ("UP", 0)
    check notificationCount == 0

  test "an initial failure reaches DOWN at threshold one":
    let testDir = newTestDir("state-initial-down")
    defer: removeDir(testDir)
    let dbPath = testDir / "state.db"
    var notificationCount = 0
    let sender: NotificationSender = proc(urls: string,
                                          message: string): bool =
      notificationCount.inc()
      true

    handleStateAndNotify("dns_service", false, "mock://alerts", dbPath, 1,
                         sender)
    check readState(dbPath, "dns_service") == ("DOWN", 1)
    check notificationCount == 1

  test "DOWN requires consecutive successes before recovery":
    let testDir = newTestDir("state-recovery-threshold")
    defer: removeDir(testDir)
    let dbPath = testDir / "state.db"
    var notifications: seq[string] = @[]
    let sender: NotificationSender = proc(url: string,
                                          message: string): bool =
      notifications.add(message)
      true

    discard processStateAndNotify(
      "dns_recovery", false, "mock://alerts", dbPath, 1, 2,
      sender = sender
    )
    check readState(dbPath, "dns_recovery") == ("DOWN", 1)
    check notifications.len == 1

    discard processStateAndNotify(
      "dns_recovery", true, "mock://alerts", dbPath, 1, 2,
      sender = sender
    )
    check readState(dbPath, "dns_recovery") == ("DOWN", 0)
    check notifications.len == 1

    discard processStateAndNotify(
      "dns_recovery", true, "mock://alerts", dbPath, 1, 2,
      latencyMs = 9, cause = "healthy", sender = sender
    )
    check readState(dbPath, "dns_recovery") == ("UP", 0)
    check notifications.len == 2
    for field in [
      "name=dns_recovery", "transition=UP", "attempt=2",
      "latency_ms=9", "cause=healthy", "timestamp="
    ]:
      check field in notifications[1]

  test "failed deliveries remain in the durable outbox for a later run":
    let testDir = newTestDir("notification-outbox")
    defer: removeDir(testDir)
    let dbPath = testDir / "state.db"
    var attempts = 0
    let failingSender: NotificationSender = proc(url: string,
                                                 message: string): bool =
      attempts.inc()
      false

    let firstResults = processStateAndNotify(
      "tcp_outbox", false, "mock://secret", dbPath, 1, 1,
      latencyMs = 12, cause = "connection refused", sender = failingSender
    )
    check firstResults.len == 1
    check firstResults[0].status == "retry"
    check firstResults[0].target == "<invalid notification URL>"
    check attempts == 1

    block:
      let db = openDatabase(dbPath)
      defer: db.close()
      let row = db.one(
        "SELECT status, attempt_count, target, message " &
        "FROM notification_outbox"
      )
      require row.isSome
      check row.get()[0].fromDb(string) == "pending"
      check row.get()[1].fromDb(int) == 1
      check row.get()[2].fromDb(string) == "mock://secret"
      check "transition=DOWN" in row.get()[3].fromDb(string)
      db.exec("UPDATE notification_outbox SET next_attempt = 0")

    let successfulSender: NotificationSender = proc(url: string,
                                                    message: string): bool =
      attempts.inc()
      true
    let retryResults = processStateAndNotify(
      "tcp_outbox", false, "", dbPath, 1, 1, sender = successfulSender
    )
    check retryResults.len == 1
    check retryResults[0].status == "sent"
    check retryResults[0].attempt == 2
    check attempts == 2

    let db = openDatabase(dbPath)
    defer: db.close()
    let sent = db.one(
      "SELECT status, sent_at FROM notification_outbox"
    )
    require sent.isSome
    check sent.get()[0].fromDb(string) == "sent"
    check sent.get()[1].fromDb(int64) > 0

  test "legacy state databases are migrated in place":
    let testDir = newTestDir("state-migration")
    defer: removeDir(testDir)
    let dbPath = testDir / "state.db"
    block:
      let db = openDatabase(dbPath)
      defer: db.close()
      db.execScript("""
        CREATE TABLE canary_state (
          id TEXT PRIMARY KEY,
          status TEXT NOT NULL,
          fail_count INTEGER NOT NULL DEFAULT 0,
          last_check INTEGER NOT NULL DEFAULT 0
        );
        INSERT INTO canary_state(id, status, fail_count, last_check)
          VALUES('legacy', 'DOWN', 3, 0);
      """)

    discard processStateAndNotify(
      "legacy", true, "", dbPath, 1, 2
    )
    let db = openDatabase(dbPath)
    defer: db.close()
    let row = db.one(
      "SELECT status, success_count FROM canary_state WHERE id = 'legacy'"
    )
    require row.isSome
    check row.get()[0].fromDb(string) == "DOWN"
    check row.get()[1].fromDb(int) == 1

  test "state transition rolls back when its outbox insert fails":
    let testDir = newTestDir("state-outbox-atomicity")
    defer: removeDir(testDir)
    let dbPath = testDir / "state.db"
    handleStateAndNotify("atomic", true, "", dbPath)
    block:
      let db = openDatabase(dbPath)
      defer: db.close()
      db.execScript("""
        CREATE TRIGGER reject_notification
        BEFORE INSERT ON notification_outbox
        BEGIN
          SELECT RAISE(ABORT, 'fixture rejection');
        END;
      """)

    discard processStateAndNotify(
      "atomic", false, "mock://alerts", dbPath
    )
    check readState(dbPath, "atomic") == ("UP", 0)
    let db = openDatabase(dbPath)
    defer: db.close()
    let count = db.one("SELECT COUNT(*) FROM notification_outbox")
    require count.isSome
    check count.get()[0].fromDb(int) == 0
