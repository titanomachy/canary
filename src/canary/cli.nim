import confutils
import confutils/toml/defs
import std/[os, strutils]
import toml_serialization
import ../[canary_contract, common, notifier]
import app, config

type
  CanaryCommand* {.pure.} = enum
    http = "Check HTTP/HTTPS service availability and response"
    ssl = "Check days remaining until an SSL/TLS certificate expires"
    tcp = "Check a TCP connection or protocol response"
    udp = "Send a UDP datagram and require a response"
    dns = "Query A, AAAA, CNAME, MX, or TXT DNS records"
    icmp = "Check ICMP ping reachability"
    command = "Run a local executable and assert its result"

  CommonCliConfig* = object
    checkId* {.
      name: "id"
      defaultValue: ""
      desc: "Explicit state identity for this check" .}: string
    notifyUrls* {.
      name: "notify"
      abbr: "n"
      defaultValue: @[]
      envVarValueSep: "\n"
      desc: "Notification URL (repeat for multiple endpoints)" .}: seq[string]
    dbPath* {.
      name: "db"
      abbr: "d"
      defaultValue: ""
      desc: "Path to the SQLite state database" .}: string
    retries* {.
      abbr: "r"
      defaultValue: 1
      desc: "Consecutive failures required before a DOWN alert" .}: int
    recoveryThreshold* {.
      name: "recoveryThreshold"
      defaultValue: 1
      desc: "Consecutive successes required before a recovery alert" .}: int
    cooldownSeconds* {.
      name: "cooldown"
      defaultValue: 0
      desc: "Minimum seconds between DOWN-class notifications (0 disables)" .}: int
    repeatIntervalSeconds* {.
      name: "repeatInterval"
      defaultValue: 0
      desc: "Repeat a DOWN alert after this many seconds (0 disables)" .}: int
    silenceUntil* {.
      name: "silenceUntil"
      defaultValue: ""
      desc: "Suppress notifications until a UTC timestamp, or use clear" .}: string
    asJson* {.
      name: "json"
      abbr: "j"
      defaultValue: false
      desc: "Output the result as one JSON object" .}: bool

  HttpCliConfig* = object
    url* {.
      argument
      name: "url"
      defaultValue: ""
      desc: "Target URL to test" .}: string
    timeoutMs* {.
      name: "timeout"
      abbr: "t"
      defaultValue: 5000
      desc: "Timeout in milliseconds" .}: int
    expectedStatus* {.
      name: "status"
      abbr: "s"
      defaultValue: 200
      desc: "Expected HTTP status code" .}: int
    search* {.
      defaultValue: ""
      desc: "Required string in the response body" .}: string
    headers* {.
      defaultValue: ""
      desc: "Custom request headers" .}: string
    methodStr* {.
      name: "methodStr"
      abbr: "m"
      defaultValue: "GET"
      desc: "HTTP method" .}: string
    body* {.
      abbr: "b"
      defaultValue: ""
      desc: "Request body for methods that accept one" .}: string
    maxRedirects* {.
      name: "maxRedirects"
      defaultValue: 5
      desc: "Maximum number of redirects to follow" .}: int
    statusRange* {.
      name: "statusRange"
      defaultValue: ""
      desc: "Accepted statuses, e.g. 2xx,200-204,304" .}: string
    maxLatencyMs* {.
      name: "maxLatency"
      defaultValue: 0
      desc: "Maximum total HTTP response time in milliseconds (0 disables)" .}: int
    responseHeader* {.
      name: "responseHeader"
      defaultValue: ""
      desc: "Required response header as Name or Name: value" .}: string
    bodyRegex* {.
      name: "regex"
      defaultValue: ""
      desc: "Regular expression required in the response body" .}: string
    jsonField* {.
      name: "jsonField"
      defaultValue: ""
      desc: "Required JSON scalar as dotted.path=value" .}: string
    verboseTimings* {.
      name: "verbose"
      abbr: "v"
      defaultValue: false
      desc: "Show DNS, TCP, TLS, TTFB, transfer, and total timings" .}: bool

  SslCliConfig* = object
    host* {.
      argument
      name: "host"
      defaultValue: ""
      desc: "Hostname or URL to inspect" .}: string
    minDays* {.
      name: "minDays"
      abbr: "m"
      defaultValue: 14
      desc: "Minimum acceptable remaining validity in days" .}: int
    port* {.
      abbr: "p"
      defaultValue: 443
      desc: "SSL/TLS port" .}: int
    timeoutMs* {.
      name: "timeout"
      abbr: "t"
      defaultValue: 5000
      desc: "Timeout in milliseconds" .}: int

  TcpCliConfig* = object
    host* {.
      argument
      name: "host"
      defaultValue: ""
      desc: "Target hostname or IP address" .}: string
    port* {.
      abbr: "p"
      desc: "TCP port number" .}: int
    request* {.
      defaultValue: ""
      desc: "Optional bytes to send after connecting" .}: string
    expected* {.
      defaultValue: ""
      desc: "Required response or server banner substring" .}: string
    timeoutMs* {.
      name: "timeout"
      abbr: "t"
      defaultValue: 5000
      desc: "Timeout in milliseconds" .}: int

  UdpCliConfig* = object
    host* {.
      argument
      name: "host"
      defaultValue: ""
      desc: "Target hostname or IP address" .}: string
    port* {.
      abbr: "p"
      desc: "UDP port number" .}: int
    payload* {.
      defaultValue: "ping"
      desc: "Payload string to transmit" .}: string
    expected* {.
      defaultValue: ""
      desc: "Expected response substring" .}: string
    timeoutMs* {.
      name: "timeout"
      abbr: "t"
      defaultValue: 5000
      desc: "Timeout in milliseconds" .}: int

  DnsCliConfig* = object
    host* {.
      argument
      name: "host"
      defaultValue: ""
      desc: "Domain name to resolve" .}: string
    recordType* {.
      name: "type"
      defaultValue: "A"
      desc: "DNS record type: A, AAAA, CNAME, MX, or TXT" .}: string
    expectedValues* {.
      name: "expected"
      defaultValue: @[]
      envVarValueSep: "\n"
      desc: "Required answer value (repeat for multiple values)" .}: seq[string]
    resolver* {.
      defaultValue: ""
      desc: "DNS resolver IP with optional port (default: system resolver)" .}: string
    timeoutMs* {.
      name: "timeout"
      abbr: "t"
      defaultValue: 5000
      desc: "Timeout in milliseconds" .}: int

  IcmpCliConfig* = object
    host* {.
      argument
      name: "host"
      defaultValue: ""
      desc: "Target hostname or IP address" .}: string
    count* {.
      defaultValue: 1
      desc: "Number of ICMP packets to send" .}: int
    timeoutMs* {.
      name: "timeout"
      abbr: "t"
      defaultValue: 5000
      desc: "Maximum execution time in milliseconds" .}: int

  CommandCliConfig* = object
    executable* {.
      argument
      name: "executable"
      defaultValue: ""
      desc: "Local executable name or path" .}: string
    args* {.
      name: "arg"
      defaultValue: @[]
      envVarValueSep: "\n"
      desc: "Argument passed verbatim (repeat for multiple arguments)" .}: seq[string]
    timeoutMs* {.
      name: "timeout"
      abbr: "t"
      defaultValue: 5000
      desc: "Maximum execution time in milliseconds" .}: int
    expectedExitCode* {.
      name: "exitCode"
      defaultValue: 0
      desc: "Expected process exit code (0 through 255)" .}: int
    outputMatch* {.
      name: "outputMatch"
      defaultValue: ""
      desc: "Required literal substring in combined stdout and stderr" .}: string

  CliConfig* = object
    configFile* {.
      name: "config"
      defaultValue: ""
      desc: "TOML defaults file (default: ~/.config/canary/config.toml)" .}: string
    common* {.flatten.}: CommonCliConfig
    case command* {.command.}: CanaryCommand
    of CanaryCommand.http:
      httpOptions* {.flatten.}: HttpCliConfig
    of CanaryCommand.ssl:
      sslOptions* {.flatten.}: SslCliConfig
    of CanaryCommand.tcp:
      tcpOptions* {.flatten.}: TcpCliConfig
    of CanaryCommand.udp:
      udpOptions* {.flatten.}: UdpCliConfig
    of CanaryCommand.dns:
      dnsOptions* {.flatten.}: DnsCliConfig
    of CanaryCommand.icmp:
      icmpOptions* {.flatten.}: IcmpCliConfig
    of CanaryCommand.command:
      commandOptions* {.flatten.}: CommandCliConfig

const
  Commands = ["http", "ssl", "tcp", "udp", "dns", "icmp", "command"]
  ValueOptions = [
    "--config", "--id", "--notify", "--db", "--retries", "-n", "-d",
    "-r", "--recoveryThreshold", "--cooldown", "--repeatInterval",
    "--silenceUntil", "--timeout", "--status", "--search", "--headers", "--methodStr",
    "--body", "--maxRedirects", "--statusRange", "--maxLatency",
    "--responseHeader", "--regex", "--jsonField", "--minDays", "--port",
    "--request", "--payload", "--expected", "--type", "--resolver",
    "--count", "--arg", "--exitCode", "--outputMatch", "-t", "-s", "-m",
    "-b", "-p"
  ]
  BooleanOptions = [
    "--json", "-j", "--verbose", "-v", "--timing", "--help", "--version"
  ]
  NumericOptions = [
    "--retries", "--recoveryThreshold", "--cooldown", "--repeatInterval",
    "--timeout", "--status", "--maxRedirects", "--maxLatency", "--minDays",
    "--port", "--count", "--exitCode", "-r", "-t", "-s", "-m", "-p"
  ]

proc normalizedArguments(arguments: seq[string]): seq[string] =
  ## Confutils accepts `--option=value`; Canary's established contract also
  ## accepts `--option value`. Normalize only documented valued options and
  ## leave positionals and boolean flags untouched.
  var index = 0
  while index < arguments.len:
    let argument =
      if arguments[index] == "--timing": "--verbose"
      else: arguments[index]
    if argument in ValueOptions and index + 1 < arguments.len:
      result.add(argument & "=" & arguments[index + 1])
      inc index, 2
    else:
      result.add(argument)
      inc index

proc optionKey(argument: string): string =
  argument.split('=', maxsplit = 1)[0]

proc hasOption(arguments: openArray[string], names: openArray[string]): bool =
  for argument in arguments:
    if argument.optionKey() in names:
      return true

proc parserDiagnostic(arguments: seq[string]): string =
  ## Confutils intentionally omits exception text when `quitOnFailure=false`.
  ## Build a concise, redacted contract diagnostic without echoing option
  ## values, which may contain notification or authorization secrets.
  for argument in arguments:
    if argument.len > 0 and argument[0] == '-':
      let key = argument.optionKey()
      if key notin ValueOptions and key notin BooleanOptions:
        return "Configuration error: unknown option '" & key & "'"

  if arguments.len > 0 and arguments[0] in ["tcp", "udp"] and
      not arguments.hasOption(["--port", "-p"]):
    return "Configuration error: required option 'port' was not specified"

  if arguments.hasOption(["--config"]):
    return "Configuration error: failed to load the requested configuration file"

  for argument in arguments:
    let key = argument.optionKey()
    if key in NumericOptions:
      return "Configuration error: invalid value for option '" & key.strip(
        leading = true, trailing = false, chars = {'-'}
      ) & "'"

  "Configuration error: invalid command-line or configuration input"

proc defaultConfigPath*(): string =
  ## The default is read when present and ignored when absent. No directory or
  ## file is created just by resolving configuration.
  let xdgConfigHome = getEnv("XDG_CONFIG_HOME")
  let configHome =
    if xdgConfigHome.len > 0: xdgConfigHome
    else: getHomeDir() / ".config"
  configHome / "canary" / "config.toml"

template tomlSource(Configuration: type): untyped =
  proc (input: Configuration, sources: ref SecondarySources) {.
      raises: [ConfigurationError].} =
    let explicitPath = input.configFile.len > 0
    let configPath =
      if explicitPath: expandTilde(input.configFile)
      else: defaultConfigPath()
    if explicitPath or fileExists(configPath):
      sources.addConfigFile(Toml, InputFile(configPath))

proc loadCliConfig*(arguments: seq[string]): CliConfig =
  ## Load exactly one command using the documented precedence:
  ## defaults < TOML < CANARY_* environment variables < command-line options.
  CliConfig.load(
    cmdLine = normalizedArguments(arguments),
    version = CanaryVersion,
    copyrightBanner = "Canary " & CanaryVersion,
    quitOnFailure = false,
    secondarySources = tomlSource(CliConfig),
    envVarsPrefix = "CANARY"
  )

proc commonConfig(input: CommonCliConfig): CommonConfig =
  CommonConfig(
    checkId: input.checkId,
    notifyUrls: input.notifyUrls,
    dbPath: input.dbPath,
    retries: input.retries,
    recoveryThreshold: input.recoveryThreshold,
    cooldownSeconds: input.cooldownSeconds,
    repeatIntervalSeconds: input.repeatIntervalSeconds,
    silenceUntil: input.silenceUntil,
    asJson: input.asJson
  )

proc requireTarget(target, missingMessage: string): string =
  if target.len == 0:
    raise newException(CanaryConfigError, missingMessage)
  target

proc toCanaryConfig*(input: CliConfig): CanaryConfig =
  let common = commonConfig(input.common)
  case input.command
  of CanaryCommand.http:
    let http = input.httpOptions
    CanaryConfig(
      kind: ckHttp,
      common: common,
      httpConfig: HttpConfig(
        url: requireTarget(http.url, "no URL specified"),
        timeoutMs: http.timeoutMs,
        expectedStatus: http.expectedStatus,
        search: http.search,
        headers: http.headers,
        httpMethod: http.methodStr,
        body: http.body,
        maxRedirects: http.maxRedirects,
        statusRange: http.statusRange,
        maxLatencyMs: http.maxLatencyMs,
        responseHeader: http.responseHeader,
        bodyRegex: http.bodyRegex,
        jsonField: http.jsonField,
        verboseTimings: http.verboseTimings
      )
    )
  of CanaryCommand.ssl:
    let ssl = input.sslOptions
    CanaryConfig(
      kind: ckSsl,
      common: common,
      sslConfig: SslConfig(
        host: requireTarget(ssl.host, "no hostname specified"),
        minDays: ssl.minDays,
        port: ssl.port,
        timeoutMs: ssl.timeoutMs
      )
    )
  of CanaryCommand.tcp:
    let tcp = input.tcpOptions
    CanaryConfig(
      kind: ckTcp,
      common: common,
      tcpConfig: TcpConfig(
        host: requireTarget(tcp.host, "no host specified"),
        port: tcp.port,
        request: tcp.request,
        expected: tcp.expected,
        timeoutMs: tcp.timeoutMs
      )
    )
  of CanaryCommand.udp:
    let udp = input.udpOptions
    CanaryConfig(
      kind: ckUdp,
      common: common,
      udpConfig: UdpConfig(
        host: requireTarget(udp.host, "no host specified"),
        port: udp.port,
        payload: udp.payload,
        expected: udp.expected,
        timeoutMs: udp.timeoutMs
      )
    )
  of CanaryCommand.dns:
    let dns = input.dnsOptions
    CanaryConfig(
      kind: ckDns,
      common: common,
      dnsConfig: DnsConfig(
        host: requireTarget(dns.host, "no hostname specified"),
        recordType: dns.recordType,
        expectedValues: dns.expectedValues,
        resolver: dns.resolver,
        timeoutMs: dns.timeoutMs
      )
    )
  of CanaryCommand.icmp:
    let icmp = input.icmpOptions
    CanaryConfig(
      kind: ckIcmp,
      common: common,
      icmpConfig: IcmpConfig(
        host: requireTarget(icmp.host, "no host specified"),
        count: icmp.count,
        timeoutMs: icmp.timeoutMs
      )
    )
  of CanaryCommand.command:
    let command = input.commandOptions
    CanaryConfig(
      kind: ckCommand,
      common: common,
      commandConfig: CommandConfig(
        executable: requireTarget(
          command.executable, "no command executable specified"
        ),
        args: command.args,
        timeoutMs: command.timeoutMs,
        expectedExitCode: command.expectedExitCode,
        outputMatch: command.outputMatch
      )
    )

proc runNotificationTest(arguments: seq[string]): int =
  if arguments.len == 1 or arguments == @["notify", "--help"] or
      arguments == @["notify", "test", "--help"]:
    stdout.writeLine(
      "Usage: canary notify test <slack|discord|pushover|webhook> " &
        "[--notify URL]... [--config PATH]"
    )
    return ExitUp
  if arguments.len < 3 or arguments[1] != "test":
    raise newException(
      CanaryConfigError,
      "expected 'canary notify test <provider>'"
    )

  let providerName = arguments[2]
  let provider = parseNotificationProvider(providerName)
  let optionArguments = if arguments.len > 3: arguments[3 .. ^1] else: @[]
  for argument in optionArguments:
    if argument.len > 0 and argument[0] == '-' and
        argument.optionKey() notin ["--config", "--notify", "-n"]:
      raise newException(
        CanaryConfigError,
        "unsupported notification-test option '" & argument.optionKey() & "'"
      )

  # Reuse the normal layered common configuration without introducing a
  # second parser or a second TOML schema. The synthetic HTTP target is never
  # validated or contacted.
  let input = loadCliConfig(
    @["http", "https://notification-test.invalid"] & optionArguments
  )
  if sendTestNotifications(provider, input.common.notifyUrls):
    for notifyUrl in input.common.notifyUrls:
      stdout.writeLine(
        "Notification test delivered via " &
          providerName.toLowerAscii() & " to " &
          notificationTarget(notifyUrl)
      )
    ExitUp
  else:
    ExitDown

proc printTopLevelHelp() =
  stdout.writeLine("Canary " & CanaryVersion)
  stdout.writeLine("")
  stdout.writeLine("Usage: canary <command> [options]")
  stdout.writeLine("")
  stdout.writeLine("Check commands: http, ssl, tcp, udp, dns, icmp, command")
  stdout.writeLine("Notification command: notify test <provider>")
  stdout.writeLine("")
  stdout.writeLine(
    "Common options: --config, --id, --notify, --db, --retries, " &
      "--recoveryThreshold, --cooldown, --repeatInterval, --silenceUntil, --json"
  )
  stdout.writeLine("Use 'canary <command> --help' for command-specific help.")

proc runCli*(): int =
  let arguments = commandLineParams()
  if arguments == @["--version"]:
    stdout.writeLine(CanaryVersion)
    return ExitUp
  if arguments.len == 0 or arguments == @["--help"]:
    printTopLevelHelp()
    return ExitUp
  if arguments.len > 0 and arguments[0].len > 0 and arguments[0][0] != '-' and
      arguments[0] != "notify" and
      arguments[0] notin Commands:
    stderr.writeLine("Unknown command '" & arguments[0] & "'")
    return ExitConfigError

  try:
    if arguments.len > 0 and arguments[0] == "notify":
      runNotificationTest(arguments)
    else:
      let input = loadCliConfig(arguments)
      run(input.toCanaryConfig())
  except ConfigurationError:
    stderr.writeLine(parserDiagnostic(arguments))
    ExitConfigError
  except CanaryConfigError, ValueError:
    stderr.writeLine("Configuration error: " & getCurrentExceptionMsg())
    ExitConfigError
