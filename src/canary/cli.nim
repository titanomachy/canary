import confutils
import confutils/toml/defs
import std/[os, strutils]
import toml_serialization
import ../[canary_contract, common]
import app, config

type
  CanaryCommand* {.pure.} = enum
    http = "Check HTTP/HTTPS service availability and response"
    ssl = "Check days remaining until an SSL/TLS certificate expires"
    tcp = "Check whether a TCP port accepts connections"
    udp = "Send a UDP datagram and require a response"
    dns = "Resolve a domain, optionally matching an expected IP"
    icmp = "Check ICMP ping reachability"

  CommonCliConfig* = object
    checkId* {.
      name: "id"
      defaultValue: ""
      desc: "Explicit state identity for this check" .}: string
    notifyUrl* {.
      name: "notify"
      abbr: "n"
      defaultValue: ""
      desc: "Notification URL(s) separated by commas" .}: string
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
    expected* {.
      defaultValue: ""
      desc: "Expected resolved IP address" .}: string

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

const
  Commands = ["http", "ssl", "tcp", "udp", "dns", "icmp"]
  ValueOptions = [
    "--config", "--id", "--notify", "--db", "--retries", "-n", "-d",
    "-r", "--recoveryThreshold", "--timeout", "--status", "--search", "--headers", "--methodStr",
    "--body", "--maxRedirects", "--minDays", "--port", "--payload",
    "--expected", "--count", "-t", "-s", "-m", "-b", "-p"
  ]
  BooleanOptions = ["--json", "-j", "--help", "--version"]
  NumericOptions = [
    "--retries", "--recoveryThreshold", "--timeout", "--status", "--maxRedirects", "--minDays",
    "--port", "--count", "-r", "-t", "-s", "-m", "-p"
  ]

proc normalizedArguments(arguments: seq[string]): seq[string] =
  ## Confutils accepts `--option=value`; Canary's established contract also
  ## accepts `--option value`. Normalize only documented valued options and
  ## leave positionals and boolean flags untouched.
  var index = 0
  while index < arguments.len:
    let argument = arguments[index]
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
    notifyUrl: input.notifyUrl,
    dbPath: input.dbPath,
    retries: input.retries,
    recoveryThreshold: input.recoveryThreshold,
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
        maxRedirects: http.maxRedirects
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
        expected: dns.expected
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

proc runCli*(): int =
  let arguments = commandLineParams()
  if arguments == @["--version"]:
    stdout.writeLine(CanaryVersion)
    return ExitUp
  if arguments.len > 0 and arguments[0].len > 0 and arguments[0][0] != '-' and
      arguments[0] notin Commands:
    stderr.writeLine("Unknown command '" & arguments[0] & "'")
    return ExitConfigError

  if arguments.len == 0:
    discard CliConfig.load(
      cmdLine = @["--help"],
      version = CanaryVersion,
      copyrightBanner = "Canary " & CanaryVersion,
      envVarsPrefix = "CANARY"
    )

  try:
    let input = loadCliConfig(arguments)
    run(input.toCanaryConfig())
  except ConfigurationError:
    stderr.writeLine(parserDiagnostic(arguments))
    ExitConfigError
  except CanaryConfigError, ValueError:
    stderr.writeLine("Configuration error: " & getCurrentExceptionMsg())
    ExitConfigError
