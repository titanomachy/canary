import std/[strutils, times]
import ../[common, input_contract, network_target]

type
  CheckKind* = enum
    ckHttp,
    ckSsl,
    ckTcp,
    ckUdp,
    ckDns,
    ckIcmp,
    ckCommand

  CommonConfig* = object
    ## Options shared by every check. The CLI is only one possible source for
    ## this model; TOML and environment adapters can populate the same fields.
    checkId*: string
    notifyUrls*: seq[string]
    dbPath*: string
    retries*: int
    recoveryThreshold*: int
    cooldownSeconds*: int
    repeatIntervalSeconds*: int
    silenceUntil*: string
    asJson*: bool

  HttpConfig* = object
    url*: string
    timeoutMs*: int
    expectedStatus*: int
    search*: string
    headers*: string
    httpMethod*: string
    body*: string
    maxRedirects*: int
    statusRange*: string
    maxLatencyMs*: int
    responseHeader*: string
    bodyRegex*: string
    jsonField*: string
    verboseTimings*: bool

  SslConfig* = object
    host*: string
    minDays*: int
    port*: int
    timeoutMs*: int

  TcpConfig* = object
    host*: string
    port*: int
    request*: string
    expected*: string
    timeoutMs*: int

  UdpConfig* = object
    host*: string
    port*: int
    payload*: string
    expected*: string
    timeoutMs*: int

  DnsConfig* = object
    host*: string
    recordType*: string
    expectedValues*: seq[string]
    resolver*: string
    timeoutMs*: int

  IcmpConfig* = object
    host*: string
    count*: int
    timeoutMs*: int

  CommandConfig* = object
    executable*: string
    args*: seq[string]
    timeoutMs*: int
    expectedExitCode*: int
    outputMatch*: string

  CanaryConfig* = object
    common*: CommonConfig
    case kind*: CheckKind
    of ckHttp:
      httpConfig*: HttpConfig
    of ckSsl:
      sslConfig*: SslConfig
    of ckTcp:
      tcpConfig*: TcpConfig
    of ckUdp:
      udpConfig*: UdpConfig
    of ckDns:
      dnsConfig*: DnsConfig
    of ckIcmp:
      icmpConfig*: IcmpConfig
    of ckCommand:
      commandConfig*: CommandConfig

proc validateCheckId*(checkId: string) =
  ## Explicit IDs are persisted and included in notification messages, so keep
  ## them compact and single-line. They are deliberately opaque: changing a
  ## target does not change state ownership when an ID is configured.
  if checkId.len == 0:
    return
  if checkId != checkId.strip() or checkId.len > 128:
    raise newException(
      CanaryConfigError,
      "id must be between 1 and 128 characters without surrounding whitespace"
    )
  for character in checkId:
    if ord(character) < 32 or ord(character) == 127:
      raise newException(CanaryConfigError, "id must not contain control characters")

proc parseSilenceUntil*(value: string): int64 =
  ## Silence windows use an unambiguous UTC timestamp. `clear` explicitly
  ## removes a previously persisted window; an empty value leaves it unchanged.
  let normalized = value.strip()
  if normalized.len == 0 or normalized.toLowerAscii() == "clear":
    return 0
  try:
    result = parse(
      normalized, "yyyy-MM-dd'T'HH:mm:ss'Z'", utc()
    ).toTime().toUnix()
  except TimeParseError, ValueError:
    raise newException(
      CanaryConfigError,
      "silenceUntil must be a UTC timestamp like 2026-08-30T18:00:00Z or clear"
    )

proc validate*(config: CanaryConfig) =
  ## Validate a parser-independent configuration before executing a check.
  validateCheckId(config.common.checkId)
  validateRetries(config.common.retries)
  validateRecoveryThreshold(config.common.recoveryThreshold)
  validateNotificationInterval("cooldown", config.common.cooldownSeconds)
  validateNotificationInterval(
    "repeatInterval", config.common.repeatIntervalSeconds
  )
  discard parseSilenceUntil(config.common.silenceUntil)

  case config.kind
  of ckHttp:
    let http = config.httpConfig
    validateHttp(
      http.url,
      http.timeoutMs,
      config.common.retries,
      http.expectedStatus,
      http.maxRedirects,
      http.httpMethod,
      http.statusRange,
      http.maxLatencyMs,
      http.responseHeader,
      http.bodyRegex,
      http.jsonField
    )
    validateHttpHeaders(http.headers)
  of ckSsl:
    let ssl = config.sslConfig
    validateCommon(ssl.timeoutMs, config.common.retries)
    validatePort(ssl.port)
    discard hostnameFromSslTarget(ssl.host)
    if ssl.minDays < 0:
      raise newException(CanaryConfigError, "minDays cannot be negative")
  of ckTcp:
    let tcp = config.tcpConfig
    validateCommon(tcp.timeoutMs, config.common.retries)
    validatePort(tcp.port)
    validateHostname(tcp.host)
    validateTcpProbe(tcp.request, tcp.expected)
  of ckUdp:
    let udp = config.udpConfig
    validateCommon(udp.timeoutMs, config.common.retries)
    validatePort(udp.port)
    validateHostname(udp.host)
  of ckDns:
    let dns = config.dnsConfig
    validateCommon(dns.timeoutMs, config.common.retries)
    validateHostname(dns.host)
    validateDnsExpectedValues(dns.recordType, dns.expectedValues)
    discard splitDnsResolver(dns.resolver)
  of ckIcmp:
    let icmp = config.icmpConfig
    validateCommon(icmp.timeoutMs, config.common.retries)
    validateHostname(icmp.host)
    validatePacketCount(icmp.count)
  of ckCommand:
    let command = config.commandConfig
    validateCommand(
      command.executable, command.args, command.timeoutMs,
      command.expectedExitCode, command.outputMatch
    )

proc resolvedCheckId*(config: CanaryConfig): string =
  ## Prefer an operator-defined identity. Generated IDs preserve the 0.1 CLI
  ## behavior for callers that do not opt in to explicit state separation.
  if config.common.checkId.len > 0:
    return config.common.checkId

  case config.kind
  of ckHttp:
    makeCheckId("http", config.httpConfig.url)
  of ckSsl:
    makeCheckId(
      "ssl", normalizedNetworkHost(config.sslConfig.host),
      config.sslConfig.port
    )
  of ckTcp:
    makeCheckId(
      "tcp", normalizedNetworkHost(config.tcpConfig.host),
      config.tcpConfig.port
    )
  of ckUdp:
    makeCheckId(
      "udp", normalizedNetworkHost(config.udpConfig.host),
      config.udpConfig.port
    )
  of ckDns:
    let dns = config.dnsConfig
    let normalizedType = normalizedDnsRecordType(dns.recordType)
    if normalizedType == "A" and dns.resolver.len == 0:
      makeCheckId("dns", normalizedNetworkHost(dns.host))
    else:
      makeCheckId(
        "dns_" & normalizedType.toLowerAscii(),
        normalizedNetworkHost(dns.host) &
          (if dns.resolver.len > 0: "_" & dns.resolver else: "")
      )
  of ckIcmp:
    makeCheckId("icmp", normalizedNetworkHost(config.icmpConfig.host))
  of ckCommand:
    # Arguments and assertions may contain credentials, so the generated ID
    # deliberately contains only the executable. Use --id for distinct probes.
    makeCheckId("command", config.commandConfig.executable)
