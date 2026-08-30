import std/[json, os]
import ../[canary_contract, common, notifier]
import ../checks/[dnscheck, httpcheck, icmpcheck, sslcheck, tcpcheck, udpcheck]
import config

proc executeCheck*(config: CanaryConfig): CheckResult =
  ## Execute one validated check without parsing arguments, printing, changing
  ## state, notifying, or terminating the process.
  config.validate()
  case config.kind
  of ckHttp:
    let http = config.httpConfig
    checkHttp(
      http.url,
      http.timeoutMs,
      http.expectedStatus,
      http.search,
      http.headers,
      http.httpMethod,
      http.body,
      http.maxRedirects,
      http.statusRange,
      http.maxLatencyMs,
      http.responseHeader,
      http.bodyRegex,
      http.jsonField,
      http.verboseTimings
    )
  of ckSsl:
    let ssl = config.sslConfig
    checkSsl(ssl.host, ssl.minDays, ssl.port, ssl.timeoutMs)
  of ckTcp:
    let tcp = config.tcpConfig
    checkTcp(
      tcp.host, tcp.port, tcp.timeoutMs, tcp.request, tcp.expected
    )
  of ckUdp:
    let udp = config.udpConfig
    checkUdp(
      udp.host,
      udp.port,
      udp.payload,
      udp.expected,
      udp.timeoutMs
    )
  of ckDns:
    let dns = config.dnsConfig
    checkDns(
      dns.host,
      dns.recordType,
      dns.expectedValues,
      dns.resolver,
      dns.timeoutMs
    )
  of ckIcmp:
    let icmp = config.icmpConfig
    checkIcmp(icmp.host, icmp.count, icmp.timeoutMs)

proc stateTrackingRequested(common: CommonConfig): bool =
  ## Notifications need state to detect transitions; otherwise persistence is
  ## opt-in through the model or the established CANARY_DB environment input.
  common.notifyUrls.len > 0 or common.dbPath.len > 0 or
    getEnv("CANARY_DB").len > 0

proc run*(config: CanaryConfig): int =
  ## Orchestrate one configuration and return the public process exit code.
  ## The caller owns process termination, which keeps this layer reusable.
  var checkResult: CheckResult
  try:
    checkResult = executeCheck(config)
  except CanaryConfigError, ValueError:
    stderr.writeLine("Configuration error: " & getCurrentExceptionMsg())
    return ExitConfigError
  except CatchableError:
    stderr.writeLine("Internal error: check execution failed")
    return ExitInternalError

  var deliveries: seq[DeliveryResult]
  if stateTrackingRequested(config.common):
    let safeResult = publicResult(checkResult)
    deliveries = processStateAndNotify(
      config.resolvedCheckId(),
      checkResult.isOk,
      config.common.notifyUrls,
      config.common.dbPath,
      config.common.retries,
      config.common.recoveryThreshold,
      safeResult.latencyMs,
      safeResult.details
    )
  if config.common.asJson:
    var output = parseJson(formatResult(checkResult, true))
    if stateTrackingRequested(config.common):
      output["notifications"] = newJArray()
      for delivery in deliveries:
        output["notifications"].add(delivery.deliveryResultJson())
    echo $output
  else:
    outputResult(checkResult)
  if checkResult.isOk: ExitUp else: ExitDown
