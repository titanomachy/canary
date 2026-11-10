import std/[json, os, strutils]
import ../[canary_contract, common, input_contract, network_target, notifier]
import ../checks/[commandcheck, dnscheck, httpcheck, icmpcheck, sslcheck,
                  tcpcheck, udpcheck]
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
  of ckCommand:
    let command = config.commandConfig
    checkCommand(
      command.executable,
      command.args,
      command.timeoutMs,
      command.expectedExitCode,
      command.outputMatch
    )

proc stateTrackingRequested(common: CommonConfig): bool =
  ## Notifications need state to detect transitions; otherwise persistence is
  ## opt-in through the model or the established CANARY_DB environment input.
  common.notifyUrls.len > 0 or common.dbPath.len > 0 or
    getEnv("CANARY_DB").len > 0 or common.silenceUntil.len > 0

proc run*(configs: openArray[CanaryConfig]): int =
  ## Validate the complete batch before executing checks in the supplied order.
  ## Collect results before output so execution errors retain empty stdout.
  var checkResults: seq[CheckResult]
  try:
    if configs.len == 0:
      raise newException(CanaryConfigError, "no checks specified")
    for config in configs:
      config.validate()
    for config in configs:
      var checkResult = executeCheck(config)
      if configs.len > 1 and config.kind == ckSsl:
        # Single-port SSL output historically omits the port after a successful
        # handshake. A batch must identify every certificate's endpoint.
        let target = formatHostPort(
          hostnameFromSslTarget(config.sslConfig.host), config.sslConfig.port
        )
        checkResult.message = checkResult.message.replace(
          " - " & checkResult.target, " - " & target
        )
        checkResult.target = target
      checkResults.add(checkResult)
  except CanaryConfigError, ValueError:
    stderr.writeLine("Configuration error: " & getCurrentExceptionMsg())
    return ExitConfigError
  except CatchableError:
    stderr.writeLine("Internal error: check execution failed")
    return ExitInternalError

  var outputs = newJArray()
  var allOk = true
  for index, config in configs:
    let checkResult = checkResults[index]
    allOk = allOk and checkResult.isOk
    var deliveries: seq[DeliveryResult]
    let trackState = stateTrackingRequested(config.common)
    if trackState:
      let safeResult = publicResult(checkResult)
      deliveries = processStateAndNotify(
        config.resolvedCheckId(),
        checkResult.isOk,
        config.common.notifyUrls,
        config.common.dbPath,
        config.common.retries,
        config.common.recoveryThreshold,
        safeResult.latencyMs,
        safeResult.details,
        cooldownSeconds = config.common.cooldownSeconds,
        repeatIntervalSeconds = config.common.repeatIntervalSeconds,
        silenceUntil = if config.common.silenceUntil.len == 0:
          -1'i64
        else:
          parseSilenceUntil(config.common.silenceUntil)
      )
    if configs[0].common.asJson:
      var output = parseJson(formatResult(checkResult, true))
      if trackState:
        output["notifications"] = newJArray()
        for delivery in deliveries:
          output["notifications"].add(delivery.deliveryResultJson())
      outputs.add(output)
    else:
      outputResult(checkResult)
  if configs[0].common.asJson:
    if configs.len == 1:
      echo $outputs[0]
    else:
      echo $(%*{"status": if allOk: "UP" else: "DOWN", "results": outputs})
  if allOk: ExitUp else: ExitDown

proc run*(config: CanaryConfig): int =
  ## Preserve the single-check application entrypoint.
  run([config])
