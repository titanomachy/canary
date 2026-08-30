import std/[monotimes, strutils]
import ../[common, input_contract, process_runner]

proc checkCommand*(executable: string, args: seq[string] = @[],
                   timeoutMs: int = 5000, expectedExitCode: int = 0,
                   outputMatch: string = "",
                   runner: ProcessRunner = nil): CheckResult =
  ## Run a local executable directly, never through a shell. Standard error is
  ## merged into standard output for the optional literal substring assertion.
  let startTime = getMonoTime()
  validateCommand(executable, args, timeoutMs, expectedExitCode, outputMatch)
  let execute = if runner.isNil: runProcess else: runner

  var execution: ProcessResult
  try:
    execution = execute(executable, args, "", timeoutMs)
  except OSError, IOError:
    raise newException(
      CanaryConfigError,
      "command executable could not be started"
    )

  let durationMs = elapsedMilliseconds(startTime)
  if execution.timedOut:
    return CheckResult(
      kind: "command", target: executable, isOk: false,
      message: "COMMAND TIMEOUT - " & executable & " - After " &
        $durationMs & "ms",
      latencyMs: durationMs, details: "Timeout"
    )

  if execution.exitCode != expectedExitCode:
    return CheckResult(
      kind: "command", target: executable, isOk: false,
      message: "COMMAND ERROR - " & executable & " - Exit code " &
        $execution.exitCode & " (expected " & $expectedExitCode & ")",
      latencyMs: durationMs,
      details: "Unexpected exit code: " & $execution.exitCode
    )

  if outputMatch.len > 0 and outputMatch notin execution.output:
    return CheckResult(
      kind: "command", target: executable, isOk: false,
      message: "COMMAND ERROR - " & executable &
        " - Expected output not received",
      latencyMs: durationMs, details: "Expected output not received"
    )

  let matchDetails =
    if outputMatch.len > 0: "; expected output received"
    else: ""
  CheckResult(
    kind: "command", target: executable, isOk: true,
    message: "COMMAND OK - " & executable & " - Exit code: " &
      $execution.exitCode & " - Runtime: " & $durationMs & "ms",
    latencyMs: durationMs,
    details: "Exit code: " & $execution.exitCode & matchDetails
  )
