import std/[monotimes, os, osproc, streams, times]

type
  ProcessResult* = object
    output*: string
    exitCode*: int
    timedOut*: bool

  ProcessRunner* = proc(command: string, args: seq[string], input: string,
                        timeoutMs: int): ProcessResult {.closure.}

proc runProcess*(command: string, args: seq[string], input: string = "",
                 timeoutMs: int = 5000): ProcessResult =
  ## Execute one program directly. Arguments are passed as an argv array and
  ## are never interpreted by a shell.
  let started = getMonoTime()
  let process = startProcess(
    command,
    args = args,
    options = {poUsePath, poStdErrToStdOut}
  )
  defer: process.close()

  let processInput = process.inputStream()
  if input.len > 0:
    processInput.write(input)
  processInput.close()

  while process.running() and
      (getMonoTime() - started).inMilliseconds < timeoutMs:
    sleep(5)
  if process.running():
    result.timedOut = true
    process.terminate()
    discard process.waitForExit()
    # Keep the established cross-platform timeout status instead of exposing
    # the platform-specific termination code (Windows commonly reports zero).
    result.exitCode = 137
  else:
    result.exitCode = process.waitForExit()
  result.output = process.outputStream().readAll()
