import std/[monotimes, osproc, streams, times]

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

  result.exitCode = process.waitForExit(timeoutMs)
  result.output = process.outputStream().readAll()
  result.timedOut = result.exitCode == 137 and
    (getMonoTime() - started).inMilliseconds >= timeoutMs
