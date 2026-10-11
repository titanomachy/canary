import std/[monotimes, os, times]
import process_child

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
  let process = startChild(command, args)
  defer: process.close()

  process.sendInput(input)

  while process.running() and
      (getMonoTime() - started).inMilliseconds < timeoutMs:
    sleep(5)
  if process.running():
    result.timedOut = true
    process.killTree()
    # Keep the established cross-platform timeout status instead of exposing
    # the platform-specific termination code (Windows commonly reports zero).
    result.exitCode = 137
  else:
    result.exitCode = process.exitCode()
    while (getMonoTime() - started).inMilliseconds < timeoutMs:
      let chunk = process.readAvailable()
      result.output.add(chunk.data)
      if chunk.eof:
        return
      if chunk.data.len == 0:
        sleep(5)
    result.timedOut = true
    result.exitCode = 137
    process.killTree()
