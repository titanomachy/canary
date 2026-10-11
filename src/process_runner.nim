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

  var outputClosed = false
  while (getMonoTime() - started).inMilliseconds < timeoutMs:
    var received = 0
    if not outputClosed:
      # Drain while the child runs: waiting for exit first lets a full pipe
      # block a healthy command. Reads remain bounded by the same deadline.
      let chunk = process.readAvailable()
      result.output.add(chunk.data)
      received = chunk.data.len
      outputClosed = chunk.eof
    if not process.running() and outputClosed:
      result.exitCode = process.exitCode()
      return
    if received == 0:
      sleep(5)

  result.timedOut = true
  process.killTree()
  # Keep the established cross-platform timeout status instead of exposing
  # the platform-specific termination code (Windows commonly reports zero).
  result.exitCode = 137
