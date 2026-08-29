import std/[os, osproc, streams, strutils, times]

const
  ProjectRoot* = currentSourcePath().parentDir.parentDir
  FixtureBinary* = ProjectRoot / "build" / "local_server"
  StateWorkerBinary* = ProjectRoot / "build" / "state_worker"

type LocalServer* = object
  process*: Process
  port*: int

proc startLocalServer*(mode: string,
                       extraArgs: openArray[string] = []): LocalServer =
  var args = @[mode]
  args.add(extraArgs)
  result.process = startProcess(
    FixtureBinary,
    workingDir = ProjectRoot,
    args = args,
    options = {}
  )
  try:
    result.port = parseInt(result.process.outputStream.readLine())
  except CatchableError:
    let diagnostic = result.process.errorStream.readAll()
    result.process.close()
    raise newException(IOError, "local server failed to start: " & diagnostic)

proc stop*(server: var LocalServer) =
  if server.process != nil:
    if server.process.running():
      server.process.terminate()
    discard server.process.waitForExit()
    server.process.close()
    server.process = nil

proc waitForSuccess*(server: var LocalServer) =
  let exitCode = server.process.waitForExit()
  let diagnostic = server.process.errorStream.readAll()
  server.process.close()
  server.process = nil
  if exitCode != 0:
    raise newException(
      IOError,
      "local server exited with " & $exitCode & ": " & diagnostic
    )

proc newTestDir*(label: string): string =
  result = getTempDir() / (
    "canary-" & label & "-" & $getCurrentProcessId() & "-" &
    $(epochTime() * 1_000_000).int64
  )
  createDir(result)
