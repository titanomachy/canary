import std/[os, osproc]
when defined(posix):
  import std/posix

let arguments = commandLineParams()
case arguments[0]
of "ignore-term":
  when defined(posix):
    discard signal(SIGTERM, SIG_IGN)
  sleep(1200)
of "sleep-child":
  writeFile(arguments[1] / "ready", "ready")
  sleep(800)
  writeFile(arguments[1] / "escaped", "child survived")
of "wait-child", "orphan-child":
  let child = startProcess(
    getAppFilename(), args = @["sleep-child", arguments[1]],
    options = {poParentStreams}
  )
  while not fileExists(arguments[1] / "ready"):
    sleep(5)
  if arguments[0] == "wait-child":
    discard child.waitForExit()
  child.close()
of "echo":
  stdout.write(arguments[1])
  stderr.write(arguments[2])
else:
  quit(2)
