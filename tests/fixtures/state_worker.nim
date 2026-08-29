import std/[os, strutils]
import ../../src/notifier

when isMainModule:
  if paramCount() != 4:
    stderr.writeLine("usage: state_worker DB JOB_ID IS_OK RETRIES")
    quit(2)

  let dbPath = paramStr(1)
  let jobId = paramStr(2)
  let isOk = parseBool(paramStr(3))
  let retries = parseInt(paramStr(4))
  handleStateAndNotify(jobId, isOk, "", dbPath, retries)
