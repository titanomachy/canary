import std/[os, strutils]
import ../../src/notifier

when isMainModule:
  if paramCount() notin [4, 7]:
    stderr.writeLine(
      "usage: state_worker DB JOB_ID IS_OK RETRIES " &
      "[NOTIFY_URL REPEAT_INTERVAL TIMESTAMP]"
    )
    quit(2)

  let dbPath = paramStr(1)
  let jobId = paramStr(2)
  let isOk = parseBool(paramStr(3))
  let retries = parseInt(paramStr(4))
  if paramCount() == 4:
    handleStateAndNotify(jobId, isOk, "", dbPath, retries)
  else:
    discard processStateAndNotify(
      jobId, isOk, paramStr(5), dbPath, retries,
      repeatIntervalSeconds = parseInt(paramStr(6)),
      timestampOverride = parseBiggestInt(paramStr(7))
    )
