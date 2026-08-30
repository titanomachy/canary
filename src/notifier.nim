import nim_sqlite
import std/[httpclient, json, options, os, strutils, times, uri]
import common

const
  OutboxLeaseSeconds = 300'i64
  MaxRetryDelaySeconds* = 300'i64

type
  NotificationProvider* = enum
    npSlack,
    npDiscord,
    npPushover,
    npWebhook

  NotificationSender* = proc(notifyUrl: string,
                             message: string): bool {.closure.}

  DeliveryResult* = object
    target*: string
    status*: string
    attempt*: int
    nextAttempt*: int64

  ClaimedEvent = object
    id: int64
    target: string
    message: string
    attempt: int

proc deliveryResultJson*(delivery: DeliveryResult): JsonNode =
  result = %*{
    "target": delivery.target,
    "status": delivery.status,
    "attempt": delivery.attempt
  }
  if delivery.nextAttempt > 0:
    result["next_attempt"] = %delivery.nextAttempt

proc parsePushoverCredentials*(notifyUrl: string): tuple[userKey, apiToken: string] =
  ## Parses the documented `pushover://USER_KEY@API_TOKEN` format.
  let parsed = parseUri(notifyUrl)
  if parsed.scheme == "pushover":
    result = (decodeUrl(parsed.username), decodeUrl(parsed.hostname))

proc notificationTarget*(notifyUrl: string): string =
  ## Describe an endpoint without exposing credentials, paths, or query values.
  try:
    let parsed = parseUri(notifyUrl)
    if parsed.scheme == "pushover":
      return "pushover://<redacted>"
    if parsed.scheme in ["http", "https"]:
      return parsed.scheme & "://" & parsed.hostname
  except ValueError:
    discard
  "<invalid notification URL>"

proc webhookPayload*(notifyUrl, message: string): JsonNode =
  ## Slack and Discord reject each other's field names on stricter endpoints.
  ## Unknown HTTP webhooks retain the backwards-compatible dual payload.
  let hostname = parseUri(notifyUrl).hostname.toLowerAscii()
  if hostname == "hooks.slack.com" or hostname.endsWith(".hooks.slack.com"):
    %*{"text": message}
  elif hostname in ["discord.com", "discordapp.com"] or
      hostname.endsWith(".discord.com") or
      hostname.endsWith(".discordapp.com"):
    %*{"content": message}
  else:
    %*{"text": message, "content": message}

proc sendSingleNotification(notifyUrl: string, message: string,
                            timeoutMs: int): bool =
  let trimmed = notifyUrl.strip()
  if trimmed.len == 0:
    return true

  let client = newHttpClient(timeout = timeoutMs)
  try:
    let parsed = parseUri(trimmed)
    var response: Response
    if parsed.scheme == "pushover":
      let (userKey, apiToken) = parsePushoverCredentials(trimmed)
      if userKey.len == 0 or apiToken.len == 0:
        stderr.writeLine("Error sending notification to " &
                         notificationTarget(trimmed) & ": missing credentials")
        return false
      let body = "token=" & encodeUrl(apiToken) & "&user=" & encodeUrl(userKey) &
                 "&message=" & encodeUrl(message)
      client.headers = newHttpHeaders([
        ("Content-Type", "application/x-www-form-urlencoded")
      ])
      response = client.request(
        "https://api.pushover.net/1/messages.json", HttpPost, body
      )
    elif parsed.scheme in ["http", "https"]:
      client.headers = newHttpHeaders([("Content-Type", "application/json")])
      response = client.request(
        trimmed, HttpPost, $webhookPayload(trimmed, message)
      )
    else:
      stderr.writeLine("Error sending notification: unsupported URL scheme")
      return false

    let statusCode = int(response.code)
    if statusCode < 200 or statusCode >= 300:
      stderr.writeLine(
        "Error sending notification to " & notificationTarget(trimmed) &
        ": HTTP " & $statusCode
      )
      return false
    result = true
  except CatchableError:
    stderr.writeLine("Error sending notification to " &
                     notificationTarget(trimmed) & ": delivery failed")
  finally:
    client.close()

proc sendNotifications*(notifyUrls: openArray[string], message: string,
                        timeoutMs: int = 5000): bool =
  ## Deliver to every configured endpoint and report aggregate success.
  result = true
  for url in notifyUrls:
    if not sendSingleNotification(url, message, timeoutMs):
      result = false

proc sendNotifications*(notifyUrl: string, message: string,
                        timeoutMs: int = 5000): bool =
  ## Source-compatible single-endpoint API. Multiple endpoints use the
  ## open-array overload; this overload intentionally does not comma-split.
  sendNotifications([notifyUrl], message, timeoutMs)

proc parseNotificationProvider*(value: string): NotificationProvider =
  case value.toLowerAscii()
  of "slack": npSlack
  of "discord": npDiscord
  of "pushover": npPushover
  of "webhook": npWebhook
  else:
    raise newException(
      CanaryConfigError,
      "unknown notification provider '" & value &
        "' (expected slack, discord, pushover, or webhook)"
    )

proc validateNotificationTarget*(provider: NotificationProvider,
                                 notifyUrl: string) =
  let trimmed = notifyUrl.strip()
  if trimmed.len == 0:
    raise newException(CanaryConfigError, "notification URL must not be empty")

  var parsed: Uri
  try:
    parsed = parseUri(trimmed)
  except ValueError:
    raise newException(CanaryConfigError, "invalid notification URL")

  let hostname = parsed.hostname.toLowerAscii()
  case provider
  of npSlack:
    if parsed.scheme != "https" or hostname != "hooks.slack.com":
      raise newException(
        CanaryConfigError,
        "Slack notification URLs must use https://hooks.slack.com"
      )
  of npDiscord:
    if parsed.scheme != "https" or
        hostname notin ["discord.com", "discordapp.com"]:
      raise newException(
        CanaryConfigError,
        "Discord notification URLs must use https://discord.com or " &
          "https://discordapp.com"
      )
  of npPushover:
    let credentials = parsePushoverCredentials(trimmed)
    if parsed.scheme != "pushover" or credentials.userKey.len == 0 or
        credentials.apiToken.len == 0:
      raise newException(
        CanaryConfigError,
        "Pushover notification URLs must use pushover://USER_KEY@API_TOKEN"
      )
  of npWebhook:
    if parsed.scheme notin ["http", "https"] or hostname.len == 0:
      raise newException(
        CanaryConfigError,
        "webhook notification URLs must use http or https"
      )

proc sendTestNotifications*(provider: NotificationProvider,
                            notifyUrls: openArray[string],
                            timeoutMs: int = 5000): bool =
  ## Validate every target before delivering, avoiding partial delivery when
  ## one endpoint was configured for a different provider.
  if notifyUrls.len == 0:
    raise newException(
      CanaryConfigError,
      "no notification URL configured; use CANARY_NOTIFY, TOML notify, or --notify"
    )
  for notifyUrl in notifyUrls:
    validateNotificationTarget(provider, notifyUrl)
  sendNotifications(
    notifyUrls, "[TEST] Canary notification delivery test", timeoutMs
  )

proc addColumnIfMissing(db: DbConn, tableName, definition: string) =
  try:
    db.exec("ALTER TABLE " & tableName & " ADD COLUMN " & definition)
  except CatchableError:
    discard

proc initializeStore(db: DbConn) =
  db.exec("PRAGMA busy_timeout = 5000;")
  db.exec("PRAGMA journal_mode = WAL;")
  db.execScript("""
    CREATE TABLE IF NOT EXISTS canary_state (
      id TEXT PRIMARY KEY,
      status TEXT NOT NULL,
      fail_count INTEGER NOT NULL DEFAULT 0,
      success_count INTEGER NOT NULL DEFAULT 0,
      last_check INTEGER NOT NULL DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS notification_outbox (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      check_id TEXT NOT NULL,
      target TEXT NOT NULL,
      message TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'pending',
      attempt_count INTEGER NOT NULL DEFAULT 0,
      next_attempt INTEGER NOT NULL DEFAULT 0,
      locked_at INTEGER,
      created_at INTEGER NOT NULL,
      sent_at INTEGER
    );
    CREATE INDEX IF NOT EXISTS notification_outbox_due
      ON notification_outbox(status, next_attempt);
  """)
  # Existing 0.1 databases are upgraded in place.
  addColumnIfMissing(
    db, "canary_state", "success_count INTEGER NOT NULL DEFAULT 0"
  )

proc legacyNotificationUrls(raw: string): seq[string] =
  for candidate in raw.split(','):
    let target = candidate.strip()
    if target.len > 0:
      result.add(target)

proc transitionMessage(jobId, transition: string, attempt, latencyMs: int,
                       cause: string, timestamp: int64): string =
  let prefix = if transition == "DOWN": "[ALERT]" else: "[RECOVERY]"
  result = prefix & " Canary: name=" & jobId & " transition=" & transition &
    " attempt=" & $attempt & " latency_ms=" & $latencyMs &
    " timestamp=" & fromUnix(timestamp).utc.format(
      "yyyy-MM-dd'T'HH:mm:ss'Z'"
    )
  if cause.len > 0:
    result.add(" cause=" & cause.replace("\r", " ").replace("\n", " "))

proc retryDelaySeconds*(eventId: int64, attempt: int): int64 =
  ## Deterministic jitter avoids synchronized retries without process-global RNG.
  let exponent = min(max(attempt - 1, 0), 8)
  let baseDelay = min(1'i64 shl exponent, MaxRetryDelaySeconds)
  let jitterRange = max(baseDelay div 4, 1'i64)
  let jitter = abs(eventId * 31 + int64(attempt) * 17) mod jitterRange
  min(baseDelay + jitter, MaxRetryDelaySeconds)

proc enqueueTransition(db: DbConn, jobId: string, targets: openArray[string],
                       message: string,
                       timestamp: int64) =
  for target in targets:
    if target.strip().len == 0:
      continue
    db.exec(
      "INSERT INTO notification_outbox(" &
      "check_id, target, message, next_attempt, created_at" &
      ") VALUES(?, ?, ?, ?, ?)",
      jobId, target, message, timestamp, timestamp
    )

proc recordTransition(db: DbConn, jobId: string, isOk: bool,
                      notifyUrls: openArray[string], failureThreshold,
                      recoveryThreshold, latencyMs: int, cause: string,
                      timestamp: int64) =
  db.exec("BEGIN IMMEDIATE")
  var committed = false
  try:
    let rowOpt = db.one(
      "SELECT status, fail_count, success_count FROM canary_state WHERE id = ?",
      jobId
    )
    var previousStatus = "UNKNOWN"
    var failCount = 0
    var successCount = 0
    if rowOpt.isSome:
      let row = rowOpt.get()
      previousStatus = row[0].fromDb(string)
      failCount = row[1].fromDb(int)
      successCount = row[2].fromDb(int)

    var status = previousStatus
    var transition = ""
    var transitionAttempt = 0
    if isOk:
      failCount = 0
      if previousStatus == "DOWN":
        successCount.inc()
        if successCount >= recoveryThreshold:
          status = "UP"
          transition = "UP"
          transitionAttempt = successCount
          successCount = 0
      else:
        status = "UP"
        successCount = 0
    else:
      successCount = 0
      failCount.inc()
      if previousStatus == "DOWN":
        status = "DOWN"
      elif failCount >= failureThreshold:
        status = "DOWN"
        transition = "DOWN"
        transitionAttempt = failCount
      else:
        status = "PENDING_DOWN"

    if rowOpt.isNone:
      db.exec(
        "INSERT INTO canary_state(" &
        "id, status, fail_count, success_count, last_check" &
        ") VALUES(?, ?, ?, ?, ?)",
        jobId, status, failCount, successCount, timestamp
      )
    else:
      db.exec(
        "UPDATE canary_state SET status = ?, fail_count = ?, " &
        "success_count = ?, last_check = ? WHERE id = ?",
        status, failCount, successCount, timestamp, jobId
      )

    if transition.len > 0 and notifyUrls.len > 0:
      enqueueTransition(
        db,
        jobId,
        notifyUrls,
        transitionMessage(
          jobId, transition, transitionAttempt, latencyMs, cause, timestamp
        ),
        timestamp
      )
    db.exec("COMMIT")
    committed = true
  finally:
    if not committed and db.isInTransaction:
      try:
        db.exec("ROLLBACK")
      except CatchableError:
        discard

proc claimEvent(db: DbConn, timestamp: int64): Option[ClaimedEvent] =
  db.exec("BEGIN IMMEDIATE")
  var committed = false
  try:
    let rowOpt = db.one(
      "SELECT id, target, message, attempt_count " &
      "FROM notification_outbox " &
      "WHERE (status = 'pending' AND next_attempt <= ?) " &
      "OR (status = 'delivering' AND locked_at <= ?) " &
      "ORDER BY created_at, id LIMIT 1",
      timestamp, timestamp - OutboxLeaseSeconds
    )
    if rowOpt.isSome:
      let row = rowOpt.get()
      result = some(ClaimedEvent(
        id: row[0].fromDb(int64),
        target: row[1].fromDb(string),
        message: row[2].fromDb(string),
        attempt: row[3].fromDb(int) + 1
      ))
      db.exec(
        "UPDATE notification_outbox SET status = 'delivering', " &
        "attempt_count = ?, locked_at = ? WHERE id = ?",
        result.get().attempt, timestamp, result.get().id
      )
    db.exec("COMMIT")
    committed = true
  finally:
    if not committed and db.isInTransaction:
      try:
        db.exec("ROLLBACK")
      except CatchableError:
        discard

proc deliverOutbox(db: DbConn, sender: NotificationSender,
                   timestamp: int64): seq[DeliveryResult] =
  while true:
    let eventOpt = claimEvent(db, timestamp)
    if eventOpt.isNone:
      break
    let event = eventOpt.get()
    var delivered = false
    try:
      delivered = if sender.isNil:
        sendSingleNotification(event.target, event.message, 5000)
      else:
        sender(event.target, event.message)
    except CatchableError:
      delivered = false

    if delivered:
      db.exec(
        "UPDATE notification_outbox SET status = 'sent', sent_at = ?, " &
        "locked_at = NULL WHERE id = ?",
        timestamp, event.id
      )
      stderr.writeLine(
        "Notification delivered to " & notificationTarget(event.target) &
        " (attempt " & $event.attempt & ")"
      )
      result.add(DeliveryResult(
        target: notificationTarget(event.target),
        status: "sent",
        attempt: event.attempt
      ))
    else:
      let nextAttempt = timestamp + retryDelaySeconds(event.id, event.attempt)
      db.exec(
        "UPDATE notification_outbox SET status = 'pending', next_attempt = ?, " &
        "locked_at = NULL WHERE id = ?",
        nextAttempt, event.id
      )
      stderr.writeLine(
        "Notification delivery to " & notificationTarget(event.target) &
        " scheduled for retry (attempt " & $event.attempt & ")"
      )
      result.add(DeliveryResult(
        target: notificationTarget(event.target),
        status: "retry",
        attempt: event.attempt,
        nextAttempt: nextAttempt
      ))

proc processStateAndNotify*(jobId: string, isOk: bool,
                            notifyUrls: openArray[string],
                            dbPath: string = "", failureThreshold: int = 1,
                            recoveryThreshold: int = 1,
                            latencyMs: int = 0, cause: string = "",
                            sender: NotificationSender = nil): seq[DeliveryResult] =
  let finalDbPath = resolveDbPath(dbPath)
  let timestamp = getTime().toUnix()
  try:
    let dir = parentDir(finalDbPath)
    if dir.len > 0:
      createDir(dir)
    let db = openDatabase(finalDbPath)
    defer: db.close()
    initializeStore(db)
    recordTransition(
      db, jobId, isOk, notifyUrls, failureThreshold, recoveryThreshold,
      latencyMs, cause, timestamp
    )
    result = deliverOutbox(db, sender, timestamp)
  except CatchableError:
    stderr.writeLine(
      "Error during state tracking in " & finalDbPath & ": " &
      getCurrentExceptionMsg()
    )

proc processStateAndNotify*(jobId: string, isOk: bool, notifyUrl: string,
                            dbPath: string = "", failureThreshold: int = 1,
                            recoveryThreshold: int = 1,
                            latencyMs: int = 0, cause: string = "",
                            sender: NotificationSender = nil): seq[DeliveryResult] =
  ## Compatibility overload for callers of the 0.1 API. The CLI and typed
  ## configuration model use a real sequence and never comma-split options.
  processStateAndNotify(
    jobId, isOk, legacyNotificationUrls(notifyUrl), dbPath, failureThreshold,
    recoveryThreshold, latencyMs, cause, sender
  )

proc handleStateAndNotify*(jobId: string, isOk: bool, notifyUrl: string,
                           dbPath: string = "", retries: int = 1,
                           sender: NotificationSender = nil) =
  ## Compatibility wrapper for callers using the 0.1 state API.
  discard processStateAndNotify(
    jobId, isOk, notifyUrl, dbPath, retries, 1, sender = sender
  )
