import std/[net, os, parseopt, strutils]

proc announce(port: Port) =
  stdout.writeLine($port)
  stdout.flushFile()

proc fixtureHost(ipv6: bool): string =
  if ipv6: "::1" else: "127.0.0.1"

proc fixtureSocket(ipv6: bool, sockType: SockType = SOCK_STREAM,
                   protocol: Protocol = IPPROTO_TCP): Socket =
  let domain = if ipv6: AF_INET6 else: AF_INET
  newSocket(domain, sockType, protocol)

proc readHttpRequest(client: Socket): string =
  result = client.recvLine(2000) & "\n"
  var contentLength = 0
  while true:
    let line = client.recvLine(2000)
    if line.len == 0 or line == "\r\n" or line == "\n":
      break
    result.add(line & "\n")
    if line.toLowerAscii().startsWith("content-length:"):
      contentLength = parseInt(line.split(":", 1)[1].strip())
  if contentLength > 0:
    result.add(client.recv(contentLength, 2000))

proc serveHttp(mode: string, delayMs: int, ipv6: bool) =
  let server = fixtureSocket(ipv6)
  defer: server.close()
  server.setSockOpt(OptReuseAddr, true)
  server.bindAddr(Port(0), fixtureHost(ipv6))
  server.listen()
  announce(server.getLocalAddr()[1])

  var client: owned(Socket)
  server.accept(client)
  defer: client.close()
  let request = readHttpRequest(client)
  if delayMs > 0:
    sleep(delayMs)

  var status = "200 OK"
  var body = "fixture-ok"
  var contentType = "text/plain"
  var extraHeaders = ""
  case mode
  of "http-ok":
    discard
  of "http-json":
    status = "202 Accepted"
    body = "{\"service\":{\"status\":\"ready\"}," &
      "\"replicas\":[{\"healthy\":true}]}"
    contentType = "application/json; charset=utf-8"
    extraHeaders = "X-Canary-State: ready\r\n"
  of "webhook-ok", "webhook-slow":
    if "\"text\"" notin request or "\"content\"" notin request:
      status = "400 Bad Request"
      body = "invalid webhook payload"
  of "webhook-fail":
    status = "503 Service Unavailable"
    body = "fixture failure"
  else:
    status = "404 Not Found"
    body = "not found"

  let response = "HTTP/1.1 " & status & "\r\n" &
                 "Content-Type: " & contentType & "\r\n" &
                 extraHeaders &
                 "Content-Length: " & $body.len & "\r\n" &
                 "Connection: close\r\n\r\n" & body
  client.send(response)

proc serveHttpRedirect(ipv6: bool, delayMs: int) =
  let server = fixtureSocket(ipv6)
  defer: server.close()
  server.setSockOpt(OptReuseAddr, true)
  server.bindAddr(Port(0), fixtureHost(ipv6))
  server.listen()
  announce(server.getLocalAddr()[1])

  var firstClient: owned(Socket)
  server.accept(firstClient)
  discard readHttpRequest(firstClient)
  if delayMs > 0:
    sleep(delayMs)
  firstClient.send(
    "HTTP/1.1 302 Found\r\nLocation: /final\r\nContent-Length: 0\r\n" &
    "Connection: close\r\n\r\n"
  )
  firstClient.close()

  var secondClient: owned(Socket)
  server.accept(secondClient)
  defer: secondClient.close()
  discard readHttpRequest(secondClient)
  if delayMs > 0:
    sleep(delayMs)
  let body = "fixture-ok"
  secondClient.send(
    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n" &
    "Content-Length: " & $body.len & "\r\nConnection: close\r\n\r\n" & body
  )

proc serveUdp(response: string, ipv6: bool) =
  let server = fixtureSocket(ipv6, SOCK_DGRAM, IPPROTO_UDP)
  defer: server.close()
  server.bindAddr(Port(0), fixtureHost(ipv6))
  announce(server.getLocalAddr()[1])

  var payload = ""
  var clientHost = ""
  var clientPort: Port
  discard server.recvFrom(payload, 65_535, clientHost, clientPort)
  server.sendTo(clientHost, clientPort, response)

proc serveTcp(mode, response, expectedRequest: string, delayMs, holdMs: int,
              ipv6: bool) =
  let server = fixtureSocket(ipv6)
  defer: server.close()
  server.setSockOpt(OptReuseAddr, true)
  server.bindAddr(Port(0), fixtureHost(ipv6))
  server.listen()
  announce(server.getLocalAddr()[1])

  var client: owned(Socket)
  server.accept(client)
  defer: client.close()
  case mode
  of "tcp-banner":
    if delayMs > 0:
      sleep(delayMs)
    client.send(response)
  of "tcp-request":
    let request = client.recv(expectedRequest.len, 2000)
    if request != expectedRequest:
      stderr.writeLine("unexpected TCP fixture request")
      quit(1)
    if delayMs > 0:
      sleep(delayMs)
    client.send(response)
  of "tcp-split":
    let midpoint = response.len div 2
    client.send(response[0 ..< midpoint])
    sleep(50)
    client.send(response[midpoint .. ^1])
  of "tcp-silent":
    sleep(delayMs)
  else:
    discard
  if holdMs > 0:
    sleep(holdMs)

proc addUint16(buffer: var string, value: int) =
  buffer.add(char((value shr 8) and 0xff))
  buffer.add(char(value and 0xff))

proc encodedName(name: string): string =
  for label in name.split('.'):
    result.add(char(label.len))
    result.add(label)
  result.add('\0')

proc dnsAnswer(recordType: int, data: string): string =
  result = "\xc0\x0c"
  result.addUint16(recordType)
  result.addUint16(1)
  result.add("\0\0\0\x3c")
  result.addUint16(data.len)
  result.add(data)

proc serveDns(delayMs: int, ipv6: bool) =
  let server = fixtureSocket(ipv6, SOCK_DGRAM, IPPROTO_UDP)
  defer: server.close()
  server.bindAddr(Port(0), fixtureHost(ipv6))
  announce(server.getLocalAddr()[1])

  var query = ""
  var clientHost = ""
  var clientPort: Port
  discard server.recvFrom(query, 65_535, clientHost, clientPort)
  if delayMs > 0:
    sleep(delayMs)
  if query.len < 17:
    return

  var questionEnd = 12
  while questionEnd < query.len and ord(query[questionEnd]) != 0:
    questionEnd += ord(query[questionEnd]) + 1
  if questionEnd + 5 > query.len:
    return
  inc questionEnd
  let recordType = (ord(query[questionEnd]) shl 8) or
    ord(query[questionEnd + 1])
  let question = query[12 ..< questionEnd + 4]
  var answers: seq[string]
  case recordType
  of 1:
    answers.add(dnsAnswer(1, "\xc0\0\x02\x0a"))
    answers.add(dnsAnswer(1, "\xc0\0\x02\x0b"))
  of 28:
    answers.add(dnsAnswer(
      28, "\x20\x01\x0d\xb8\0\0\0\0\0\0\0\0\0\0\0\x10"
    ))
  of 5:
    answers.add(dnsAnswer(5, encodedName("alias.fixture.test")))
  of 15:
    var firstMx = ""
    firstMx.addUint16(10)
    firstMx.add(encodedName("mail1.fixture.test"))
    answers.add(dnsAnswer(15, firstMx))
    var secondMx = ""
    secondMx.addUint16(20)
    secondMx.add(encodedName("mail2.fixture.test"))
    answers.add(dnsAnswer(15, secondMx))
  of 16:
    let firstText = "canary=ready"
    let secondText = "region=eu"
    answers.add(dnsAnswer(16, char(firstText.len) & firstText))
    answers.add(dnsAnswer(16, char(secondText.len) & secondText))
  else:
    discard

  var response = query[0 .. 1]
  response.add("\x81\x80")
  response.addUint16(1)
  response.addUint16(answers.len)
  response.addUint16(0)
  response.addUint16(0)
  response.add(question)
  for answer in answers:
    response.add(answer)
  server.sendTo(clientHost, clientPort, response)

proc serveTls(certFile: string, keyFile: string, ipv6: bool) =
  let context = newContext(
    verifyMode = CVerifyNone,
    certFile = certFile,
    keyFile = keyFile
  )
  let server = fixtureSocket(ipv6)
  defer: server.close()
  context.wrapSocket(server)
  server.setSockOpt(OptReuseAddr, true)
  server.bindAddr(Port(0), fixtureHost(ipv6))
  server.listen()
  announce(server.getLocalAddr()[1])

  var client: owned(Socket)
  server.accept(client)
  client.close()

proc serveHttps(certFile: string, keyFile: string, ipv6: bool) =
  let context = newContext(
    verifyMode = CVerifyNone,
    certFile = certFile,
    keyFile = keyFile
  )
  let server = fixtureSocket(ipv6)
  defer: server.close()
  context.wrapSocket(server)
  server.setSockOpt(OptReuseAddr, true)
  server.bindAddr(Port(0), fixtureHost(ipv6))
  server.listen()
  announce(server.getLocalAddr()[1])

  var client: owned(Socket)
  server.accept(client)
  defer: client.close()
  discard readHttpRequest(client)
  let body = "fixture-ok"
  client.send(
    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n" &
    "Content-Length: " & $body.len & "\r\nConnection: close\r\n\r\n" & body
  )

proc usage() {.noreturn.} =
  stderr.writeLine(
    "usage: local_server <http-ok|http-json|http-missing|webhook-ok|" &
    "webhook-fail|webhook-slow|http-redirect|tcp-banner|tcp-request|tcp-split|tcp-silent|" &
    "udp-echo|dns|tls|https-ok> [--delay-ms=N] [--response=TEXT] " &
    "[--hold-ms=N] [--expected-request=TEXT] [--cert=PATH] [--key=PATH] [--ipv6]"
  )
  quit(2)

when isMainModule:
  var mode = ""
  var delayMs = 0
  var holdMs = 0
  var response = "pong"
  var expectedRequest = "PING\r\n"
  var certFile = ""
  var keyFile = ""
  var ipv6 = false
  for kind, key, value in getopt():
    case kind
    of cmdArgument:
      if mode.len == 0:
        mode = key
      else:
        usage()
    of cmdLongOption, cmdShortOption:
      case key
      of "delay-ms": delayMs = parseInt(value)
      of "hold-ms": holdMs = parseInt(value)
      of "response": response = value
      of "expected-request": expectedRequest = value
      of "cert": certFile = value
      of "key": keyFile = value
      of "ipv6": ipv6 = true
      else: usage()
    of cmdEnd:
      discard

  if mode == "udp-echo":
    serveUdp(response, ipv6)
  elif mode in ["tcp-banner", "tcp-request", "tcp-split", "tcp-silent"]:
    serveTcp(mode, response, expectedRequest, delayMs, holdMs, ipv6)
  elif mode == "dns":
    serveDns(delayMs, ipv6)
  elif mode == "tls" and certFile.len > 0 and keyFile.len > 0:
    serveTls(certFile, keyFile, ipv6)
  elif mode == "https-ok" and certFile.len > 0 and keyFile.len > 0:
    serveHttps(certFile, keyFile, ipv6)
  elif mode == "http-redirect":
    serveHttpRedirect(ipv6, delayMs)
  elif mode in [
    "http-ok", "http-json", "http-missing", "webhook-ok", "webhook-fail",
    "webhook-slow"
  ]:
    serveHttp(mode, delayMs, ipv6)
  else:
    usage()
