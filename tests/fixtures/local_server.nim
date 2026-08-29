import std/[net, os, parseopt, strutils]

proc announce(port: Port) =
  stdout.writeLine($port)
  stdout.flushFile()

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

proc serveHttp(mode: string, delayMs: int) =
  let server = newSocket()
  defer: server.close()
  server.setSockOpt(OptReuseAddr, true)
  server.bindAddr(Port(0), "127.0.0.1")
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
  case mode
  of "http-ok":
    discard
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
                 "Content-Type: text/plain\r\n" &
                 "Content-Length: " & $body.len & "\r\n" &
                 "Connection: close\r\n\r\n" & body
  client.send(response)

proc serveUdp(response: string) =
  let server = newSocket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
  defer: server.close()
  server.bindAddr(Port(0), "127.0.0.1")
  announce(server.getLocalAddr()[1])

  var payload = ""
  var clientHost = ""
  var clientPort: Port
  discard server.recvFrom(payload, 65_535, clientHost, clientPort)
  server.sendTo(clientHost, clientPort, response)

proc serveTls(certFile: string, keyFile: string) =
  let context = newContext(
    verifyMode = CVerifyNone,
    certFile = certFile,
    keyFile = keyFile
  )
  let server = newSocket()
  defer: server.close()
  context.wrapSocket(server)
  server.setSockOpt(OptReuseAddr, true)
  server.bindAddr(Port(0), "127.0.0.1")
  server.listen()
  announce(server.getLocalAddr()[1])

  var client: owned(Socket)
  server.accept(client)
  client.close()

proc usage() {.noreturn.} =
  stderr.writeLine(
    "usage: local_server <http-ok|http-missing|webhook-ok|" &
    "webhook-fail|webhook-slow|udp-echo|tls> [--delay-ms=N] " &
    "[--response=TEXT] [--cert=PATH] [--key=PATH]"
  )
  quit(2)

when isMainModule:
  var mode = ""
  var delayMs = 0
  var response = "pong"
  var certFile = ""
  var keyFile = ""
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
      of "response": response = value
      of "cert": certFile = value
      of "key": keyFile = value
      else: usage()
    of cmdEnd:
      discard

  if mode == "udp-echo":
    serveUdp(response)
  elif mode == "tls" and certFile.len > 0 and keyFile.len > 0:
    serveTls(certFile, keyFile)
  elif mode in [
    "http-ok", "http-missing", "webhook-ok", "webhook-fail",
    "webhook-slow"
  ]:
    serveHttp(mode, delayMs)
  else:
    usage()
