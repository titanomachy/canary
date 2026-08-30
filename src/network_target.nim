import std/[nativesockets, net, options, strutils]

type NetworkEndpoint* = object
  ## One numeric address returned by the system resolver, together with the
  ## socket family needed to reach it. Keeping resolution separate from socket
  ## creation lets TCP and UDP try both IPv4 and IPv6 addresses.
  address*: string
  domain*: Domain

proc normalizedNetworkHost*(host: string): string =
  ## Host arguments accept either `::1` or `[::1]`; socket APIs require the
  ## unbracketed form. Brackets remain mandatory only where a port is attached.
  if host.len >= 2 and host.startsWith('[') and host.endsWith(']'):
    host[1 .. ^2]
  else:
    host

proc formatHostPort*(host: string, port: int): string =
  ## Avoid ambiguous output such as `2001:db8::1:443`.
  let normalized = normalizedNetworkHost(host)
  if ':' in normalized:
    "[" & normalized & "]:" & $port
  else:
    normalized & ":" & $port

proc resolveNetworkEndpoints*(host: string, port: int, sockType: SockType,
                              protocol: Protocol): seq[NetworkEndpoint] =
  ## Resolve all usable IP families in system order. Numeric addresses are
  ## returned so each attempt uses the exact family selected here.
  let normalized = normalizedNetworkHost(host)
  let addresses = getAddrInfo(
    normalized, Port(port), AF_UNSPEC, sockType, protocol
  )
  defer: freeAddrInfo(addresses)

  var current = addresses
  while current != nil:
    let knownDomain = current.ai_family.toKnownDomain()
    if knownDomain.isSome and knownDomain.get() in {AF_INET, AF_INET6}:
      let endpoint = NetworkEndpoint(
        address: getAddrString(current.ai_addr),
        domain: knownDomain.get()
      )
      var duplicate = false
      for existing in result:
        if existing.address == endpoint.address and
            existing.domain == endpoint.domain:
          duplicate = true
          break
      if not duplicate:
        result.add(endpoint)
    current = current.ai_next

  if result.len == 0:
    raise newException(IOError, "host did not resolve to an IPv4 or IPv6 address")
