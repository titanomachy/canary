import std/[net, os, strutils]

type DnsResolverProvider* = proc(): tuple[host: string, port: int] {.closure.}

proc hostsFilePath*(): string =
  when defined(windows):
    getEnv("SystemRoot", r"C:\Windows") / "System32" / "drivers" / "etc" / "hosts"
  else:
    "/etc/hosts"

proc resolverFromConfig*(content: string): string =
  ## Linux resolver files may contain comments and scoped IPv6 addresses.
  for line in content.splitLines():
    let components = line.split('#', maxsplit = 1)[0].splitWhitespace()
    if components.len >= 2 and components[0] == "nameserver":
      try:
        discard parseIpAddress(components[1].split('%')[0])
        return components[1]
      except ValueError:
        discard

when defined(windows):
  # Use the SDK's adapter structures so pointer sizes and unions stay native.
  when defined(vcc):
    {.passl: "iphlpapi.lib ws2_32.lib".}
  else:
    {.passl: "-liphlpapi -lws2_32".}
  {.emit: """
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #include <iphlpapi.h>
  #include <stdlib.h>
  static int canarySystemDnsResolver(char *host, int capacity) {
    ULONG size = 15000;
    IP_ADAPTER_ADDRESSES *adapters = NULL;
    ULONG status = ERROR_BUFFER_OVERFLOW;
    for (int attempt = 0; attempt < 3 && status == ERROR_BUFFER_OVERFLOW; ++attempt) {
      free(adapters);
      adapters = (IP_ADAPTER_ADDRESSES *)malloc(size);
      if (!adapters) return 0;
      status = GetAdaptersAddresses(AF_UNSPEC,
        GAA_FLAG_SKIP_UNICAST | GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST,
        NULL, adapters, &size);
    }
    if (status == NO_ERROR) {
      for (IP_ADAPTER_ADDRESSES *adapter = adapters; adapter; adapter = adapter->Next) {
        if (adapter->OperStatus != IfOperStatusUp) continue;
        for (IP_ADAPTER_DNS_SERVER_ADDRESS *dns = adapter->FirstDnsServerAddress;
             dns; dns = dns->Next) {
          if (!dns->Address.lpSockaddr) continue;
          if (getnameinfo(dns->Address.lpSockaddr, dns->Address.iSockaddrLength,
                          host, capacity, NULL, 0, NI_NUMERICHOST) == 0) {
            free(adapters);
            return 1;
          }
        }
      }
    }
    free(adapters);
    return 0;
  }
  """.}
  proc nativeResolver(host: cstring, capacity: cint): cint {.
    cdecl, importc: "canarySystemDnsResolver", nodecl.}

proc systemDnsResolver*(): tuple[host: string, port: int] =
  result.port = 53
  when defined(windows):
    var host: array[128, char]
    if nativeResolver(cast[cstring](addr host[0]), host.len.cint) == 1:
      result.host = $cast[cstring](addr host[0])
  else:
    try:
      result.host = resolverFromConfig(readFile("/etc/resolv.conf"))
    except IOError, OSError:
      discard
