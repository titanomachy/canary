switch("define", "ssl")
switch("define", "confutilsNoColors")
switch("outDir", "build")
when defined(windows) and defined(amd64):
  # Nim's default Windows names target OpenSSL 1.1. Current supported Windows
  # dependencies expose the OpenSSL 3 x64 DLL names instead.
  switch("define", "sslVersion=3-x64")
# begin Nimble config (version 2)
when withDir(thisDir(), system.fileExists("nimble.paths")):
  include "nimble.paths"
# end Nimble config
