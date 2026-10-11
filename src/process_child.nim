import std/[os, osproc, oserrors]

when defined(windows):
  import winlean

  {.emit: """
  #include <windows.h>
  #include <stdint.h>
  static int canaryConfigureJob(intptr_t job) {
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits = {0};
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    return SetInformationJobObject((HANDLE)job, JobObjectExtendedLimitInformation,
                                   &limits, sizeof(limits));
  }
  """.}
  proc configureJob(job: Handle): cint {.
    cdecl, importc: "canaryConfigureJob", nodecl.}
  proc createJobObject(attributes, name: pointer): Handle {.
    stdcall, dynlib: "kernel32", importc: "CreateJobObjectW".}
  proc assignProcess(job, process: Handle): WINBOOL {.
    stdcall, dynlib: "kernel32", importc: "AssignProcessToJobObject".}
  proc terminateJob(job: Handle, exitCode: cuint): WINBOOL {.
    stdcall, dynlib: "kernel32", importc: "TerminateJobObject".}

  type ManagedChild* = ref object
    process, job, input, output: Handle

  proc close*(child: ManagedChild) =
    if child.job != 0:
      discard closeHandle(child.job)
      child.job = 0
    if child.input != 0:
      discard closeHandle(child.input)
    for handle in [child.output, child.process]:
      if handle != 0:
        discard closeHandle(handle)
    child.input = 0
    child.output = 0
    child.process = 0

  proc startChild*(command: string, args: seq[string]): ManagedChild =
    new(result)
    var childInput, childOutput: Handle
    var information: PROCESS_INFORMATION
    var attributes = SECURITY_ATTRIBUTES(
      nLength: sizeof(SECURITY_ATTRIBUTES).int32, bInheritHandle: 1
    )
    var succeeded = false
    defer:
      for handle in [childInput, childOutput, information.hThread]:
        if handle != 0:
          discard closeHandle(handle)
      if not succeeded:
        if result.process != 0:
          discard terminateProcess(result.process, 137)
        result.close()
    result.job = createJobObject(nil, nil)
    if result.job == 0 or configureJob(result.job) == 0:
      raiseOSError(osLastError())
    if createPipe(childInput, result.input, attributes, 0) == 0 or
        createPipe(result.output, childOutput, attributes, 0) == 0:
      raiseOSError(osLastError())
    if setHandleInformation(result.input, 1, 0) == 0 or
        setHandleInformation(result.output, 1, 0) == 0:
      raiseOSError(osLastError())
    var startup = STARTUPINFO(
      cb: sizeof(STARTUPINFO).int32, dwFlags: STARTF_USESTDHANDLES,
      hStdInput: childInput, hStdOutput: childOutput, hStdError: childOutput
    )
    let executable = findExe(command)
    if executable.len == 0:
      raise newException(OSError, "command executable could not be found")
    var commandLine = quoteShellWindows(executable)
    for argument in args:
      commandLine.add(" " & quoteShellWindows(argument))
    var wideCommand = newWideCString(commandLine)
    let wideExecutable = newWideCString(executable)
    # Assign the suspended process before it can spawn any descendants.
    const CreateSuspended = 4'i32
    if createProcessW(wideExecutable, wideCommand, nil, nil, 1,
        NORMAL_PRIORITY_CLASS or CREATE_UNICODE_ENVIRONMENT or
        CREATE_NO_WINDOW or CreateSuspended,
        nil, nil, startup, information) == 0:
      raiseOSError(osLastError())
    result.process = information.hProcess
    if assignProcess(result.job, result.process) == 0 or
        resumeThread(information.hThread) == -1:
      raiseOSError(osLastError())
    succeeded = true

  proc sendInput*(child: ManagedChild, input: string) =
    var offset = 0
    while offset < input.len:
      var count: int32
      if writeFile(child.input, unsafeAddr input[offset],
          (input.len - offset).int32, addr count, nil) == 0:
        raiseOSError(osLastError())
      if count == 0:
        raise newException(IOError, "process input pipe closed")
      inc offset, count.int
    discard closeHandle(child.input)
    child.input = 0

  proc running*(child: ManagedChild): bool =
    let status = waitForSingleObject(child.process, 0)
    if status == -1:
      raiseOSError(osLastError())
    status == WAIT_TIMEOUT

  proc exitCode*(child: ManagedChild): int =
    var code: int32
    if getExitCodeProcess(child.process, code) == 0:
      raiseOSError(osLastError())
    code.int

  proc killTree*(child: ManagedChild) =
    if terminateJob(child.job, 137) == 0:
      raiseOSError(osLastError())

  proc readAvailable*(child: ManagedChild): tuple[data: string, eof: bool] =
    var available: int32
    if not peekNamedPipe(child.output, lpTotalBytesAvail = addr available):
      if osLastError().int == 109: # ERROR_BROKEN_PIPE
        return ("", true)
      raiseOSError(osLastError())
    if available == 0:
      return
    result.data = newString(min(available.int, 4096))
    var count: int32
    if readFile(child.output, addr result.data[0], result.data.len.int32,
                addr count, nil) == 0:
      raiseOSError(osLastError())
    result.data.setLen(count.int)
else:
  import std/[posix, streams]

  type ManagedChild* = ref object
    process: Process

  proc startChild*(command: string, args: seq[string]): ManagedChild =
    let process = startProcess(
      command, args = args, options = {poUsePath, poStdErrToStdOut, poDaemon}
    )
    new(result)
    result.process = process
    let fd = process.outputHandle().cint
    if fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) or O_NONBLOCK) < 0:
      process.kill()
      discard process.waitForExit()
      process.close()
      raiseOSError(osLastError())

  proc sendInput*(child: ManagedChild, input: string) =
    let stream = child.process.inputStream()
    if input.len > 0:
      stream.write(input)
    stream.close()

  proc running*(child: ManagedChild): bool = child.process.running()
  proc exitCode*(child: ManagedChild): int = child.process.peekExitCode()

  proc killTree*(child: ManagedChild) =
    if posix.kill(-child.process.processID().Pid, SIGKILL) != 0 and errno != ESRCH:
      raiseOSError(osLastError())

  proc close*(child: ManagedChild) =
    # A successful script may have left descendants holding its output pipe.
    child.killTree()
    for attempt in 0 ..< 100:
      if not child.process.running():
        break
      sleep(1)
    if not child.process.running():
      discard child.process.waitForExit()
    child.process.close()

  proc readAvailable*(child: ManagedChild): tuple[data: string, eof: bool] =
    result.data = newString(4096)
    let count = posix.read(
      child.process.outputHandle().cint, addr result.data[0], result.data.len
    )
    if count >= 0:
      result.data.setLen(count)
      result.eof = count == 0
    elif errno in [EAGAIN, EWOULDBLOCK, EINTR]:
      result.data = ""
    else:
      raiseOSError(osLastError())
