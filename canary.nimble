# Package

# Keep this literal in sync with CanaryVersion in src/canary_contract.nim.
# Nimble metadata readers reject computed version assignments.
version       = "0.1.3"
author        = "titanomachy"
description   = "A lightweight, standalone service health and uptime monitoring tool."
license       = "MIT"
srcDir        = "src"
binDir        = "build"
bin           = @["canary"]


# Dependencies

requires "nim >= 2.0.0"
requires "confutils >= 0.1.1 & < 0.2.0"
requires "toml_serialization >= 0.2.18 & < 0.3.0"
requires "nim_sqlite"


# Tests

proc buildProcessFixture() =
  exec "nim c --nimcache:build/nimcache-process-worker -o:build/process_worker tests/fixtures/process_worker.nim"

proc buildTestFixtures() =
  buildProcessFixture()
  exec "nim c --nimcache:build/nimcache-fixture -o:build/local_server tests/fixtures/local_server.nim"
  exec "nim c --nimcache:build/nimcache-worker -o:build/state_worker tests/fixtures/state_worker.nim"

proc runUnitTests() =
  buildProcessFixture()
  exec "nim c -r --nimcache:build/nimcache-unit tests/unit/test_unit.nim"

proc runIntegrationTests() =
  buildTestFixtures()
  exec "nim c -r --nimcache:build/nimcache-integration tests/integration/test_integration.nim"

proc runCliTests() =
  exec "nim c --nimcache:build/nimcache-fixture -o:build/local_server tests/fixtures/local_server.nim"
  exec "nim c --nimcache:build/nimcache -o:build/canary src/canary.nim"
  exec "nim c -r --nimcache:build/nimcache-tests tests/cli/test_cli.nim"

proc runDocumentationTests() =
  buildTestFixtures()
  exec "nim c --nimcache:build/nimcache -o:build/canary src/canary.nim"
  exec "nim c -r --nimcache:build/nimcache-docs tests/docs/test_docs.nim"
  exec "sh examples/run-local-demo.sh"

task testCli, "Run command-line black-box tests":
  runCliTests()

task testIntegration, "Run tests against local HTTP, TCP, TLS, UDP, DNS, webhook, and SQLite fixtures":
  runIntegrationTests()

task testDocs, "Check documentation links and run local examples":
  runDocumentationTests()

task test, "Run all tests":
  runUnitTests()
  runIntegrationTests()
  runCliTests()
  runDocumentationTests()

task checkAll, "Run static checks, debug/release builds, and all tests":
  exec "nim check --styleCheck:error --nimcache:build/nimcache-check src/canary.nim"
  exec "nim check --styleCheck:error --nimcache:build/nimcache-unit-check tests/unit/test_unit.nim"
  exec "nim check --styleCheck:error --nimcache:build/nimcache-integration-check tests/integration/test_integration.nim"
  exec "nim check --styleCheck:error --nimcache:build/nimcache-cli-check tests/cli/test_cli.nim"
  exec "nim check --styleCheck:error --nimcache:build/nimcache-docs-check tests/docs/test_docs.nim"
  exec "nim check --styleCheck:error --nimcache:build/nimcache-fixture-check tests/fixtures/local_server.nim"
  exec "nim check --styleCheck:error --nimcache:build/nimcache-worker-check tests/fixtures/state_worker.nim"
  exec "nim check --styleCheck:error --nimcache:build/nimcache-process-worker-check tests/fixtures/process_worker.nim"
  exec "nim c --nimcache:build/nimcache-debug -o:build/canary-debug src/canary.nim"
  exec "nim c -d:release --nimcache:build/nimcache-release -o:build/canary-release src/canary.nim"
  runUnitTests()
  runIntegrationTests()
  runCliTests()
  runDocumentationTests()

when defined(windows):
  task testWindows, "Run Windows static, build, and compatibility checks":
    exec "nim check --styleCheck:error --nimcache:build/nimcache-check src/canary.nim"
    exec "nim check --styleCheck:error --nimcache:build/nimcache-unit-check tests/unit/test_unit.nim"
    exec "nim check --styleCheck:error --nimcache:build/nimcache-integration-check tests/integration/test_integration.nim"
    exec "nim check --styleCheck:error --nimcache:build/nimcache-docs-check tests/docs/test_docs.nim"
    exec "nim check --styleCheck:error --nimcache:build/nimcache-fixture-check tests/fixtures/local_server.nim"
    exec "nim check --styleCheck:error --nimcache:build/nimcache-worker-check tests/fixtures/state_worker.nim"
    exec "nim check --styleCheck:error --nimcache:build/nimcache-process-worker-check tests/fixtures/process_worker.nim"
    exec "nim check --styleCheck:error --nimcache:build/nimcache-windows-check tests/windows/test_windows.nim"
    exec "nim c --nimcache:build/nimcache-debug -o:build/canary src/canary.nim"
    exec "nim c -d:release --nimcache:build/nimcache-release -o:build/canary-release src/canary.nim"
    runUnitTests()
    runIntegrationTests()
    exec "nim c -r --nimcache:build/nimcache-windows tests/windows/test_windows.nim"
    exec "nim c -r --nimcache:build/nimcache-docs tests/docs/test_docs.nim"
