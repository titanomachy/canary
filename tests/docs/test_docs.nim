import std/[os, strutils, unittest]

const ProjectRoot = currentSourcePath().parentDir.parentDir.parentDir

proc markdownFiles(): seq[string] =
  for name in ["README.md", "CHANGELOG.md", "CONTRIBUTING.md", "TODO.md"]:
    let path = ProjectRoot / name
    # TODO.md is a local roadmap in existing worktrees and is intentionally not
    # part of release archives. Validate it when present without requiring it.
    if fileExists(path):
      result.add(path)
  for directory in [ProjectRoot / "docs", ProjectRoot / "examples"]:
    for path in walkDirRec(directory):
      if path.endsWith(".md"):
        result.add(path)

proc localLinkTargets(markdown: string): seq[string] =
  var offset = 0
  while true:
    let start = markdown.find("](", offset)
    if start < 0:
      break
    let finish = markdown.find(')', start + 2)
    if finish < 0:
      break
    var target = markdown[start + 2 ..< finish].strip()
    if target.startsWith("<") and target.endsWith(">"):
      target = target[1 .. ^2]
    let fragment = target.find('#')
    if fragment >= 0:
      target = target[0 ..< fragment]
    if target.len > 0 and not target.contains("://") and
        not target.startsWith("mailto:"):
      result.add(target)
    offset = finish + 1

suite "documentation contract":
  test "all local Markdown links resolve":
    for document in markdownFiles():
      check fileExists(document)
      for target in localLinkTargets(readFile(document)):
        let resolved = absolutePath(target, document.parentDir)
        check fileExists(resolved) or dirExists(resolved)

  test "README stays an entry point instead of a complete manual":
    let readme = readFile(ProjectRoot / "README.md")
    check readme.splitLines().len <= 250
    for requiredLink in [
      "docs/checks.md", "docs/notifications.md", "docs/state-machine.md",
      "docs/configuration.md", "docs/development.md", "examples/README.md",
      "CONTRIBUTING.md"
    ]:
      check requiredLink in readme

  test "examples are credential-free and include scheduler recipes":
    let exampleConfig = readFile(ProjectRoot / "examples" / "canary.toml")
    check "hooks.example.invalid" in exampleConfig or
      "# notify" in exampleConfig
    check fileExists(ProjectRoot / "examples" / "run-local-demo.sh")
    check fileExists(ProjectRoot / "examples" / "metronome-web.md")
    check fileExists(ProjectRoot / "examples" / "canary.cron")
    check fileExists(
      ProjectRoot / "examples" / "systemd" / "canary-api.service"
    )
    check fileExists(
      ProjectRoot / "examples" / "systemd" / "canary-api.timer"
    )
