const
  ## CLI version. Keep this in sync with the literal in canary.nimble; Nimble
  ## metadata readers require the manifest assignment to be a string literal.
  CanaryVersion* = "0.1.3"

  ## Stable CLI exit-code contract.
  ExitUp* = 0
  ExitDown* = 1
  ExitConfigError* = 2
  ExitInternalError* = 3
