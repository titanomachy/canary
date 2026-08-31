const
  ## Canonical package and CLI version. The Nimble manifest includes this file
  ## from src/ in a checkout or from the flattened package root after install.
  CanaryVersion* = "0.1.0"

  ## Stable CLI exit-code contract.
  ExitUp* = 0
  ExitDown* = 1
  ExitConfigError* = 2
  ExitInternalError* = 3
