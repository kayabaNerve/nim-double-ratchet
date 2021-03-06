mode = ScriptMode.Verbose

version       = "0.1.0"
author        = "Status Research & Development GmbH"
description   = "Implementation of the Double Ratchet protocol, as specified by Status."
license       = "MIT"
skipDirs      = @["tests"]

requires "nim >= 1.2.0",
         "stew",
         "nimcrypto",
         "secp256k1",
         "libp2p"

task test, "Run all tests":
  exec "nim c -r tests/test_all"
