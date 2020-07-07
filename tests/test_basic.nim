#import random
import unittest

import ../double_ratchet

suite "Test Basic Encrypting/Decrypting":
  test "Hello, World":
    #[
    var sharedKey: array[32, byte]
    for b in 0 ..< sharedKey.len:
      sharedKey[b] = byte(rand(255))
    ]#

    var
      alicePair: DHPair = generateDH()
      bobPair: DHPair = generateDH()
      bob: KDFRoot = newDoubleRatchet("bob-session-id", bobPair, alicePair.pubkey)
      alice: KDFRoot = newDoubleRatchet("alice-session-id", alicePair, bobPair.pubkey)

      msg: seq[byte] = cast[seq[byte]]("Hello, World!")

    check msg == bob.decrypt(alice.encrypt(msg, @[]), @[])
