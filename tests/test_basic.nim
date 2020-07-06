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
      alicePair: Curve25519KeyPair = newCurve25519KeyPair()
      bobPair: Curve25519KeyPair = newCurve25519KeyPair()
      bob: KDFRoot = newDoubleRatchet("bob-session-id", bobPair, alicePair.pub)
      alice: KDFRoot = newDoubleRatchet("alice-session-id", alicePair, bobPair.pub)

      msg: seq[byte] = cast[seq[byte]]("Hello, World!")

    doAssert(msg == bob.decrypt(alice.encrypt(msg, @[]), @[]))
