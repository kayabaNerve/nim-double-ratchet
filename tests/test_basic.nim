import random
import unittest

import ../double_ratchet

suite "Test Basic Encrypting/Decrypting":
  test "Hello, World":
    var sharedKey: array[32, byte]
    for b in 0 ..< sharedKey.len:
      sharedKey[b] = byte(rand(255))

    var
      bobPair: DHPair = generateDH()
      bob: DoubleRatchet = newDoubleRatchet(sharedKey, bobPair)
      alice: DoubleRatchet = newRemoteDoubleRatchet(sharedKey, bobPair.pubkey)

      msg: seq[byte] = cast[seq[byte]]("Hello, World!")

    check msg == bob.decrypt(alice.encrypt(msg, @[]), @[])
