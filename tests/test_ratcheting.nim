import random
import strutils
import unittest

import ../double_ratchet

proc newMsgAndAd(msg: var seq[byte], ad: var seq[byte]) =
  msg.setLen(rand(1024))
  for b in 0 ..< msg.len:
    msg[b] = byte(rand(255))
  ad.setLen(rand(255))
  for b in 0 ..< ad.len:
    ad[b] = byte(rand(255))

suite "Ratcheting":
  setup:
    var sharedKey: array[32, byte]
    for b in 0 ..< sharedKey.len:
      sharedKey[b] = byte(rand(255))

    var
      bobPair: DHPair = generateDH()
      bob: DoubleRatchet = newDoubleRatchet(sharedKey, bobPair)
      alice: DoubleRatchet = newRemoteDoubleRatchet(sharedKey, bobPair.pubkey)

  test "Basic ratchet":
    var msg: seq[byte] = cast[seq[byte]]("Hello, World!")
    check msg == bob.decrypt(alice.encrypt(msg, @[]), @[])

  test "Linear balanced fuzz":
    for _ in 0 ..< 2000:
      var
        msg: seq[byte]
        ad: seq[byte]

      newMsgAndAd(msg, ad)
      check msg == bob.decrypt(alice.encrypt(msg, ad), ad)
      newMsgAndAd(msg, ad)
      check msg == alice.decrypt(bob.encrypt(msg, ad), ad)

  test "Linear unbalanced fuzz":
    for _ in 0 ..< 2000:
      var
        msg: seq[byte]
        ad: seq[byte]

      if rand(1) == 1:
        newMsgAndAd(msg, ad)
        check msg == bob.decrypt(alice.encrypt(msg, ad), ad)
      if rand(2) == 1:
        newMsgAndAd(msg, ad)
        check msg == alice.decrypt(bob.encrypt(msg, ad), ad)

  test "Gap fuzz":
    var
      msg: seq[byte]
      ad: seq[byte]

      msgs: seq[seq[byte]]
      ads: seq[seq[byte]]
      gaps: seq[Message]

    for _ in 0 ..< 2:
      for _ in 0 ..< 1100:
        #Perform a random amount of linear messages.
        for _ in 0 ..< (rand(50) + 1):
          newMsgAndAd(msg, ad)
          check msg == bob.decrypt(alice.encrypt(msg, ad), ad)

        #Skip a random amount of messages.
        for _ in 0 ..< (rand(998) + 1):
          newMsgAndAd(msg, ad)
          #Save a small amount of messages to make sure we can decrypt gap messages.
          if rand(5) == 0:
            msgs.add(msg)
            ads.add(ad)
            gaps.add(alice.encrypt(msg, ad))
          else:
            discard alice.encrypt(msg, ad)

        #Verify Bob can decrypt this next message.
        newMsgAndAd(msg, ad)
        check msg == bob.decrypt(alice.encrypt(msg, ad), ad)

        #Decrypt the gap messages.
        for i in 0 ..< gaps.len:
          check msgs[i] == bob.decrypt(gaps[i], ads[i])

        msgs = @[]
        ads = @[]
        gaps = @[]

      #Tuple swap Alice and Bob to ensure assymetric equality.
      (alice, bob) = (bob, alice)

  test "Vectorized":
    sharedKey = [byte(82), 79, 29, 3, 209, 216, 30, 148, 160, 153, 4, 39, 54, 212, 11, 217, 104, 27, 134, 115, 33, 68, 63, 245, 138, 69, 104, 226, 116, 219, 216, 59]
    var remote: DHPublic = DHPublic.init("03ef8a992e0b71878837c616d154d3fab2eacf4dfea35d81e56c74263df9c45bf1").get()
    alice = newRemoteDoubleRatchet(sharedKey, remote)

    var ciphers: seq[seq[byte]] = @[
      @[byte(17), 146, 65, 113, 27, 249, 63, 48, 225, 2, 121, 76, 11, 250, 59, 3, 14, 240, 227, 197, 201, 28, 48, 123, 18, 174, 17, 193, 0, 91, 88, 146, 150, 21, 41, 123, 191, 18, 113, 10, 76, 171, 93, 124, 223, 164, 56, 132, 137, 137, 51, 96, 142, 188, 159, 232, 238, 61, 204, 171],
      @[byte(161), 230, 175, 150, 218, 9, 214, 101, 124, 59, 120, 234, 233, 254, 176, 162, 114, 55, 75, 65, 150, 164, 72, 166, 237, 225, 17, 34, 104, 21, 102, 46, 159, 78, 2, 106, 187, 90, 219, 195, 190, 166, 70, 229, 72, 144, 190, 131, 127, 20, 2, 96, 233, 64, 160, 130, 99, 34, 0, 79],
      @[byte(85), 41, 162, 212, 137, 154, 143, 121, 229, 190, 83, 126, 221, 224, 18, 16, 8, 75, 191, 22, 18, 28, 41, 10, 33, 32, 234, 62, 1, 141, 92, 15, 254, 143, 2, 35, 193, 25, 108, 141, 89, 48, 247, 143, 62, 12, 217, 197, 231, 19, 234, 42, 216, 78, 156, 110, 32, 171, 72, 154],
      @[byte(211), 69, 80, 73, 11, 123, 10, 33, 156, 139, 107, 91, 74, 28, 126, 222, 163, 167, 241, 40, 134, 208, 43, 172, 94, 71, 96, 185, 221, 91, 103, 33, 168, 89, 179, 232, 63, 143, 139, 131, 64, 30, 52, 223, 123, 252, 26, 168, 105, 34, 217, 23, 31, 3, 182, 137, 146, 178, 180, 103],
      @[byte(154), 97, 140, 162, 54, 123, 48, 193, 7, 254, 172, 84, 70, 124, 233, 138, 233, 233, 62, 228, 230, 158, 119, 202, 33, 233, 40, 192, 66, 245, 203, 64, 53, 210, 7, 128, 201, 173, 43, 233, 76, 126, 0, 5, 185, 44, 174, 180, 124, 201, 31, 145, 46, 191, 209, 26, 134, 163, 113, 201]
    ]
    for c in 0 ..< ciphers.len:
      check cast[seq[byte]]("From Bob: " & $(c + 1) & "!") == alice.decrypt(
        Message(
          header: Header(
            n: uint32(c),
            pn: 0,
            dh: cast[seq[byte]](parseHexStr("03ef8a992e0b71878837c616d154d3fab2eacf4dfea35d81e56c74263df9c45bf1"))
          ),
          ciphertext: ciphers[c]
        ),
        @[]
      )
