#This file won't compile if it's named Curve25519.
#Nim will fail to resolve the Curve25519 type below.

import libp2p/crypto/curve25519
export Curve25519Key

const KEY_SIG_LEN*: int = 32

type Curve25519KeyPair* = object
  priv*: Curve25519Key
  pub*: Curve25519Key

proc newCurve25519KeyPair*(): Curve25519KeyPair =
  result.priv = Curve25519Key.random().get()
  result.pub = result.priv.public()

proc diffieHellman*(
  priv: Curve25519Key,
  theirPub: Curve25519Key
): Curve25519Key {.inline.} =
  Curve25519.mul(result, priv, theirPub)
