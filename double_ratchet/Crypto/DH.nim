import secp256k1
import libp2p/crypto/secp
export secp

type
  DHPublic* = secp.SkPublicKey
  DHPair* = secp.SkKeyPair

proc generateDH*(): DHPair {.inline.} =
  DHPair.random().get()

proc diffieHellman*(
  pair: DHPair,
  theirPub: DHPublic
): seq[byte] {.inline.} =
  @(ecdhRaw(secp256k1.SkSecretKey(pair.seckey), secp256k1.SkPublicKey(theirPub)).get().data)
