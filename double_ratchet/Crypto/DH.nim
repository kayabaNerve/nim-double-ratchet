import secp256k1
import libp2p/crypto/secp
export secp

type
  DRResult* = SkResult
  DHPublic* = secp.SkPublicKey
  DHPair* = secp.SkKeyPair

proc generateDH*(): DRResult[DHPair] {.inline.} =
  DHPair.random()

proc diffieHellman*(
  pair: DHPair,
  theirPub: DHPublic
): DRResult[seq[byte]] {.inline.} =
  ok(@((? ecdhRaw(secp256k1.SkSecretKey(pair.seckey), secp256k1.SkPublicKey(theirPub))).data))
