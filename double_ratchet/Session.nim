import Crypto/[Chain, C25519]

proc newDoubleRatchet*(
  id: string,
  pair: Curve25519KeyPair,
  remote: Curve25519Key
): KDFRoot =
  newKDFRootChain(pair, remote)
