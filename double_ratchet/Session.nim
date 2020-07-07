import Crypto/[Chain, DH]

proc newDoubleRatchet*(
  id: string,
  sharedKey: array[32, byte],
  pair: DHPair,
  remote: DHPublic
): KDFRoot =
  newKDFRootChain(pair, remote)
