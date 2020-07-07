import Crypto/[Chain, DH]

proc newDoubleRatchet*(
  id: string,
  pair: DHPair,
  remote: DHPublic
): KDFRoot =
  newKDFRootChain(pair, remote)
