import nimcrypto

const
  HASH_LEN*: int = 32
  HASH_BITS*: int = HASH_LEN * 8
  MACD_LEN*: int = HASH_LEN * 3

#HKDF following https://tools.ietf.org/html/rfc5869.
proc hkdf*(
  secret: ptr byte,
  salt: ptr byte,
  info: ptr byte,
  #Used by the tests to test vectors which don't conform to the DR sizing.
  secretLen: int = HASH_LEN,
  saltLen: int = HASH_LEN,
  infoLen: int = HASH_LEN
): array[MACD_LEN, byte] =
  var
    prk: MDigest[HASH_BITS] = sha256.hmac(salt, uint(saltLen), secret, uint(secretLen))
    last: MDigest[HASH_BITS]
  for i in 0 ..< 3:
    var key: seq[byte]
    if i != 0:
      key = newSeq[byte](HASH_LEN + infoLen + 1)
      copyMem(addr key[0], addr last.data[0], HASH_LEN)
      copyMem(addr key[HASH_LEN], info, infoLen)
    else:
      key = newSeq[byte](infoLen + 1)
      copyMem(addr key[0], info, infoLen)
    key[^1] = byte(i + 1)

    last = sha256.hmac(addr prk.data[0], uint(HASH_LEN), addr key[0], uint(key.len))
    copyMem(addr result[i * HASH_LEN], addr last.data[0], uint(HASH_LEN))
