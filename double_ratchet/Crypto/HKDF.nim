import nimcrypto

const
  HASH_LEN*: int = 32
  HASH_BITS*: int = HASH_LEN * 8
  MACD_LEN*: int = HASH_LEN * 3

#HKDF following https://tools.ietf.org/html/rfc5869.
proc hkdf*(
  secret: ptr byte,
  salt: ptr byte,
  info: ptr byte
): array[MACD_LEN, byte] =
  var
    last: MDigest[HASH_BITS] = sha256.hmac(secret, uint(HASH_LEN), nil, 0'u)
    hmacCtx: HMAC[sha256]
  for i in 0 ..< 3:
    hmacCtx.init(secret, uint(HASH_LEN))
    hmacCtx.update(last.data)
    hmacCtx.update(info, uint(HASH_LEN))
    hmacCtx.update([byte(i + 1)])
    last = hmacCtx.finish()
    hmacCtx.clear()

    var salted: MDigest[HASH_BITS] = sha256.hmac(
      salt,
      uint(HASH_LEN),
      addr last.data[0],
      uint(HASH_LEN)
    )
    copyMem(
      addr result[i * HASH_LEN],
      addr salted.data[0],
      uint(HASH_LEN)
    )
