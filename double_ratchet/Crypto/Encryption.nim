import nimcrypto
import libp2p/crypto/hkdf

import DH

const
  IV_LEN: int = 16
  IV_AND_SIG_LEN: int = IV_LEN + 32

type
  IV = array[IV_LEN, byte]
  DecryptionError* = object of CatchableError

var
  CHAIN_INFO: seq[byte] = cast[seq[byte]]("pcwSByyx2CRdryCffXJwy7xgVZWtW5Sh")
  BLANK_SALT: array[0, byte] = []

template deriveEncKeys(secret: array[32, byte]) =
  var
    macd: array[3, array[32, byte]]
    encKey {.inject.}: array[32, byte]
    authKey {.inject.}: array[32, byte]
    iv {.inject.}: IV
  sha256.hkdf(BLANK_SALT, secret, CHAIN_INFO, macd)
  copyMem(addr encKey[0], addr macd[0], 32)
  copyMem(addr authKey[0], addr macd[1], 32)
  copyMem(addr iv[0], addr macd[2], IV_LEN)

proc calculateSignature(
  authKey: array[32, byte],
  cipher: ptr byte,
  cipherLen: int,
  associated: seq[byte]
): array[32, byte] =
  var hmac: HMAC[sha256]
  hmac.init(authKey)
  hmac.update(associated)
  hmac.update(cipher, uint(cipherLen))
  result = hmac.finish().data
  hmac.clear()

proc encryptByKey*(
  sendKey: array[32, byte],
  data: seq[byte],
  associated: seq[byte]
): seq[byte] =
  deriveEncKeys(sendKey)

  result = newSeq[byte](IV_LEN + data.len + 32)
  copyMem(addr result[0], addr iv[0], iv.len)

  if data.len != 0:
    var ctx: CTR[aes256]
    ctx.init(encKey, iv)
    ctx.encrypt(unsafeAddr data[0], addr result[iv.len], uint(data.len))
    ctx.clear()
  var sig: array[32, byte] = calculateSignature(
    authKey,
    addr result[0],
    result.len - 32,
    associated
  )
  copyMem(
    addr result[^32],
    addr sig[0],
    32
  )

proc decryptByKey*(
  recvKey: array[32, byte],
  data: seq[byte],
  associated: seq[byte]
): seq[byte] =
  if data.len < (IV_AND_SIG_LEN):
    raise newException(DecryptionError, "Invalid data; a full IV/signature was not provided.")
  deriveEncKeys(recvKey)

  if calculateSignature(
    authKey,
    unsafeAddr data[0],
    data.len - 32,
    associated
  ) != data[data.len - 32 ..< data.len]:
    raise newException(DecryptionError, "Invalid signature.")

  if data.len == (IV_AND_SIG_LEN):
    return

  result = newSeq[byte](data.len - (IV_AND_SIG_LEN))
  var ctx: CTR[aes256]
  ctx.init(encKey, data[0 ..< IV_LEN])
  ctx.decrypt(unsafeAddr data[IV_LEN], addr result[0], uint(data.len - IV_AND_SIG_LEN))
  ctx.clear()
