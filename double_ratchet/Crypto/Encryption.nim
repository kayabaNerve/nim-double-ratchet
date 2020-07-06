import nimcrypto

import C25519
import HKDF

const
  IV_LEN: int = 16
  IV_AND_SIG_LEN: int = IV_LEN + KEY_SIG_LEN

type
  IV = array[IV_LEN, byte]
  DecryptionError* = object of CatchableError

var
  CHAIN_INFO_STR: string = "pcwSByyx2CRdryCffXJwy7xgVZWtW5Sh"
  CHAIN_INFO: ptr byte = cast[ptr byte](addr CHAIN_INFO_STR[0])
  BLANK_SALT: ptr byte = cast[ptr byte](alloc0(HASH_LEN))

template deriveEncKeys(secret: ptr byte) =
  var
    macd: array[MACD_LEN, byte] = hkdf(
      secret,
      CHAIN_INFO,
      BLANK_SALT
    )
    encKey {.inject.}: Curve25519Key
    authKey {.inject.}: Curve25519Key
    iv {.inject.}: IV
  copyMem(addr encKey[0], addr macd[0], KEY_SIG_LEN)
  copyMem(addr authKey[0], addr macd[KEY_SIG_LEN], KEY_SIG_LEN)
  copyMem(addr iv[0], addr macd[KEY_SIG_LEN * 2], IV_LEN)

proc calculateSignature(
  authKey: Curve25519Key,
  cipher: ptr byte,
  cipherLen: int,
  associated: seq[byte]
): array[KEY_SIG_LEN, byte] =
  var hmac: HMAC[sha256]
  hmac.init(authKey)
  hmac.update(associated)
  hmac.update(cipher, uint(cipherLen))
  result = hmac.finish().data
  hmac.clear()

proc encryptByKey*(
  sendKey: ptr byte,
  data: seq[byte],
  associated: seq[byte]
): seq[byte] =
  deriveEncKeys(sendKey)

  result = newSeq[byte](IV_LEN + data.len + KEY_SIG_LEN)
  copyMem(addr result[0], addr iv[0], iv.len)

  if data.len != 0:
    var ctx: CTR[aes256]
    ctx.init(encKey, iv)
    ctx.encrypt(unsafeAddr data[0], addr result[iv.len], uint(data.len))
    ctx.clear()
  var sig: array[KEY_SIG_LEN, byte] = calculateSignature(
    authKey,
    addr result[0],
    result.len - KEY_SIG_LEN,
    associated
  )
  copyMem(
    addr result[^KEY_SIG_LEN],
    addr sig[0],
    KEY_SIG_LEN
  )

proc decryptByKey*(
  recvKey: ptr byte,
  data: seq[byte],
  associated: seq[byte]
): seq[byte] =
  if data.len < (IV_AND_SIG_LEN):
    raise newException(DecryptionError, "Invalid data; a full IV/signature was not provided.")
  deriveEncKeys(recvKey)

  if calculateSignature(
    authKey,
    unsafeAddr data[0],
    data.len - KEY_SIG_LEN,
    associated
  ) != data[data.len - KEY_SIG_LEN ..< data.len]:
    raise newException(DecryptionError, "Invalid signature.")

  if data.len == (IV_AND_SIG_LEN):
    return

  result = newSeq[byte](data.len - (IV_AND_SIG_LEN))
  var ctx: CTR[aes256]
  ctx.init(encKey, data[0 ..< IV_LEN])
  ctx.decrypt(unsafeAddr data[IV_LEN], addr result[0], uint(data.len - IV_AND_SIG_LEN))
  ctx.clear()
