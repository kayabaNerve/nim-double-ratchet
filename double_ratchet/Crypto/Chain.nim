import nimcrypto

import C25519
import HKDF
import Encryption

type
  KDFChain* = ref object
    chainKey: Curve25519Key
    msgKey*: Curve25519Key
    nextMsgKey: Curve25519Key
    messages: int

  KDFRoot* = ref object
    pair: Curve25519KeyPair
    theirPub: Curve25519Key

    chainKey: Curve25519Key
    send*: KDFChain
    recv*: KDFChain

var
  ROOT_INFO_STR: string = "rsZUpEuXUqqwXBvSy3EcievAh4cMj6QL"
  ROOT_INFO: ptr byte = cast[ptr byte](addr ROOT_INFO_STR[0])

proc newKDFRootChain*(
  pair: Curve25519KeyPair,
  theirPub: Curve25519Key
): KDFRoot =
  var chainKey: Curve25519Key = diffieHellman(pair.priv, theirPub)
  KDFRoot(
    pair: pair,
    theirPub: theirPub,

    chainKey: chainKey,
    send: KDFChain(chainKey: chainKey),
    recv: KDFChain(chainKey: chainKey)
  )

proc next*(kdf: KDFRoot, theirPub: Curve25519Key) =
  kdf.theirPub = theirPub

  #Update the receive chain.
  var dh: Curve25519Key = diffieHellman(kdf.pair.priv, kdf.theirPub)
  var macd: array[MACD_LEN, byte] = hkdf(
    addr dh[0],
    addr kdf.chainKey[0],
    ROOT_INFO
  )
  copyMem(addr kdf.chainKey[0], addr macd[0], KEY_SIG_LEN)

  kdf.recv = KDFChain()
  copyMem(addr kdf.recv.chainKey[0], addr macd[KEY_SIG_LEN], KEY_SIG_LEN)
  kdf.recv.msgKey = kdf.recv.nextMsgKey
  copyMem(addr kdf.recv.nextMsgKey[0], addr macd[KEY_SIG_LEN * 2], KEY_SIG_LEN)

  #Create a new private key and update our send chain.
  kdf.pair = newCurve25519KeyPair()
  dh = diffieHellman(kdf.pair.priv, kdf.theirPub)

  macd = hkdf(addr dh[0], addr kdf.chainKey[0], ROOT_INFO)
  copyMem(addr kdf.chainKey[0], addr macd[0], KEY_SIG_LEN)

  kdf.send = KDFChain()
  copyMem(addr kdf.send.chainKey[0], addr macd[KEY_SIG_LEN], KEY_SIG_LEN)
  kdf.send.msgKey = kdf.send.nextMsgKey
  copyMem(addr kdf.send.nextMsgKey[0], addr macd[KEY_SIG_LEN * 2], KEY_SIG_LEN)

proc next*(kdf: KDFChain) =
  var hmac: HMAC[sha256]
  hmac.init(kdf.chainKey)
  hmac.update([byte(15)])
  var finished: MDigest[HASH_BITS] = hmac.finish()
  copyMem(addr kdf.chainKey[0], addr finished.data[0], KEY_SIG_LEN)
  hmac.clear()

  hmac.init([byte(16)])
  finished = hmac.finish()
  kdf.msgKey = kdf.nextMsgKey
  copyMem(addr kdf.nextMsgKey[0], addr finished.data[0], KEY_SIG_LEN)
  hmac.clear()

  inc(kdf.messages)

proc skip*(kdf: KDFChain, until: int) =
  while kdf.messages < until:
    kdf.next()

proc encrypt*(
  kdf: KDFRoot,
  data: seq[byte],
  associated: seq[byte]
): seq[byte] =
  encryptByKey(addr kdf.send.msgKey[0], data, associated)

proc decrypt*(
  kdf: KDFRoot,
  data: seq[byte],
  associated: seq[byte]
): seq[byte] =
  decryptByKey(addr kdf.recv.msgKey[0], data, associated)
