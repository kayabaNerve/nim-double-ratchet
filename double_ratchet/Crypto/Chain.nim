import nimcrypto
import libp2p/crypto/hkdf

import DH
import Encryption

type
  KDFChain = ref object
    chainKey: array[32, byte]
    msgKey: array[32, byte]
    nextMsgKey: array[32, byte]
    messages: int

  KDFRoot* = ref object
    pair: DHPair
    theirPub: DHPublic

    chainKey: array[32, byte]
    send*: KDFChain
    recv*: KDFChain

var ROOT_INFO: seq[byte] = cast[seq[byte]]("rsZUpEuXUqqwXBvSy3EcievAh4cMj6QL")

proc newKDFRootChain*(pair: DHPair, theirPub: DHPublic): KDFRoot =
  var chainKey: array[32, byte] = diffieHellman(pair, theirPub)
  KDFRoot(
    pair: pair,
    theirPub: theirPub,

    chainKey: chainKey,
    send: KDFChain(chainKey: chainKey),
    recv: KDFChain(chainKey: chainKey)
  )

proc next*(kdf: KDFRoot, theirPub: DHPublic) =
  kdf.theirPub = theirPub

  #Update the receive chain.
  var dh: array[32, byte] = diffieHellman(kdf.pair, kdf.theirPub)
  var macd: array[3, array[32, byte]]
  sha256.hkdf(kdf.chainKey, dh, ROOT_INFO, macd)
  copyMem(addr kdf.chainKey[0], addr macd[0], 32)

  kdf.recv = KDFChain()
  copyMem(addr kdf.recv.chainKey[0], addr macd[1], 32)
  kdf.recv.msgKey = kdf.recv.nextMsgKey
  copyMem(addr kdf.recv.nextMsgKey[0], addr macd[2], 32)

  #Create a new private key and update our send chain.
  kdf.pair = generateDH()
  dh = diffieHellman(kdf.pair, kdf.theirPub)

  sha256.hkdf(kdf.chainKey, dh, ROOT_INFO, macd)
  copyMem(addr kdf.chainKey[0], addr macd[0], 32)

  kdf.send = KDFChain()
  copyMem(addr kdf.send.chainKey[0], addr macd[1], 32)
  kdf.send.msgKey = kdf.send.nextMsgKey
  copyMem(addr kdf.send.nextMsgKey[0], addr macd[2], 32)

proc next*(kdf: KDFChain) =
  var hmac: HMAC[sha256]
  hmac.init(kdf.chainKey)
  hmac.update([byte(15)])
  var finished: MDigest[256] = hmac.finish()
  copyMem(addr kdf.chainKey[0], addr finished.data[0], 32)
  hmac.clear()

  hmac.init([byte(16)])
  finished = hmac.finish()
  kdf.msgKey = kdf.nextMsgKey
  copyMem(addr kdf.nextMsgKey[0], addr finished.data[0], 32)
  hmac.clear()

  inc(kdf.messages)

proc skip*(kdf: KDFChain, until: int) =
  while kdf.messages < until:
    kdf.next()

proc encrypt*(kdf: KDFRoot, data: seq[byte], associated: seq[byte]): seq[byte] =
  encryptByKey(kdf.send.msgKey, data, associated)

proc decrypt*(kdf: KDFRoot, data: seq[byte], associated: seq[byte]): seq[byte] =
  decryptByKey(kdf.recv.msgKey, data, associated)
