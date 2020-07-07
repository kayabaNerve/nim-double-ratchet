import tables

import stew/[endians2, results]
export results
import nimcrypto
import libp2p/crypto/hkdf

import double_ratchet/Crypto/[DH, Encryption]
export DH

const MAX_SKIP: uint32 = 1000'u32

#Let as the Nim VM doesn't like the cast.
let ROOT_INFO: seq[byte] = cast[seq[byte]]("rsZUpEuXUqqwXBvSy3EcievAh4cMj6QL")

type
  Header* = object
    dh*: seq[byte]
    n*: uint32
    pn*: uint32

  Message* = object
    header*: Header
    ciphertext*: seq[byte]

  KDFChain = ref object
    chainKey: array[32, byte] #CK
    messages: uint32 #N

    case send: bool
      of true:
        previous: uint32 #PN
      of false:
        skipped: Table[(seq[byte], uint32), array[32, byte]] #MKSKIPPED

  DoubleRatchet* = ref object
    pair: DHPair #DHs
    remote: DHPublic #DHr
    rootKey: array[32, byte] #RK

    send*: KDFChain
    recv*: KDFChain

proc encode*(header: Header): seq[byte] {.inline.} =
  @(header.n.toBytesLE()) & @(header.pn.toBytesLE()) & header.dh

#KDF_RK
proc next(
  ratchet: DoubleRatchet,
  keyToEdit: var array[32, byte],
  hellmaned: seq[byte]
) =
  var macd: array[3, array[32, byte]]
  sha256.hkdf(ratchet.rootKey, hellmaned, ROOT_INFO, macd)
  copyMem(addr ratchet.rootKey[0], addr macd[0], 32)
  copyMem(addr keyToEdit[0], addr macd[1], 32)

proc newDoubleRatchet*(
  sharedKey: array[32, byte],
  pair: DHPair
): DoubleRatchet {.inline.} =
  DoubleRatchet(
    pair: pair,
    rootKey: sharedKey,

    send: KDFChain(
      chainKey: sharedKey,
      send: true
    ),

    recv: KDFChain(
      chainKey: sharedKey,
      send: false,
      skipped: initTable[(seq[byte], uint32), array[32, byte]]()
    )
  )

proc newRemoteDoubleRatchet*(
  sharedKey: array[32, byte],
  remote: DHPublic
): DRResult[DoubleRatchet] =
  var interim: DoubleRatchet = DoubleRatchet(
    pair: ? generateDH(),
    rootKey: sharedKey,
    remote: remote,

    send: KDFChain(
      chainKey: sharedKey,
      send: true
    ),

    recv: KDFChain(
      chainKey: sharedKey,
      send: false,
      skipped: initTable[(seq[byte], uint32), array[32, byte]]()
    )
  )
  interim.next(interim.send.chainKey, ? diffieHellman(interim.pair, remote))
  result = ok(interim)

#KDF_CK
proc next(chain: KDFChain): array[32, byte] =
  var hmac: HMAC[sha256]
  hmac.init(chain.chainKey)
  hmac.update([byte(16)])
  var finished: MDigest[256] = hmac.finish()
  copyMem(addr result[0], addr finished.data[0], 32)
  hmac.clear()

  hmac.init(chain.chainKey)
  hmac.update([byte(15)])
  finished = hmac.finish()
  copyMem(addr chain.chainKey[0], addr finished.data[0], 32)
  hmac.clear()

proc encrypt*(
  ratchet: DoubleRatchet,
  msg: seq[byte],
  ad: seq[byte]
): Message =
  result = Message(
    header: Header(
      dh: ratchet.pair.pubkey.getBytes(),
      n: ratchet.send.messages,
      pn: ratchet.send.previous
    )
  )

  inc(ratchet.send.messages)
  result.ciphertext = encryptByKey(
    ratchet.send.next(),
    msg,
    ad & result.header.encode()
  )

proc decrypt*(
  ratchet: DoubleRatchet,
  message: Message,
  ad: seq[byte]
): DRResult[seq[byte]] =
  #Check if this message was skipped. If it was, use the skipped key.
  if ratchet.recv.skipped.hasKey((message.header.dh, message.header.n)):
    result = decryptByKey(
      ratchet.recv.skipped[(message.header.dh, message.header.n)],
      message.ciphertext,
      ad & message.header.encode()
    )
    ratchet.recv.skipped.del((message.header.dh, message.header.n))
    return

  #Check if this isn't the next message.
  #This also runs if this is the first message.
  if DHPublic.init(message.header.dh).get() != ratchet.remote:
    if ratchet.recv.messages + MAX_SKIP < message.header.pn:
      return err("Too many messages skipped.")

    #If this isn't the first message, skip ahead.
    var first: bool = true
    for b in ratchet.recv.chainKey:
      if b != 0:
        first = false
        break
    if not first:
      while ratchet.recv.messages < message.header.pn:
        ratchet.recv.skipped[(ratchet.remote.getBytes(), ratchet.recv.messages)] = ratchet.recv.next()
        inc(ratchet.recv.messages)

    ratchet.send.previous = ratchet.send.messages
    ratchet.send.messages = 0
    ratchet.recv.messages = 0
    ratchet.remote = DHPublic.init(message.header.dh).get()
    ratchet.next(ratchet.recv.chainKey, ? diffieHellman(ratchet.pair, ratchet.remote))
    ratchet.pair = ? generateDH()
    ratchet.next(ratchet.send.chainKey, ? diffieHellman(ratchet.pair, ratchet.remote))

  while ratchet.recv.messages < message.header.n:
    ratchet.recv.skipped[(ratchet.remote.getBytes(), ratchet.recv.messages)] = ratchet.recv.next()
    inc(ratchet.recv.messages)

  inc(ratchet.recv.messages)
  result = decryptByKey(
    ratchet.recv.next(),
    message.ciphertext,
    ad & message.header.encode()
  )
