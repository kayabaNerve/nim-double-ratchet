import protobuf_serialization

type
  MapEntry[T] = object
    key {.fieldNumber: 1.}: string
    value {.fieldNumber: 2.}: T

  DHHeader = object of RootObj
    key {.fieldNumber: 1.}: seq[byte]

  X3DHHeader = object of DHHeader
    id {.fieldNumber: 4.}: seq[byte]

  DRHeader = object of X3DHHeader
    n {.fieldNumber: 2, pint.}: uint32
    pn {.fieldNumber: 3, pint.}: uint32

  SignedPreKey = object
    key {.fieldNumber: 1.}: seq[byte]
    version {.fieldNumber: 2, pint.}: uint32

  Bundle = object
    id {.fieldNumber: 1.}: seq[byte]
    preKeys {.fieldNumber: 2.}: seq[MapEntry[SignedPreKey]]
    sig {.fieldNumber: 4.}: seq[byte]
    time {.fieldNumber: 5, pint.}: int64

  DirectMessage = object
    x3dhHeader {.fieldNumber: 1.}: X3DHHeader
    drHeader {.fieldNumber: 2.}: DRHeader
    dhHeader {.fieldNumber: 101.}: DHHeader
    payload {.fieldNumber: 3.}: seq[byte]

  Message = object
    installationID {.fieldNumber: 2.}: string
    bundles {.fieldNumber: 3.}: seq[Bundle]
    messages {.fieldNumber: 101.}: seq[MapEntry[DirectMessage]]
    public {.fieldNumber: 102.}: seq[byte]
