## Boot Guard Manifest Parser

A python3 script that takes a bin file dumped from the flash, iterates over it and finds manifest structures verified by **Intel Boot Guard's ACM**. 

An output example:

```python
======================================================================
Searching for Firmware Interface Table (FIT)
======================================================================

  FIT found at offset 0x00000C00
  Number of entries: 12
  Idx   Type                           Address              Size(x16)    Ver      C_V   Chk
  ----- ------------------------------ -------------------- ------------ -------- ----- ------
  0     0x00 (Header)                  0x2020205F5449465F   12           0x0100   1     0x9C
  1     0x01 (Microcode)               0x00000000FFC81000   0x0          0x0100   0     0x00
  2     0x01 (Microcode)               0x00000000FFCBC000   0x0          0x0100   0     0x00
  3     0x02 (Startup ACM)             0x00000000FFC40000   0x0          0x0100   0     0x00
  4     0x07 (BIOS Startup Module)     0x00000000FFD3D000   0x8600       0x0100   0     0x00
  5     0x07 (BIOS Startup Module)     0x00000000FFE72000   0x15000      0x0100   0     0x00
  6     0x07 (BIOS Startup Module)     0x00000000FFFC2000   0x1000       0x0100   0     0x00
  7     0x07 (BIOS Startup Module)     0x00000000FFFD2000   0x100        0x0100   0     0x00
  8     0x07 (BIOS Startup Module)     0x00000000FFFD3000   0x2720       0x0100   0     0x00
  9     0x07 (BIOS Startup Module)     0x00000000FFFFAD00   0x530        0x0100   0     0x00
  10    0x0B (Key Manifest)            0x00000000FFFFA200   0x355        0x0100   0     0x00
  11    0x0C (Boot Policy Manifest)    0x00000000FFFFA600   0x3a9        0x0100   0     0x00

======================================================================
Searching for Boot Guard structures
======================================================================

  [Key Manifest (KM)] found at offset 0x00000200
    StructVersion                        : 0x21
    Reserved                             : 000000
    KeySignatureOffset                   : 0x0044
    Reserved2                            : 000000
    KeyManifestRevision                  : 1
    KmSvn                                : 0
    KeyManifestId                        : 1
    KmPubKeyHashAlg                      : 0x000C
    KeyCount                             : 1

    KeyHash[0].Usage                     : 0x0000000000000001
    KeyHash[0].Digest.HashAlg            : 0x000B (SHA256)
    KeyHash[0].Digest.Size               : 0x0020
    KeyHash[0].Digest.Hash               : 68837dd09e6db4ba7f08d385a02f5a823db8ba7c03e41ae5b006afcbc22a16cf

    KeyManifestSignature.Version         : 0x10
    KeyManifestSignature.KeyAlg          : 0x0001 (RSA)
    KeyManifestSignature.Key.Version     : 0x10
    KeyManifestSignature.Key.KeySizeBits : 3072
    KeyManifestSignature.Key.Exponent    : 0x00010001
    KeyManifestSignature.Key.Modulus     : d9 03 fc 44 eb ad 15 79 bf b1 a5 45 22 f2 af a8 6e bd b8 62 f5 4b 59 fe 6b 97 a6 9a f0 74 59 89 e2 35 27 00 74 7e 8b 10 df ef 15 84 d0 d9 a7 77 e8 af f3 7e de 4a 2a 1a 18 5f 50 ed 01 b7 4d a4 bd b4 65 a5 74 88 10 8a 22 f6 b0 c6 e6 a1 ba 64 5e d8 5e 8f fc 91 37 ef fa 88 66 56 40 1d 9a 60 43 91 dc 0b 6d 8b 01 28 4a 5b 4d b7 1f fc 0f 79 8e 92 b4 03 0b 02 b8 3b 16 ba d3 a7 f4 70 72 d8 4e e7 c0 0c 52 57 b1 05 74 c7 24 d2 6b c6 b7 5a ba 35 6e 81 0f ca 0c 46 cf 8f bb f4 8d fc 5b 3d 85 59 b0 35 7b 30 c2 10 4e 93 3c 6e cc 66 cc 2d d1 4f 5a 5e ce 73 4c 25 78 f1 73 4c e2 25 33 25 18 9c 63 9b 21 58 1f c5 6f aa 40 36 58 25 78 a4 a8 6d c5 ca 5f 95 11 d2 03 6e 00 fa 74 61 9d 2b 18 16 41 0a 3c cf 84 e8 bb b4 a7 76 d3 d9 86 2b 42 68 f3 1e 31 31 4e ad 28 ec f6 66 53 e5 26 9f c6 fa 39 6d 17 04 bf 5b d3 3e 55 24 0e b1 1f 20 90 60 8d 97 c5 b3 b7 ed dc 9f 46 9f 2f 62 5d 10 e9 80 e8 4c cc 0d 64 e0 1a b2 11 d6 03 44 24 aa 41 14 07 28 0d e3 a8 a6 e7 27 17 23 65 88 46 ed 9b de 9a c2 37 e2 2f 4f 14 3d 32 2a e2 0e 2c 41 36 7a d6 9b f1 a4 ea 8d 26 a9 a8 85 f0 56 69 00 65 88 47 ca 3b 7d 17 f6 7b e9 cb 5a 49 39 8b 41 f0 f6 5b d0 11 30 c8 92 c8 98 51 af c6 4a 76 d8

    KeyManifestSignature.SigScheme       : 0x0016 (RSAPSS)
    KeyManifestSignature.Sig.Version     : 0x10
    KeyManifestSignature.Sig.KeySizeBits : 3072
    KeyManifestSignature.Sig.HashAlg     : 0x000C (SHA384)
    KeyManifestSignature.Sig.Signature   : a1 c7 93 15 c4 25 27 24 40 79 ae 96 33 ab b6 06 ab 5a 0a be 73 18 35 07 a8 85 62 be 52 5b 29 42 d1 6e 9c b0 ce 12 ef 96 5f 78 2d d1 73 26 44 26 cb d5 9a f7 88 4a 10 db e1 e6 91 d8 2f 1b 57 bf 0e c0 fc f0 9b 42 34 3e 93 ac 54 97 e3 fd db 6e 07 ec 91 0d c0 d8 8b 38 e5 f8 40 8f 6b 60 7e 6b f2 58 74 ab 6e 9f 62 a1 72 73 e4 fc 02 2a dc 46 06 0e 4e 21 d2 85 56 3b 1c 79 26 72 59 dd 85 24 c9 80 16 e6 e9 47 07 a2 fb a1 9c 20 cb e5 0e b4 d2 17 80 c5 a7 33 73 92 eb 2d 62 fa b2 59 52 e9 0a 31 40 3d c0 2e e2 e1 3d dd 50 d2 d4 1d 8d 6b 21 e4 10 1c 31 e2 d9 84 a9 6c 11 1e b7 a1 85 b1 a6 4f d8 60 27 50 9e 6f 99 3e bf d6 a6 a3 25 b5 db 84 51 bc f5 7a 25 4b b1 28 fc 8b 4a 38 9c f0 ad 13 7c 21 cb 59 72 00 ce c8 94 b7 7d ff b3 2c 65 67 7a 57 35 c9 30 f1 f4 90 80 22 10 bf f7 65 9c ed 10 84 1c 14 32 df 23 a4 61 1b fd 47 c0 48 14 91 66 95 02 40 2f 8b 94 bb 9c b3 95 be e4 b6 8f d7 07 4c a4 42 92 7b 4c 22 0a bf 2f 39 79 35 42 50 2c bf f2 2a 19 02 91 4c c9 c5 82 03 61 90 64 ca 93 87 ee 17 ba f0 d9 82 4e 4b dd f1 b2 29 b6 c2 0d ea db 4e 39 c3 3a ba b5 d8 da f4 3b 78 7a 54 5f 08 48 e4 21 b5 37 5b 1f 1f 23 e2 39 9d 9f 57 77 0a 13 77 de 7d bc ee 32 09 2c 14 53 92

  [Boot Policy Manifest (BPM) Header] found at offset 0x00000600
    StructVersion      : 0x21
    HdrStructVersion   : 0x20
    HdrSize            : 0x0014
    KeySignatureOffset : 0x0198
    BpmRevision        : 1
    BpmRevocation      : 1
    AcmRevocation      : 2
    Reserved           : 0
    NemPages           : 3

  [IBB Element] found at offset 0x00000614
    StructVersion                : 0x20
    Reserved0                    : 0
    ElementSize                  : 0x012C
    Reserved1                    : 0
    SetType                      : 0
    Reserved                     : 0
    PbetValue                    : 15
    Flags                        : 0x00000013
    IbbMchBar                    : 0x00000000FED10000
    VtdBar                       : 0x00000000FED91000
    DmaProtBase0                 : 0x00100000
    DmaProtLimit0                : 0x00F00000
    DmaProtBase1                 : 0x0000000000000000
    DmaProtLimit1                : 0x0000000001000000
    PostIbbHash.HashAlg          : 0x0010 (Unknown)
    PostIbbHash.Size             : 0x0000
    IbbEntryPoint                : 0XFFFFFFF0 (Reset Vector)

    DigestList.Size              : 0x0098
    DigestList.Count             : 4

    DigestList.Digest[0].HashAlg : 0x000B (SHA256)
    DigestList.Digest[0].Size    : 0x0020
    DigestList.Digest[0].Hash    : 1465e41fbd5ff72c0a479d53eb33cc4516f7595f3218f0f8cab38f1038e23c38

    DigestList.Digest[1].HashAlg : 0x0004 (SHA1)
    DigestList.Digest[1].Size    : 0x0014
    DigestList.Digest[1].Hash    : 6504cad58310803e8bbe16d44d973e1afcdbfa20

    DigestList.Digest[2].HashAlg : 0x000C (SHA384)
    DigestList.Digest[2].Size    : 0x0030
    DigestList.Digest[2].Hash    : 4b1aafd8071e0e3ae9aab03319aa98fd078d33aa73e26ef1c131063723b328c67af1273a3b5cae0ca7526b32ac88106b

    DigestList.Digest[3].HashAlg : 0x0012 (SM3_256)
    DigestList.Digest[3].Size    : 0x0020
    DigestList.Digest[3].Hash    : cec8cb0e787854d20524c76e9dd7f35afcb8613b25dece5ae3465b143ebeefca

    ObbHash.HashAlg              : 0x0010 (Unknown)
    ObbHash.Size                 : 0x0000
    Reserved2                    : 000000

    SegmentCount                 : 6
    IbbSegment[0].Reserved       : 0x0000
    IbbSegment[0].Flags          : 0x0000 (IBB)
    IbbSegment[0].Base           : 0xFFD3D000
    IbbSegment[0].Size           : 0x00086000

    IbbSegment[1].Reserved       : 0x0000
    IbbSegment[1].Flags          : 0x0000 (IBB)
    IbbSegment[1].Base           : 0xFFE72000
    IbbSegment[1].Size           : 0x00150000

    IbbSegment[2].Reserved       : 0x0000
    IbbSegment[2].Flags          : 0x0000 (IBB)
    IbbSegment[2].Base           : 0xFFFC2000
    IbbSegment[2].Size           : 0x00010000

    IbbSegment[3].Reserved       : 0x0000
    IbbSegment[3].Flags          : 0x0000 (IBB)
    IbbSegment[3].Base           : 0xFFFD2000
    IbbSegment[3].Size           : 0x00001000

    IbbSegment[4].Reserved       : 0x0000
    IbbSegment[4].Flags          : 0x0000 (IBB)
    IbbSegment[4].Base           : 0xFFFD3000
    IbbSegment[4].Size           : 0x00027200

    IbbSegment[5].Reserved       : 0x0000
    IbbSegment[5].Flags          : 0x0000 (IBB)
    IbbSegment[5].Base           : 0xFFFFAD00
    IbbSegment[5].Size           : 0x00005300


  [TXT Element] found at offset 0x00000740
    StructVersion    : 0x20
    Reserved0        : 0
    ElementSize      : 0x0028
    Reserved1        : 0
    SetType          : 0
    Reserved         : 0
    Flags            : 0x00000000
    PwrDownInterval  : 62
    PttCmosOffset0   : 0xFE
    PttCmosOffset1   : 0xFF
    AcpiBaseOffset   : 0x0400
    Reserved2        : 0
    PrwmBaseOffset   : 0xFE000000
    DigestList.Size  : 0x0004
    DigestList.Count : 0

    Reserved3        : 000000
    SegmentCount     : 0

  [Platform Config Data Element] found at offset 0x00000768
    StructVersion  : 0x20
    Reserved0      : 0
    ElementSize    : 0x0024
    Reserved1      : 0
    SizeOfData     : 0x0014
    Data (preview) : 5f 5f 50 44 52 53 5f 5f 10 09 00 00 03 70 00 71 00 03 00 2b

  [BPM Signature Element] found at offset 0x0000078C
    StructVersion          : 0x20
    Reserved               : 000000
    KeySig.Version         : 0x10
    KeySig.KeyAlg          : 0x0001 (RSA)
    KeySig.Key.Version     : 0x10
    KeySig.Key.KeySizeBits : 2048
    KeySig.Key.Exponent    : 0x00010001
    KeySig.Key.Modulus     : dd d5 d1 ef ba 0b 58 6e 93 3c 3d fb f7 aa 84 de ab a6 71 6c 57 74 7c 51 7b 82 43 88 4f 0f a5 dc 57 eb b2 ed e5 0c 1f 3d fe 5b 07 c9 c3 2c 8f 46 3f cb 73 85 66 74 b7 99 6d f5 67 36 66 be 1a 4e 98 90 84 f3 a5 19 b0 3f 1a 4a d2 97 51 66 ff 4c 75 09 7f 30 0b 32 8f d6 1e 87 9a 38 fb f3 41 c1 b3 4f 89 6b 1a 82 df c5 1b b2 85 7d 64 a8 e0 52 62 1e f5 7e d6 a9 e6 d3 93 9f e9 68 82 6d dc 69 e2 a1 2e 29 3a 56 9f d5 04 3c e3 3b b0 92 69 79 fa 24 07 1b b1 74 85 8d 94 1f 50 39 0f db c4 14 fd 46 69 43 4c 76 41 99 78 dd 01 9b 0c 54 96 37 76 41 cc cf 13 67 5a c5 73 db 0e 52 5c 47 d4 c8 75 ed 8a 73 74 f3 25 60 9f 7c 57 1a 95 e9 ea 0d 14 4f ad cf d6 a5 7c 01 3b 9d ae dd d0 6e 15 68 31 fc a8 33 e8 b3 fd 94 1b 28 0d 59 55 89 42 7f 9a 3e 33 1e 9f 47 b1 50 27 be 6c 96 0f 82 fe ca

    KeySig.SigScheme       : 0x0016 (RSAPSS)
    KeySig.Sig.Version     : 0x10
    KeySig.Sig.KeySizeBits : 2048
    KeySig.Sig.HashAlg     : 0x000B (SHA256)
    KeySig.Sig.Signature   : 00 4d c0 26 70 76 ec c3 ec 72 84 a0 5f 41 3d bc 93 84 09 a8 4d 13 33 43 76 94 a1 8f cb 84 bb f6 0e de 3a 48 88 be 18 ba 7a 17 b4 71 1e 08 a7 49 6d e3 64 f5 52 5c 5f d6 e8 f5 8b 08 b5 8f 5c 79 b1 89 4a 07 17 5d 2d a3 2e 2a 8c d9 ae e9 0f bf b7 73 2d cf c0 ea ad f4 11 31 a0 88 99 5d bf ab ef 8b 31 38 45 f4 8c 8f 0b d3 a7 6d f6 dc 24 b0 48 01 91 8f 4d f7 5b 7d a5 fa 30 6e 25 f0 a3 6a 2d 10 f5 86 cf c5 27 b9 b3 9b 1a 5e b6 2d 29 8f 0c 46 bf a0 f6 9b d4 67 f6 59 00 9e 06 82 b6 af d5 98 9e e1 e4 55 ee 54 0d 1f a8 d3 e1 50 39 38 fd 79 6a 00 cc 71 32 a6 8a 35 3b ec 7e 36 66 b7 0e 9e ef f2 d6 53 64 9a 70 0c 45 bc f1 e9 6f b5 6c a2 6c ed 3e d4 09 fe 25 e7 85 da 01 7e 58 e2 f4 99 53 0d dc d4 f2 e6 67 c3 0d aa cb c5 b0 44 2a ed 2d 0e de 97 b5 5e ad a3 07 73 00 30 5f 92

Done.

```
