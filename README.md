## Boot Guard Manifest Parser

A python3 script that takes a path to a dump (can be a full flash dump or only BIOS Region dump) as an argument, parses it and outputs the Firmware Interface Table entries and the Manifest structures verified by **Intel Boot Guard's ACM**. 

An output example:

```python
======================================================================
Searching for Firmware Interface Table (FIT)
======================================================================

  FIT found at offset 0x00FFAC00
  Number of entries: 12
  Idx   Type                           Address              Size         Ver      C_V   Chk
  ----- ------------------------------ -------------------- ------------ -------- ----- ------
  0     0x00 (Header)                  0x2020205F5449465F   12           0x0100   1     0xCD
  1     0x01 (Microcode)               0x00000000FFC80060   0x2E000      0x0100   0     0x00
  2     0x01 (Microcode)               0x00000000FFCAE060   0x2B400      0x0100   0     0x00
  3     0x02 (Startup ACM)             0x00000000FFC40000   0x9400       0x0100   0     0x00
  4     0x07 (BIOS Startup Module)     0x00000000FFD3D000   0x8600       0x0100   0     0x00
  5     0x07 (BIOS Startup Module)     0x00000000FFE72000   0x15000      0x0100   0     0x00
  6     0x07 (BIOS Startup Module)     0x00000000FFFC2000   0x1000       0x0100   0     0x00
  7     0x07 (BIOS Startup Module)     0x00000000FFFD2000   0x100        0x0100   0     0x00
  8     0x07 (BIOS Startup Module)     0x00000000FFFD3000   0x2720       0x0100   0     0x00
  9     0x07 (BIOS Startup Module)     0x00000000FFFFAD00   0x530        0x0100   0     0x00
  10    0x0B (Key Manifest)            0x00000000FFFFA200   0x355        0x0100   0     0x00
  11    0x0C (Boot Policy Manifest)    0x00000000FFFFA600   0x3A9        0x0100   0     0x00

======================================================================
Searching for Boot Guard structures
======================================================================

  [Key Manifest (KM)] found at offset 0x00FFA200
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
    KeyManifestSignature.Sig.Signature   : 32 e3 62 2a 8c fe 71 36 17 96 b1 d8 c7 65 1e f4 15 4c 6b ad 36 ad 86 6c 53 c4 61 61 33 2a 3c b0 49 19 29 60 85 56 e4 cc df 18 d5 fe f8 b6 8c 04 60 8a f1 87 f4 62 c1 c8 4e 8e 0b df 05 9b 9e 25 91 5c 2d 40 5f d9 25 60 da 82 a9 ac 1a 93 73 ce 58 47 aa 3e 26 1d 8c 3b e7 6d 25 bd 0b a9 70 07 1e f0 69 21 fc 27 f2 e5 03 56 00 ea 6e ed cc b8 d8 3e cb 97 fb 30 0b 4d 92 db 5b d1 40 64 8d ee 6c 7a b0 d1 7a e4 da f9 0b 6f a3 2f 1d a5 98 3e 36 0b a6 6a 96 3a b5 58 5a ad b7 b4 78 1a 74 20 d3 ea a4 9f 18 6f 76 33 bf 94 2a 41 a4 8a 82 d9 87 4c e8 ca d2 02 37 1c d6 8f 95 b7 65 0f 53 f3 88 f0 76 b2 68 44 03 9e 76 73 fa 05 b5 92 58 52 43 f5 c2 6d 84 4c a3 ac ac d6 3d 92 d7 d3 c5 19 cf ba 7e 0e 38 01 ae ad 92 14 f0 c2 e0 57 8f f6 2d f0 16 30 41 77 7a b7 77 c3 d5 8e 0b 34 9e d3 5b f9 e9 7b bf c2 d2 08 bc ae 90 3f 5b 71 ab b5 e4 2b 41 fd 54 76 1c 6d 92 9d d7 32 68 55 bd 63 cf 95 fc fb 61 b1 a4 fe 76 39 47 35 9f bf 59 6d c4 02 8f 41 76 c6 5b 58 c5 ab 6a 61 1f 3c 93 31 cd 5c 86 6d dd a4 a2 6c 4a 0f 50 2c ce 6c 7c 59 2c 2d 6c 1b f9 32 ed 8e e0 0c 51 57 f8 33 e0 2e 28 80 04 71 cc c0 ff 68 43 fe dd b7 20 da bf a8 fd cb f4 f2 d1 36 9a 98 c6 92 dc 14 1c e1 43 e2

  [Boot Policy Manifest (BPM) Header] found at offset 0x00FFA600
    StructVersion      : 0x21
    HdrStructVersion   : 0x20
    HdrSize            : 0x0014
    KeySignatureOffset : 0x0198
    BpmRevision        : 1
    BpmRevocation      : 1
    AcmRevocation      : 2
    Reserved           : 0
    NemPages           : 3

  [IBB Element] found at offset 0x00FFA614
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
    DigestList.Digest[0].Hash    : 8153b3fc3a72fd76299e9a30d28fed4146a3554bae7e18906d9a5e04a7355a4e

    DigestList.Digest[1].HashAlg : 0x0004 (SHA1)
    DigestList.Digest[1].Size    : 0x0014
    DigestList.Digest[1].Hash    : 86eb8587fff3510ed9bbf2ac018dfd90df56d05a

    DigestList.Digest[2].HashAlg : 0x000C (SHA384)
    DigestList.Digest[2].Size    : 0x0030
    DigestList.Digest[2].Hash    : 1ac55b9c58afa0c1a0f9b3bad3cc33bfc7e6484286eea4b6e519c16a00125cf0f0432f20f855c7f38d9644625205edbd

    DigestList.Digest[3].HashAlg : 0x0012 (SM3_256)
    DigestList.Digest[3].Size    : 0x0020
    DigestList.Digest[3].Hash    : f183ba9a02d048f689dac28160c97d80e694696e405fc473aa800ca7457b5ed4

    ObbHash.HashAlg              : 0x0010 (Unknown)
    ObbHash.Size                 : 0x0000
    Reserved2                    : 000000

    SegmentCount                 : 6
    IbbSegment[0].Reserved       : 0x0000
    IbbSegment[0].Flags          : 0x0000 (IBB)
    IbbSegment[0].Base           : 0xFFD3D000
    IbbSegment[0].Size           : 0x00008600

    IbbSegment[1].Reserved       : 0x0000
    IbbSegment[1].Flags          : 0x0000 (IBB)
    IbbSegment[1].Base           : 0xFFE72000
    IbbSegment[1].Size           : 0x00015000

    IbbSegment[2].Reserved       : 0x0000
    IbbSegment[2].Flags          : 0x0000 (IBB)
    IbbSegment[2].Base           : 0xFFFC2000
    IbbSegment[2].Size           : 0x00001000

    IbbSegment[3].Reserved       : 0x0000
    IbbSegment[3].Flags          : 0x0000 (IBB)
    IbbSegment[3].Base           : 0xFFFD2000
    IbbSegment[3].Size           : 0x00000100

    IbbSegment[4].Reserved       : 0x0000
    IbbSegment[4].Flags          : 0x0000 (IBB)
    IbbSegment[4].Base           : 0xFFFD3000
    IbbSegment[4].Size           : 0x00002720

    IbbSegment[5].Reserved       : 0x0000
    IbbSegment[5].Flags          : 0x0000 (IBB)
    IbbSegment[5].Base           : 0xFFFFAD00
    IbbSegment[5].Size           : 0x00000530


  [TXT Element] found at offset 0x00FFA740
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

  [Platform Config Data Element] found at offset 0x00FFA768
    StructVersion  : 0x20
    Reserved0      : 0
    ElementSize    : 0x0024
    Reserved1      : 0
    SizeOfData     : 0x0014
    Data (preview) : 5f 5f 50 44 52 53 5f 5f 10 09 00 00 03 70 00 71 00 03 00 2b

  [BPM Signature Element] found at offset 0x00FFA78C
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
    KeySig.Sig.Signature   : bb fd d5 14 25 db 54 ca 0c 36 8b dd ae 97 ed 06 29 ad f9 d8 86 72 14 5f 8f 8c 31 07 0d e9 ec 93 a2 e1 b3 0d 56 32 05 23 83 fd ee 76 70 23 76 a9 46 77 cf 0d 6c 14 2f 06 b0 47 80 63 8e 55 38 67 90 5c 84 ea 8f 0b 63 b1 cf 83 57 cd f2 43 04 32 1d 54 29 bf bb f7 b6 9c 29 d8 80 a5 9a 91 f0 5e 9a 76 67 56 21 e2 5b 69 31 16 4f 8d 37 b4 a2 7d 03 4a ce f6 d3 ee d1 cc 6e 10 70 4d 0f 8c 5c 3f 72 45 94 ab 48 f6 20 a4 d0 2c aa c4 8b c2 a7 39 58 79 44 39 ba 88 77 a4 e9 1d 31 bb 1d cc 07 a9 12 36 34 30 79 5c da d5 6d 2d 0f ba 71 4d 26 54 4b 29 44 ba 72 30 9d c3 82 a7 a5 bd 4d 56 4d 0d 03 a3 72 6f e4 ba 46 3a cf ed cc 50 63 cf 82 71 be 90 09 b3 98 d1 23 c3 67 f1 a0 19 79 14 2b 69 91 ea 51 a6 26 32 44 17 c2 aa 50 fb 3a e6 8f 75 41 3c 77 b2 78 71 4c e6 69 fc ab 56 25 85 29 3e

Done

```
