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
  1     0x01 (Microcode)               0x00000000FFC81000   0            0x0100   0     0x00
  2     0x01 (Microcode)               0x00000000FFCBC000   0            0x0100   0     0x00
  3     0x02 (Startup ACM)             0x00000000FFC40000   0            0x0100   0     0x00
  4     0x07 (BIOS Startup Module)     0x00000000FFD3D000   34304        0x0100   0     0x00
  5     0x07 (BIOS Startup Module)     0x00000000FFE72000   86016        0x0100   0     0x00
  6     0x07 (BIOS Startup Module)     0x00000000FFFC2000   4096         0x0100   0     0x00
  7     0x07 (BIOS Startup Module)     0x00000000FFFD2000   256          0x0100   0     0x00
  8     0x07 (BIOS Startup Module)     0x00000000FFFD3000   10016        0x0100   0     0x00
  9     0x07 (BIOS Startup Module)     0x00000000FFFFAD00   1328         0x0100   0     0x00
  10    0x0B (Key Manifest)            0x00000000FFFFA200   853          0x0100   0     0x00
  11    0x0C (Boot Policy Manifest)    0x00000000FFFFA600   937          0x0100   0     0x00

======================================================================
Searching for Boot Guard structures
======================================================================

  [Key Manifest (KM)] found at offset 0x00000200
    StructVersion       : 0x21
    Reserved            : 000000
    KeySignatureOffset  : 0x0044
    Reserved2           : 000000
    KeyManifestRevision : 1
    KmSvn               : 0
    KeyManifestId       : 1
    KmPubKeyHashAlg     : 0x000C
    KeyCount            : 1

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
    StructVersion       : 0x20
    Reserved0           : 0
    ElementSize         : 0x012C
    Reserved1           : 0
    SetType             : 0
    Reserved            : 0
    PbetValue           : 15
    Flags               : 0x00000013
    IbbMchBar           : 0x00000000FED10000
    VtdBar              : 0x00000000FED91000
    DmaProtBase0        : 0x00100000
    DmaProtLimit0       : 0x00F00000
    DmaProtBase1        : 0x0000000000000000
    DmaProtLimit1       : 0x0000000001000000
    PostIbbHash.HashAlg : 0x0010
    PostIbbHash.Size    : 0
    PostIbbHash.Data    :

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
    StructVersion      : 0x20
    Reserved           : 000000
    KeySig.Version     : 0x10
    KeySig.KeyAlg      : 0x0001
    KeySig.KeyAlg_Name : RSA

Done.

```
