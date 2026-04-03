#!/usr/bin/env python3
"""
Parser for Boot Guard binary structures.

Searches a binary file for Key Manifest, Boot Policy Manifest,
FIT table, and BPM sub-elements, then prints their parsed fields.
"""

import argparse
import struct
import sys
from pathlib import Path


# 8-byte signatures (as they appear in the binary)
SIGNATURES = {
    b"__KEYM__": "Key Manifest (KM)",
    b"__ACBP__": "Boot Policy Manifest (BPM) Header",
    b"__IBBS__": "IBB Element",
    b"__TXTS__": "TXT Element",
    b"__PCDS__": "Platform Config Data Element",
    b"__PMDA__": "Platform Manufacturer Element",
    b"__PMSG__": "BPM Signature Element",
}

FIT_SIGNATURE = b"_FIT_   "  # 8 bytes, padded with spaces

# Hash algorithm IDs → (name, digest_size)
HASH_ALG_INFO = {
    0x0004: ("SHA1",    20),
    0x000B: ("SHA256",  32),
    0x000C: ("SHA384",  48),
    0x0012: ("SM3_256", 32),
}

# Key/Signature algorithm names
KEY_ALG_NAMES = {0x1: "RSA", 0x23: "ECC"}
SIG_SCHEME_NAMES = {0x14: "RSASSA", 0x15: "RSAPSS", 0x16: "RSAPSS", 0x1B: "SM2"}

KNOWN_ADDRESS = {0xFFFFFFF0: "Reset Vector"}

def hex_dump(data, max_bytes=4096):
    """Return a hex string of data, truncated if needed."""

    preview = data[:max_bytes].hex(" ")
    if len(data) > max_bytes:
        preview += " ..."

    return preview


def parse_shax_hash(data, pos, prefix, fields):
    """Parse a SHAX_HASH_STRUCTURE at pos. Returns new pos after the structure."""

    if pos + 4 > len(data):
        return pos

    hash_alg = struct.unpack_from("<H", data, pos)[0]
    hash_size = struct.unpack_from("<H", data, pos + 2)[0]
    alg_name = HASH_ALG_INFO.get(hash_alg, ("Unknown", 0))[0]

    fields[f"{prefix}.HashAlg"] = f"0x{hash_alg:04X} ({alg_name})"
    fields[f"{prefix}.Size"] = f"0x{hash_size:04X}"

    if hash_size > 0 and pos + 4 + hash_size <= len(data):
        fields[f"{prefix}.Hash"] = f"{data[pos + 4: pos + 4 + hash_size].hex()}\n"

    return pos + 4 + hash_size


def parse_hash_list(data, pos, prefix, fields):
    """Parse a HASH_LIST (Size, Count) + Count x SHAX_HASH_STRUCTURE digests.
    Returns new pos after all digests."""
    if pos + 4 > len(data):
        return pos

    dl_size = struct.unpack_from("<H", data, pos)[0]
    dl_count = struct.unpack_from("<H", data, pos + 2)[0]

    fields[f"{prefix}.Size"] = f"0x{dl_size:04X}"
    fields[f"{prefix}.Count"] = f"{dl_count}\n"

    dpos = pos + 4

    for i in range(dl_count):
        dpos = parse_shax_hash(data, dpos, f"{prefix}.Digest[{i}]", fields)

    return dpos


def parse_key_and_signature(data, pos, prefix, fields):
    """Parse KEY_AND_SIGNATURE_STRUCT at pos. Returns new pos after the structure."""

    if pos + 3 > len(data):
        return pos

    fields[f"{prefix}.Version"] = f"0x{data[pos]:02X}"
    key_alg = struct.unpack_from("<H", data, pos + 1)[0]
   
    fields[f"{prefix}.KeyAlg"] = f"0x{key_alg:04X} ({KEY_ALG_NAMES.get(key_alg, 'Unknown')})"
    kpos = pos + 3  # after Version + KeyAlg

    if key_alg == 0x1:  # RSA
        # RSA_PUBLIC_KEY_STRUCT: Version(1) + KeySizeBits(2) + Exponent(4) + Modulus[KeySizeBits/8]
        if kpos + 3 > len(data):
            return kpos

        fields[f"{prefix}.Key.Version"] = f"0x{data[kpos]:02X}"
        key_size_bits = struct.unpack_from("<H", data, kpos + 1)[0]
        fields[f"{prefix}.Key.KeySizeBits"] = key_size_bits

        mod_bytes = key_size_bits // 8

        if kpos + 7 > len(data):
            return kpos

        exponent = struct.unpack_from("<I", data, kpos + 3)[0]
        fields[f"{prefix}.Key.Exponent"] = f"0x{exponent:08X}"
        if kpos + 7 + mod_bytes <= len(data):
            fields[f"{prefix}.Key.Modulus"] = f"{hex_dump(data[kpos + 7: kpos + 7 + mod_bytes])}\n"

        kpos += 7 + mod_bytes

        # SigScheme (UINT16)
        if kpos + 2 > len(data):
            return kpos

        sig_scheme = struct.unpack_from("<H", data, kpos)[0]
        fields[f"{prefix}.SigScheme"] = f"0x{sig_scheme:04X} ({SIG_SCHEME_NAMES.get(sig_scheme, 'Unknown')})"
        kpos += 2

        # RSASSA_SIGNATURE_STRUCT: Version(1) + KeySizeBits(2) + HashAlg(2) + Signature[KeySizeBits/8]
        if kpos + 5 > len(data):
            return kpos

        fields[f"{prefix}.Sig.Version"] = f"0x{data[kpos]:02X}"
        sig_size_bits = struct.unpack_from("<H", data, kpos + 1)[0]

        fields[f"{prefix}.Sig.KeySizeBits"] = sig_size_bits
        sig_hash_alg = struct.unpack_from("<H", data, kpos + 3)[0]

        alg_name = HASH_ALG_INFO.get(sig_hash_alg, ("Unknown", 0))[0]
        fields[f"{prefix}.Sig.HashAlg"] = f"0x{sig_hash_alg:04X} ({alg_name})"

        sig_bytes = sig_size_bits // 8
        if kpos + 5 + sig_bytes <= len(data):
            fields[f"{prefix}.Sig.Signature"] = hex_dump(data[kpos + 5: kpos + 5 + sig_bytes])

        kpos += 5 + sig_bytes

    elif key_alg == 0x23:  # ECC
        # ECC_PUBLIC_KEY_STRUCT: Version(1) + KeySizeBits(2) + Qx[32] + Qy[32]
        if kpos + 3 > len(data):
            return kpos
        
        fields[f"{prefix}.Key.Version"] = f"0x{data[kpos]:02X}"
        key_size_bits = struct.unpack_from("<H", data, kpos + 1)[0]
        fields[f"{prefix}.Key.KeySizeBits"] = key_size_bits
        
        key_len = key_size_bits // 8  # typically 32
        if kpos + 3 + 2 * key_len <= len(data):
            fields[f"{prefix}.Key.Qx"] = data[kpos + 3: kpos + 3 + key_len].hex()
            fields[f"{prefix}.Key.Qy"] = data[kpos + 3 + key_len: kpos + 3 + 2 * key_len].hex()
        
        kpos += 3 + 2 * key_len

        # SigScheme (UINT16)
        if kpos + 2 > len(data):
            return kpos

        sig_scheme = struct.unpack_from("<H", data, kpos)[0]
        fields[f"{prefix}.SigScheme"] = f"0x{sig_scheme:04X} ({SIG_SCHEME_NAMES.get(sig_scheme, 'Unknown')})"
        kpos += 2

        # ECC_SIGNATURE_STRUCT: Version(1) + KeySizeBits(2) + HashAlg(2) + R[key_len] + S[key_len]
        if kpos + 5 > len(data):
            return kpos

        fields[f"{prefix}.Sig.Version"] = f"0x{data[kpos]:02X}"

        sig_size_bits = struct.unpack_from("<H", data, kpos + 1)[0]
        sig_hash_alg = struct.unpack_from("<H", data, kpos + 3)[0]

        alg_name = HASH_ALG_INFO.get(sig_hash_alg, ("Unknown", 0))[0]

        fields[f"{prefix}.Sig.KeySizeBits"] = sig_size_bits
        fields[f"{prefix}.Sig.HashAlg"] = f"0x{sig_hash_alg:04X} ({alg_name})"

        sig_len = sig_size_bits // 8

        if kpos + 5 + 2 * sig_len <= len(data):
            fields[f"{prefix}.Sig.R"] = data[kpos + 5: kpos + 5 + sig_len].hex()
            fields[f"{prefix}.Sig.S"] = data[kpos + 5 + sig_len: kpos + 5 + 2 * sig_len].hex()

        kpos += 5 + 2 * sig_len

    return kpos


def parse_acm_header(data, offset):
    """Try to identify ACM header at offset (heuristic: ModuleType == 2)."""
    
    if offset + 4 > len(data):
        return None

    module_type = struct.unpack_from("<H", data, offset)[0]
    if module_type != 2:  # ACM_MODULE_TYPE_CHIPSET_ACM
        return None

    fields = {}

    if offset + 80 > len(data):
        return None

    (fields["ModuleType"], fields["ModuleSubType"], fields["HeaderLen"],
     fields["HeaderVersion"], fields["ChipsetId"], fields["Flags"],
     fields["ModuleVendor"], fields["Date"], fields["Size"],
     fields["AcmSvn"], fields["SeAcmSvn"], fields["CodeControl"],
     fields["ErrorEntryPoint"], fields["GdtLimit"], fields["GdtBasePtr"],
     fields["SegSel"], fields["EntryPoint"]) = struct.unpack_from(
        "<HHIHHHIIIHHHIIIII", data, offset)

    # Format some fields as hex
    for k in ("Flags", "Date", "CodeControl", "ErrorEntryPoint",
              "GdtBasePtr", "EntryPoint"):
        if k in fields:
            fields[k] = f"0x{fields[k]:08X}"
    fields["Size"] = f"0x{int(fields['Size'], 16) if isinstance(fields['Size'], str) else fields['Size']:08X} ({fields['Size'] if isinstance(fields['Size'], int) else '?'} dwords)"

    # Tail fields: Rsa2048PubKey[256], RsaPubExp(4), Rsa2048Sig[256], Scratch[572]
    # The fixed header above is 68 bytes (0x44). HeaderLen is in dwords.
    # The RSA fields start right after the base header.
    pos = offset + 68  # end of base ACM header fields

    if pos + 256 <= len(data):
        fields["Rsa2048PubKey"] = hex_dump(data[pos:pos + 256])
        pos += 256
    else:
        return fields

    if pos + 4 <= len(data):
        fields["RsaPubExp"] = f"0x{struct.unpack_from('<I', data, pos)[0]:08X}"
        pos += 4

    if pos + 256 <= len(data):
        fields["Rsa2048Sig"] = hex_dump(data[pos:pos + 256])
        pos += 256

    if pos + 572 <= len(data):
        fields["Scratch (572 bytes)"] = hex_dump(data[pos:pos + 572], max_bytes=32)
        pos += 572

    return fields


def parse_fit_table(data, offset):
    """Parse FIT entries starting at offset where FIT_SIGNATURE was found."""
    
    entry_size = 16  # sizeof(FIRMWARE_INTERFACE_TABLE_ENTRY)
    entries = []

    # The first entry is the header; its Size field holds the entry count
    if offset + entry_size > len(data):
        return entries

    header_addr = struct.unpack_from("<Q", data, offset)[0]

    size_bytes = data[offset + 8: offset + 11]
    num_entries = int.from_bytes(size_bytes, "little")

    reserved = data[offset + 11]
    version = struct.unpack_from("<H", data, offset + 12)[0]
    type_cv = data[offset + 14]

    fit_type = type_cv & 0x7F

    c_v = (type_cv >> 7) & 1
    chksum = data[offset + 15]

    entries.append({
        "Index": 0,
        "Address": f"0x{header_addr:016X}",
        "NumEntries": num_entries,
        "Version": f"0x{version:04X}",
        "Type": f"0x{fit_type:02X} (Header)",
        "C_V": c_v,
        "Checksum": f"0x{chksum:02X}",
    })

    fit_type_names = {
        0x00: "Header",
        0x01: "Microcode",
        0x02: "Startup ACM",
        0x04: "Prot Boot Policy",
        0x07: "BIOS Startup Module",
        0x08: "TPM Policy",
        0x09: "BIOS Policy",
        0x0A: "TXT Policy",
        0x0B: "Key Manifest",
        0x0C: "Boot Policy Manifest",
        0x10: "CSE Secure Boot",
        0x2D: "TXTSX Policy",
        0x2F: "JMP Debug Policy",
        0x7F: "Skip",
    }

    # --- Flash-to-file-offset conversion ---
    # Strategy 1 (full image): flash_base = 4G - file_size
    # Strategy 2 (extracted region): derive flash_base from known signatures
    #   e.g. __KEYM__ found at file offset X, FIT says its flash addr is Y
    #   → flash_base = Y - X
    flash_base_full = 0x100000000 - len(data)

    # Try to derive flash base from known structures in the file
    flash_base_derived = None
    sig_to_fit_type = {b"__KEYM__": 0x0B, b"__ACBP__": 0x0C}
    for sig, expected_ft in sig_to_fit_type.items():
        local_off = data.find(sig)

        if local_off == -1:
            continue

        # Find the FIT entry with matching type and look for address alignment
        for j in range(1, num_entries):
            je_off = offset + j * entry_size
            if je_off + entry_size > len(data):
                break

            jft = data[je_off + 14] & 0x7F
            if jft != expected_ft:
                continue

            fit_addr = struct.unpack_from("<Q", data, je_off)[0]
            candidate_base = fit_addr - local_off

            if candidate_base > 0:
                flash_base_derived = candidate_base
                break

        if flash_base_derived is not None:
            break

    def flash_to_offset(addr):
        """Convert a flash-mapped physical address to a file offset.
        Tries full-image base first, then derived base (for extracted regions)."""
        for base in (flash_base_full, flash_base_derived):
            if base is None:
                continue
            off = addr - base
            if 0 <= off < len(data):
                return off
        return None

    def resolve_microcode_size(addr):
        """Read TotalSize from a microcode update header (UINT32 at offset 0x20)."""

        file_off = flash_to_offset(addr)

        if file_off is None or file_off + 0x24 > len(data):
            return 0

        total_size = struct.unpack_from("<I", data, file_off + 0x20)[0]
        if total_size == 0:
            # Per spec: if TotalSize is 0, use DataSize + 48
            data_size = struct.unpack_from("<I", data, file_off + 0x1C)[0]
            total_size = data_size + 48
        return total_size

    def resolve_acm_size(addr):
        """Read Size (in dwords) from an ACM header (UINT32 at offset 0x18).
        Returns the raw dword value — the FIT Size field for ACM is in dwords."""

        file_off = flash_to_offset(addr)
        if file_off is None or file_off + 0x1C > len(data):
            return 0
            
        size_dwords = struct.unpack_from("<I", data, file_off + 0x18)[0]
        return size_dwords

    for i in range(1, num_entries):
        e_off = offset + i * entry_size
        if e_off + entry_size > len(data):
            break
        addr = struct.unpack_from("<Q", data, e_off)[0]
        sz = int.from_bytes(data[e_off + 8: e_off + 11], "little")
        ver = struct.unpack_from("<H", data, e_off + 12)[0]

        tc = data[e_off + 14]
        ft = tc & 0x7F
        cv = (tc >> 7) & 1
        cs = data[e_off + 15]
        type_name = fit_type_names.get(ft, "Unknown")

        # Resolve size from component header when FIT Size field is 0
        if sz == 0 and ft == 0x01:  # Microcode
            sz = resolve_microcode_size(addr)
        elif sz == 0 and ft == 0x02:  # Startup ACM
            sz = resolve_acm_size(addr)

        entries.append({
            "Index": i,
            "Address": f"0x{addr:016X}",
            "Size": f"0x{sz:X}",
            "Version": f"0x{ver:04X}",
            "Type": f"0x{ft:02X} ({type_name})",
            "C_V": cv,
            "Checksum": f"0x{cs:02X}",
        })

    return entries


def parse_key_manifest(data, offset):
    """Parse KEY_MANIFEST_STRUCTURE at offset."""

    fields = {}

    # 8 + 1 + 3 + 2 + 3 + 1 + 1 + 1 + 2 + 2 = 24 bytes minimum
    if offset + 24 > len(data):
        return fields

    pos = offset + 8  # skip StructureId

    fields["StructVersion"] = f"0x{data[pos]:02X}"; pos += 1
    fields["Reserved"] = data[pos:pos+3].hex(); pos += 3
    fields["KeySignatureOffset"] = f"0x{struct.unpack_from('<H', data, pos)[0]:04X}"; pos += 2
    fields["Reserved2"] = data[pos:pos+3].hex(); pos += 3
    fields["KeyManifestRevision"] = data[pos]; pos += 1
    fields["KmSvn"] = data[pos]; pos += 1
    fields["KeyManifestId"] = data[pos]; pos += 1
    fields["KmPubKeyHashAlg"] = f"0x{struct.unpack_from('<H', data, pos)[0]:04X}"; pos += 2
    
    key_count = struct.unpack_from("<H", data, pos)[0]
    
    fields["KeyCount"] = f"{key_count}\n"; pos += 2

    # KeyHash[KeyCount] — each is SHAX_KMHASH_STRUCT: Usage(UINT64) + SHAX_HASH_STRUCTURE
    for i in range(key_count):
        if pos + 8 > len(data):
            break

        usage = struct.unpack_from("<Q", data, pos)[0]
        fields[f"KeyHash[{i}].Usage"] = f"0x{usage:016X}"

        pos += 8
        pos = parse_shax_hash(data, pos, f"KeyHash[{i}].Digest", fields)

    # KeyManifestSignature: KEY_AND_SIGNATURE_STRUCT
    pos = parse_key_and_signature(data, pos, "KeyManifestSignature", fields)

    return fields


def parse_bpm_header(data, offset):
    """Parse BOOT_POLICY_MANIFEST_HEADER at offset."""

    fields = {}

    # Minimum size: 8+1+1+2+2+1+1+1+1+2 = 20
    if offset + 20 > len(data):
        return fields

    pos = offset + 8

    fields["StructVersion"] = f"0x{data[pos]:02X}"; pos += 1
    fields["HdrStructVersion"] = f"0x{data[pos]:02X}"; pos += 1
    fields["HdrSize"] = f"0x{struct.unpack_from('<H', data, pos)[0]:04X}"; pos += 2
    fields["KeySignatureOffset"] = f"0x{struct.unpack_from('<H', data, pos)[0]:04X}"; pos += 2
    fields["BpmRevision"] = data[pos]; pos += 1
    fields["BpmRevocation"] = data[pos]; pos += 1
    fields["AcmRevocation"] = data[pos]; pos += 1
    fields["Reserved"] = data[pos]; pos += 1
    fields["NemPages"] = struct.unpack_from("<H", data, pos)[0]; pos += 2

    return fields


def parse_ibb_element(data, offset):
    """Parse IBB_ELEMENT at offset."""

    fields = {}

    # Minimum: 8+1+1+2+1+1+1+1+4+8+8+4+4+8+8 = 60 bytes before PostIbbHash
    if offset + 60 > len(data):
        return fields

    pos = offset + 8

    fields["StructVersion"] = f"0x{data[pos]:02X}"; pos += 1
    fields["Reserved0"] = data[pos]; pos += 1
    fields["ElementSize"] = f"0x{struct.unpack_from('<H', data, pos)[0]:04X}"; pos += 2
    fields["Reserved1"] = data[pos]; pos += 1
    fields["SetType"] = data[pos]; pos += 1
    fields["Reserved"] = data[pos]; pos += 1
    fields["PbetValue"] = data[pos]; pos += 1
    fields["Flags"] = f"0x{struct.unpack_from('<I', data, pos)[0]:08X}"; pos += 4
    fields["IbbMchBar"] = f"0x{struct.unpack_from('<Q', data, pos)[0]:016X}"; pos += 8
    fields["VtdBar"] = f"0x{struct.unpack_from('<Q', data, pos)[0]:016X}"; pos += 8
    fields["DmaProtBase0"] = f"0x{struct.unpack_from('<I', data, pos)[0]:08X}"; pos += 4
    fields["DmaProtLimit0"] = f"0x{struct.unpack_from('<I', data, pos)[0]:08X}"; pos += 4
    fields["DmaProtBase1"] = f"0x{struct.unpack_from('<Q', data, pos)[0]:016X}"; pos += 8
    fields["DmaProtLimit1"] = f"0x{struct.unpack_from('<Q', data, pos)[0]:016X}"; pos += 8

    # PostIbbHash: SHAX_HASH_STRUCTURE
    pos = parse_shax_hash(data, pos, "PostIbbHash", fields)

    # IbbEntryPoint: UINT32
    if pos + 4 > len(data):
        return fields

    #entrypoint = f"0x{struct.unpack_from('<I', data, pos)[0]:08X}\n"
    entrypoint = struct.unpack_from('<I', data, pos)[0]
    
    known_entrypoint_name = KNOWN_ADDRESS.get(entrypoint, "Unknown")
    fields["IbbEntryPoint"] = f"{hex(entrypoint).upper()} ({known_entrypoint_name})\n"
        
    pos += 4

    # DigestList: HASH_LIST + Count x SHAX_HASH_STRUCTURE
    pos = parse_hash_list(data, pos, "DigestList", fields)

    # ObbHash: SHAX_HASH_STRUCTURE  (labelled HASH_STRUCTURE in some headers)
    pos = parse_shax_hash(data, pos, "ObbHash", fields)

    # Reserved2[3] + SegmentCount
    if pos + 4 > len(data):
        return fields

    fields["Reserved2"] = f"{data[pos:pos + 3].hex()}\n"
    pos += 3

    seg_count = data[pos]
    fields["SegmentCount"] = f"{seg_count}"
    pos += 1

    # IbbSegment[SegmentCount] — each IBB_SEGMENT is 12 bytes
    for i in range(seg_count):
        if pos + 12 > len(data):
            break

        seg_reserved = struct.unpack_from("<H", data, pos)[0]
        seg_flags = struct.unpack_from("<H", data, pos + 2)[0]
        seg_base = struct.unpack_from("<I", data, pos + 4)[0]
        seg_size = struct.unpack_from("<I", data, pos + 8)[0]

        flag_name = "IBB" if seg_flags == 0 else "NON_IBB"

        fields[f"IbbSegment[{i}].Reserved"] = f"0x{seg_reserved:04X}"
        fields[f"IbbSegment[{i}].Flags"] = f"0x{seg_flags:04X} ({flag_name})"
        fields[f"IbbSegment[{i}].Base"] = f"0x{seg_base:08X}"
        fields[f"IbbSegment[{i}].Size"] = f"0x{seg_size // 16:08X}\n"
        pos += 12

    return fields


def parse_txt_element(data, offset):
    """Parse TXT_ELEMENT at offset."""

    fields = {}

    if offset + 34 > len(data):
        return fields

    pos = offset + 8

    fields["StructVersion"] = f"0x{data[pos]:02X}"; pos += 1
    fields["Reserved0"] = data[pos]; pos += 1
    fields["ElementSize"] = f"0x{struct.unpack_from('<H', data, pos)[0]:04X}"; pos += 2
    fields["Reserved1"] = data[pos]; pos += 1
    fields["SetType"] = data[pos]; pos += 1
    fields["Reserved"] = struct.unpack_from("<H", data, pos)[0]; pos += 2
    fields["Flags"] = f"0x{struct.unpack_from('<I', data, pos)[0]:08X}"; pos += 4
    fields["PwrDownInterval"] = struct.unpack_from("<H", data, pos)[0]; pos += 2
    fields["PttCmosOffset0"] = f"0x{data[pos]:02X}"; pos += 1
    fields["PttCmosOffset1"] = f"0x{data[pos]:02X}"; pos += 1
    fields["AcpiBaseOffset"] = f"0x{struct.unpack_from('<H', data, pos)[0]:04X}"; pos += 2
    fields["Reserved2"] = struct.unpack_from("<H", data, pos)[0]; pos += 2
    fields["PrwmBaseOffset"] = f"0x{struct.unpack_from('<I', data, pos)[0]:08X}"; pos += 4

    # DigestList: HASH_LIST (Size, Count, then Count x SHAX_HASH_STRUCTURE digests)
    if pos + 4 > len(data):
        return fields

    dl_size = struct.unpack_from("<H", data, pos)[0]
    dl_count = struct.unpack_from("<H", data, pos + 2)[0]
    
    fields["DigestList.Size"] = f"0x{dl_size:04X}"
    fields["DigestList.Count"] = f"{dl_count}\n"

    digest_start = pos + 4  # skip HASH_LIST header (Size + Count)

    dpos = digest_start
    for i in range(dl_count):
        if dpos + 4 > len(data):
            break

        hash_alg = struct.unpack_from("<H", data, dpos)[0]
        hash_size = struct.unpack_from("<H", data, dpos + 2)[0]

        fields[f"DigestList.Digest[{i}].HashAlg"] = f"0x{hash_alg:04X}"
        fields[f"DigestList.Digest[{i}].Size"] = f"0x{hash_size:04X}"

        if dpos + 4 + hash_size <= len(data):
            fields[f"DigestList.Digest[{i}].Hash"] = data[dpos + 4: dpos + 4 + hash_size].hex()

        dpos += 4 + hash_size

    # Reserved3[3] + SegmentCount
    if dpos + 4 > len(data):
        return fields

    fields["Reserved3"] = data[dpos:dpos + 3].hex()
    dpos += 3

    seg_count = data[dpos]
    fields["SegmentCount"] = seg_count

    dpos += 1

    # TxtSegment[SegmentCount] — each IBB_SEGMENT is 12 bytes:
    #   UINT16 Reserved, UINT16 Flags, UINT32 Base, UINT32 Size
    for i in range(seg_count):
        if dpos + 12 > len(data):
            break

        seg_reserved = struct.unpack_from("<H", data, dpos)[0]
        seg_flags = struct.unpack_from("<H", data, dpos + 2)[0]
        seg_base = struct.unpack_from("<I", data, dpos + 4)[0]
        seg_size = struct.unpack_from("<I", data, dpos + 8)[0]

        flag_name = "IBB" if seg_flags == 0 else "NON_IBB"

        fields[f"TxtSegment[{i}].Reserved"] = f"0x{seg_reserved:04X}"
        fields[f"TxtSegment[{i}].Flags"] = f"0x{seg_flags:04X} ({flag_name})"
        fields[f"TxtSegment[{i}].Base"] = f"0x{seg_base:08X}"
        fields[f"TxtSegment[{i}].Size"] = f"0x{seg_size // 16:08X}"

        dpos += 12

    return fields


def parse_pcd_element(data, offset):
    """Parse PLATFORM_CONFIG_DATA_ELEMENT at offset."""

    fields = {}

    if offset + 16 > len(data):
        return fields

    pos = offset + 8

    fields["StructVersion"] = f"0x{data[pos]:02X}"; pos += 1
    fields["Reserved0"] = data[pos]; pos += 1
    fields["ElementSize"] = f"0x{struct.unpack_from('<H', data, pos)[0]:04X}"; pos += 2
    fields["Reserved1"] = struct.unpack_from("<H", data, pos)[0]; pos += 2
    fields["SizeOfData"] = f"0x{struct.unpack_from('<H', data, pos)[0]:04X}"; pos += 2

    data_size = int(fields["SizeOfData"], 16)
    if data_size > 0 and pos + data_size <= len(data):
        fields["Data (preview)"] = hex_dump(data[pos: pos + data_size])

    return fields


def parse_pmda_element(data, offset):
    """Parse PLATFORM_MANUFACTURER_ELEMENT at offset."""

    fields = {}

    if offset + 16 > len(data):
        return fields

    pos = offset + 8

    fields["StructVersion"] = f"0x{data[pos]:02X}"; pos += 1
    fields["Reserved0"] = data[pos]; pos += 1
    fields["ElementSize"] = struct.unpack_from("<H", data, pos)[0]; pos += 2
    fields["Reserved1"] = struct.unpack_from("<H", data, pos)[0]; pos += 2
    fields["PmDataSize"] = struct.unpack_from("<H", data, pos)[0]; pos += 2

    pm_size = fields["PmDataSize"]

    if pm_size > 0 and pos + pm_size <= len(data):
        fields["PmData (preview)"] = hex_dump(data[pos: pos + pm_size])

    return fields


def parse_pmsg_element(data, offset):
    """Parse BOOT_POLICY_MANIFEST_SIGNATURE_ELEMENT at offset."""

    fields = {}

    if offset + 12 > len(data):
        return fields

    pos = offset + 8

    fields["StructVersion"] = f"0x{data[pos]:02X}"; pos += 1
    fields["Reserved"] = data[pos:pos+3].hex(); pos += 3

    # KEY_AND_SIGNATURE_STRUCT
    pos = parse_key_and_signature(data, pos, "KeySig", fields)

    return fields


PARSERS = {
    b"__KEYM__": ("Key Manifest", parse_key_manifest),
    b"__ACBP__": ("BPM Header", parse_bpm_header),
    b"__IBBS__": ("IBB Element", parse_ibb_element),
    b"__TXTS__": ("TXT Element", parse_txt_element),
    b"__PCDS__": ("PCD Element", parse_pcd_element),
    b"__PMDA__": ("Platform Manufacturer Element", parse_pmda_element),
    b"__PMSG__": ("BPM Signature Element", parse_pmsg_element),
}


def print_fields(fields, indent=4):
    if not fields:
        print(f"{' ' * indent}(no fields parsed)")
        return

    max_key = max(len(k) for k in fields)

    for key, val in fields.items():
        print(f"{' ' * indent}{key:<{max_key}} : {val}")


def find_all_occurrences(data, pattern):
    """Find all offsets of pattern in data."""

    offsets = []
    start = 0

    while True:
        idx = data.find(pattern, start)
        if idx == -1:
            break
        offsets.append(idx)
        start = idx + 1

    return offsets


def main():
    parser = argparse.ArgumentParser(
        description="Parse Boot Guard structures from a binary file."
    )

    parser.add_argument("binfile", help="Path to the binary file to parse")
    args = parser.parse_args()

    bin_path = Path(args.binfile)
    if not bin_path.is_file():
        print(f"Error: '{bin_path}' not found or is not a file.", file=sys.stderr)
        sys.exit(1)

    data = bin_path.read_bytes()
    print(f"Loaded '{bin_path}' ({len(data)} bytes / 0x{len(data):X})\n")

    # --- Search for FIT table ---
    print("=" * 70)
    print("Searching for Firmware Interface Table (FIT)")
    print("=" * 70)

    fit_offsets = find_all_occurrences(data, FIT_SIGNATURE)

    if not fit_offsets:
        print("  FIT signature not found.\n")
    else:
        for off in fit_offsets:
            entries = parse_fit_table(data, off)

            if not entries:
                continue

            header = entries[0]
            num = header.get("NumEntries", 0)
            ver = header.get("Version", "")

            # Skip invalid FIT: must have entries and a valid version
            if num == 0 or ver != "0x0100":
                continue

            print(f"\n  FIT found at offset 0x{off:08X}")
            print(f"  Number of entries: {num}")
            print(f"  {'Idx':<5} {'Type':<30} {'Address':<20} {'Size':<12} {'Ver':<8} {'C_V':<5} {'Chk'}")
            print(f"  {'-'*5} {'-'*30} {'-'*20} {'-'*12} {'-'*8} {'-'*5} {'-'*6}")

            for e in entries:
                idx = e.get("Index", "")
                typ = e.get("Type", "")
                addr = e.get("Address", "")
                sz = e.get("Size", e.get("NumEntries", ""))
                ver = e.get("Version", "")
                cv = e.get("C_V", "")
                cs = e.get("Checksum", "")
                print(f"  {idx:<5} {typ:<30} {addr:<20} {str(sz):<12} {ver:<8} {str(cv):<5} {cs}")

            print()

    # --- Search for Boot Guard structures ---
    print("=" * 70)
    print("Searching for Boot Guard structures")
    print("=" * 70)

    for sig, description in SIGNATURES.items():
        offsets = find_all_occurrences(data, sig)
        if not offsets:
            continue

        for off in offsets:
            # Validate StructVersion (byte right after the 8-byte signature)
            if off + 9 > len(data):
                continue
            struct_version = data[off + 8]
            if struct_version == 0x00:
                continue

            print(f"\n  [{description}] found at offset 0x{off:08X}")
            if sig in PARSERS:
                name, parse_fn = PARSERS[sig]
                fields = parse_fn(data, off)
                print_fields(fields)

    print("\nDone.")

if __name__ == "__main__":
    main()
