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


def hex_dump(data, max_bytes=64):
    """Return a hex string of data, truncated if needed."""
    preview = data[:max_bytes].hex(" ")
    if len(data) > max_bytes:
        preview += " ..."
    return preview


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
        entries.append({
            "Index": i,
            "Address": f"0x{addr:016X}",
            "Size (x16)": sz,
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
    fields["KeyCount"] = struct.unpack_from("<H", data, pos)[0]; pos += 2

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

    # PostIbbHash: SHAX_HASH_STRUCTURE (HashAlg, Size, then HashBuffer[])
    if pos + 4 <= len(data):
        hash_alg = struct.unpack_from("<H", data, pos)[0]
        hash_size = struct.unpack_from("<H", data, pos + 2)[0]
        fields["PostIbbHash.HashAlg"] = f"0x{hash_alg:04X}"
        fields["PostIbbHash.Size"] = hash_size
        if pos + 4 + hash_size <= len(data):
            fields["PostIbbHash.Data"] = data[pos + 4: pos + 4 + hash_size].hex()

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

    # DigestList: HASH_LIST (Size, Count)
    if pos + 4 <= len(data):
        dl_size = struct.unpack_from("<H", data, pos)[0]
        dl_count = struct.unpack_from("<H", data, pos + 2)[0]
        fields["DigestList.Size"] = dl_size
        fields["DigestList.Count"] = dl_count

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

    # KEY_AND_SIGNATURE_STRUCT starts here
    if pos + 3 <= len(data):
        fields["KeySig.Version"] = f"0x{data[pos]:02X}"
        key_alg = struct.unpack_from("<H", data, pos + 1)[0]
        fields["KeySig.KeyAlg"] = f"0x{key_alg:04X}"
        alg_name = {0x1: "RSA", 0x23: "ECC"}.get(key_alg, "Unknown")
        fields["KeySig.KeyAlg_Name"] = alg_name

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
            print(f"\n  FIT found at offset 0x{off:08X}")
            entries = parse_fit_table(data, off)
            if entries:
                header = entries[0]
                print(f"  Number of entries: {header.get('NumEntries', '?')}")
                print(f"  {'Idx':<5} {'Type':<30} {'Address':<20} {'Size(x16)':<12} {'Ver':<8} {'C_V':<5} {'Chk'}")
                print(f"  {'-'*5} {'-'*30} {'-'*20} {'-'*12} {'-'*8} {'-'*5} {'-'*6}")
                for e in entries:
                    idx = e.get("Index", "")
                    typ = e.get("Type", "")
                    addr = e.get("Address", "")
                    sz = e.get("Size (x16)", e.get("NumEntries", ""))
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
            print(f"\n  [{description}] found at offset 0x{off:08X}")
            if sig in PARSERS:
                name, parse_fn = PARSERS[sig]
                fields = parse_fn(data, off)
                print_fields(fields)

    print("\nDone.")


if __name__ == "__main__":
    main()
