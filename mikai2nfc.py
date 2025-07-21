import argparse
from pathlib import Path

def format_bytes(bs: bytes):
    return ' '.join(f"{b:02X}" for b in bs)

def detect_tag_and_uid(data: bytes):
    uid = None
    tag_type = "UNKNOWN"
    subtype = ""
    atqa = None
    sak = None

    if len(data) >= 0x208:
        uid_candidate = data[0x200:0x208]
        if any(b != 0 for b in uid_candidate):
            tag_type = "ST25TB"
            subtype = "4K"
            uid = uid_candidate

    if uid is None and len(data) >= 7:
        uid = data[0:7]

    return uid, tag_type, subtype, atqa, sak

def convert_to_nfc(input_file: Path, output_file: Path):
    with open(input_file, 'rb') as f:
        data = f.read()

    uid, tag_type, subtype, atqa, sak = detect_tag_and_uid(data)
    uid_str = format_bytes(uid) if uid else "UNKNOWN"

    data_to_dump = data
    if tag_type == "ST25TB" and subtype == "4K":
        data_to_dump = data[:0x200]

    lines = [
        "Filetype: Flipper NFC device",
        "Version: 4",
        "# Device type can be ISO14443-3A, ISO14443-3B, ISO14443-4A, ISO14443-4B, ISO15693-3, FeliCa, NTAG/Ultralight, Mifare Classic, Mifare Plus, Mifare DESFire, SLIX, ST25TB, NTAG4xx, Type 4 Tag, EMV",
        f"Device type: {tag_type}",
        "# UID is common for all formats",
        f"UID: {uid_str}",
    ]

    if tag_type == "ST25TB" and subtype == "4K":
        lines.append("# ST25TB specific data")
        lines.append(f"ST25TB Type: {subtype}")

    if atqa is not None:
        lines.append("# ISO14443-3A specific data")
        lines.append(f"ATQA: {format_bytes(atqa)}")
    if sak is not None:
        lines.append(f"SAK: {format_bytes(sak)}")

    for i in range(0, len(data_to_dump), 4):
        block_bytes = data_to_dump[i:i+4]
        hex_block = format_bytes(block_bytes)
        lines.append(f"Block {i//4}: {hex_block}")

    lines.append("System OTP Block: FF FF FF FE")

    with open(output_file, 'w') as f:
        f.write('\n'.join(lines))

    print(f"[✓] .nfc file generated: {output_file}")
    print(f"    UID: {uid_str}")
    print(f"    Type: {tag_type} — Subtype: {subtype}")
    if atqa is not None:
        print(f"    ATQA: {format_bytes(atqa)}")
    if sak is not None:
        print(f"    SAK: {format_bytes(sak)}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Binary Mikai dump converter to Flipper Zero .nfc")
    parser.add_argument('-i', '--input', required=True, help="Input binary dump file")
    parser.add_argument('-o', '--output', required=True, help="Output .nfc file")
    args = parser.parse_args()

    convert_to_nfc(Path(args.input), Path(args.output))
