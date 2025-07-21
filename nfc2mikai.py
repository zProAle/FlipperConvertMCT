import argparse
from pathlib import Path
import re

def parse_block_line(line):
    match = re.match(r"Block\s+(\d+):\s+([0-9A-Fa-f ]{11})", line)
    if not match:
        return None
    index = int(match.group(1))
    block = bytes(int(x, 16) for x in match.group(2).strip().split())
    return index, block

def parse_uid(line):
    match = re.match(r"UID:\s+([0-9A-Fa-f ]+)", line)
    if not match:
        return None
    return bytes(int(x, 16) for x in match.group(1).strip().split())

def convert_nfc_to_bin(nfc_path: Path, bin_path: Path):
    blocks = {}
    uid = None

    with open(nfc_path, 'r') as file:
        for line in file:
            line = line.strip()
            if line.startswith("UID:"):
                uid = parse_uid(line)
            elif line.startswith("Block "):
                result = parse_block_line(line)
                if result:
                    idx, data = result
                    blocks[idx] = data

    if len(blocks) != 128:
        print(f"[WARNING] Expected 128 blocks, found {len(blocks)}")

    data = bytearray()
    for i in range(128):  # 128 blocks = 0x200 bytes
        block = blocks.get(i, b'\x00\x00\x00\x00')
        data.extend(block)

    if uid:
        data.extend(uid)
    else:
        print("[WARNING] UID not found — appending zeros")
        data.extend(b'\x00' * 8)

    with open(bin_path, 'wb') as out:
        out.write(data)

    print(f"[✓] Converted to binary: {bin_path}")
    print(f"    Total size: {len(data)} bytes")
    print(f"    UID: {uid.hex(' ').upper() if uid else 'UNKNOWN'}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Convert Flipper .nfc (ST25TB) to raw binary")
    parser.add_argument('-i', '--input', required=True, help="Input .nfc file")
    parser.add_argument('-o', '--output', required=True, help="Output .bin file")
    args = parser.parse_args()

    convert_nfc_to_bin(Path(args.input), Path(args.output))

