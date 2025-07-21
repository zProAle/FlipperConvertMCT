import argparse
import os

def bytes_to_hex(b):
    return ' '.join(f"{x:02X}" for x in b)

def extract_uid_and_sak(block0: bytes):
    """
    Estrae UID, tipo UID (4 o 7 byte), e SAK in base alla struttura del blocco 0.
    """
    if block0[0] == 0x88:
        uid = bytes_to_hex(block0[1:4] + block0[4:7])
        uid_type = 7
        sak = block0[8] # x UID a 7 byte
    else:
        uid = bytes_to_hex(block0[0:4])
        uid_type = 4
        sak = block0[5]  # per UID a 4 byt
    return uid, uid_type, f"{sak:02X}"

def detect_card_type_and_params(data):
    size = len(data)
    block0 = data[0:16]
    uid, uid_length, sak = extract_uid_and_sak(block0)

    if size == 1024:
        atqa = "44 00" if uid_length == 7 else "04 00"
        card_type = "1K"
        block_count = 64

    elif size == 4096:
        atqa = "04 00"
        card_type = "4K"
        block_count = 256

    elif size == 320:
        atqa = "04 00"
        card_type = "Mini"
        block_count = 20

    else:
        raise ValueError(f"Invalid dump size: {size} bytes. Must be 320 (Mini), 1024 (1K), or 4096 (4K).")

    VALID_SAK_VALUES = {"08", "09", "18", "88", "89"}
    if sak.upper() not in VALID_SAK_VALUES:
        print(f"[WARN] SAK {sak} is not standard (possibly custom or magic tag).")

    return card_type, block_count, uid, atqa, sak

def convert_dump_to_flipper_format(dump_file, output_file, uid_override=None):
    with open(dump_file, "rb") as f:
        data = f.read()

    card_type, block_count, extracted_uid, atqa, sak = detect_card_type_and_params(data)
    uid = uid_override or extracted_uid

    print(f"[INFO] Type: Mifare Classic {card_type}")
    print(f"[INFO] UID: {uid}")
    print(f"[INFO] ATQA: {atqa}")
    print(f"[INFO] SAK: {sak}")

    with open(output_file, "w") as out:
        out.write("Filetype: Flipper NFC device\n")
        out.write("Version: 4\n")
        out.write("# Device type can be ISO14443-3A, ISO14443-3B, ISO14443-4A, ISO14443-4B, ISO15693-3, FeliCa, NTAG/Ultralight, Mifare Classic, Mifare Plus, Mifare DESFire, SLIX, ST25TB, NTAG4xx, Type 4 Tag, EMV\n")
        out.write("Device type: Mifare Classic\n")
        out.write("# UID, ATQA and SAK are common for all formats\n")
        out.write(f"UID: {uid}\n")
        out.write(f"ATQA: {atqa}\n")
        out.write(f"SAK: {sak}\n")
        out.write(f"Mifare Classic type: {card_type}\n")
        out.write("Data format version: 2\n")
        out.write("# Mifare Classic blocks, '??' means unknown data\n")

        for i in range(block_count):
            block = data[i*16:(i+1)*16]
            out.write(f"Block {i}: {bytes_to_hex(block)}\n")

    print(f"[OK] File written: {output_file}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Convert a Mifare Classic dump to a .nfc file for Flipper Zero")
    parser.add_argument("-i", "--input", required=True, help="Path to the dump file (.bin/.dmp/.hex...)")
    parser.add_argument("-o", "--output", required=True, help="Output path for the .nfc file")
    parser.add_argument("--uid", help="Custom UID to override extracted one (e.g. FE:3B:17:86)")
    args = parser.parse_args()

    if not os.path.exists(args.input):
        print(f"[ERROR] Input file not found: {args.input}")
        exit(1)

    convert_dump_to_flipper_format(
        dump_file=args.input,
        output_file=args.output,
        uid_override=args.uid
    )
