import argparse
import os
import pathlib

# Check the tag type and dump size using the SAK
def guess_mifare_size_by_sak(SAK):
    sakk = {
        "18": "4K",
        "08": "1K",
        "88": "1K",
        "11": "4K",
        "09": "MINI",
        "89": "MINI",
    }
    return sakk.get(SAK, "1K")

# Add spaces to each byte A0A1A2 -> A0 A1 A2
def add_spaces_to_hex(in_str):
    out_str = ""
    for i in range(0, len(in_str), 2):
        out_str += in_str[i:i+2] + " "
    return out_str.strip()

# Determine UID size accurately based on the first byte of block 0
def check_uid_size(dump):
    block0 = dump[0]
    if block0[0] != '0' and block0[1] != '8' and block0[1] != 'F':
        return 4
    elif block0[0] == '0' and block0[1] == '8' and block0[1] == 'F':
        return 7
    else:
        # Handle the case where the UID size cannot be determined
        raise ValueError("Unable to determine UID size")

# Open the NFC file and create an array with all the blocks
def convert_file(input_path):
    input_extension = os.path.splitext(input_path)[1]
    
    if input_extension == ".dump" or input_extension == ".mct":
        with open(input_path, "rt") as file:
            dump = []
            Lines = file.readlines()
            count = 0
            for line in Lines:
                count += 1
                if(line[0] != "+"):
                    dump.append(line.strip())
        return dump
    else:
        raise ValueError(f"Unsupported file extension: {input_extension}")

# Information about the Mifare Classic tag
def write_mifare_info(f, dump):
    uid_size = check_uid_size(dump)
    uid_hex = dump[0][:14] if uid_size == 7 else dump[0][:8]
    atqa_hex = dump[0][16:20] if uid_size == 7 else dump[0][12:16]
    sak_hex = dump[0][14:16] if uid_size == 7 else dump[0][10:12]

    f.write(f"UID: {add_spaces_to_hex(uid_hex)}\n")
    f.write(f"ATQA: {add_spaces_to_hex(atqa_hex)}\n")
    f.write(f"SAK: {add_spaces_to_hex(sak_hex)}\n")

    mifare_size = guess_mifare_size_by_sak(sak_hex)
    f.write(f"Mifare Classic type: {mifare_size}\n")

# Write the Flipper NFC file
def write_flipper_nfc(output_path, dump):
    with open(output_path, 'w') as f:
        f.write('Filetype: Flipper NFC device\n')
        f.write('Version: 4\n')
        f.write('# Device type can be ISO14443-3A, ISO14443-3B, ISO14443-4A, ISO14443-4B, ISO15693-3, FeliCa, NTAG/Ultralight, Mifare Classic, Mifare DESFire, SLIX, ST25TB\n')
        f.write('Device type: Mifare Classic\n')
        f.write('# UID, ATQA and SAK are common for all formats\n')

        write_mifare_info(f, dump)

        f.write('Data format version: 2\n')
        f.write('# Mifare Classic blocks, \'??\' means unknown data\n')
        for block, data in enumerate(dump):
            f.write(f'Block {block}: {add_spaces_to_hex(data).replace("--", "??")}\n')

# Get the input and output file paths
def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-i",
        "--input-path",
        required=True,
        type=pathlib.Path,
        help="Input file, e.g., nfc_convert.py -i file.dump -o file.nfc",
    )
    parser.add_argument(
        "-o",
        "--output-path",
        required=True,
        type=pathlib.Path,
        help="Output file, e.g., nfc_convert.py -i file.dump -o file.nfc",
    )

    args = parser.parse_args()
    return args

def main():
    args = get_args()

    if os.path.isfile(args.input_path):
        if not args.output_path:
            args.output_path = os.path.split(args.input_path)[0]
    
    dump = convert_file(args.input_path)
    write_flipper_nfc(args.output_path, dump)

if __name__ == "__main__":
    main()
