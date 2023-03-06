import argparse
import os
import pathlib
import time

#Controllo che tipo di tag è e la dimensine del dump tramite il SAK
def guess_mifare_size_by_sak(SAK):
    sakk = {
        "18": "4K",
        "08": "1K",
        "88": "1K",
        "11": "4K",
    }
    return sakk.get(SAK, "1K")

# aggiungo gli spazi ad ogni byte A0A1A2 -> A0 A1 A2
def add_spaces_to_hex(in_str):
  out_str = ""
  for i in range(0, len(in_str), 2):
    out_str += in_str[i:i+2] + " "
  return out_str.strip()

#Tramite il primo byte del blocco 0 riesco a determinare in modo accurato se un uid è a 4/7 byte
def check_uid_size(dump):
    block0 = dump[0]
    if (block0[0] != '0' and block0[1] != '8' and block0[1] != 'F'):
        return 4
    else: 
        return 7

#apro il file in formato nfc e creo un array con tutti i blocchi
def convert_file(input_path):
    input_extension = os.path.splitext(input_path)[1]
    if input_extension == ".dump":
        with open(input_path, "rt") as file:
            dump = []
            Lines = file.readlines()
            count = 0
            for line in Lines:
                count += 1
                if(line[0] != "+"):
                    dump.append(line.strip())
        return dump

#format dump for a flipper nfc
def write_flipper_nfc(output_path, dump):
    with open(output_path, 'w') as f:
        f.write('Filetype: Flipper NFC device\n')
        f.write('Version: 2\n')
        f.write('# Nfc device type can be UID, Mifare Ultralight, Mifare Classic, Bank card\n')
        f.write('Device type: Mifare Classic\n')
        f.write('# UID, ATQA and SAK are common for all formats\n')
        if(check_uid_size(dump) == 4):
            f.write('UID: '  + add_spaces_to_hex(dump[0][0:8])  + '\n')
            f.write('ATQA: ' + add_spaces_to_hex(dump[0][12:16]) + '\n')
            f.write('SAK: '  + add_spaces_to_hex(dump[0][10:12])  + '\n')
            if guess_mifare_size_by_sak(dump[0][10:12]) == "4K":
                f.write('Mifare Classic type: 4K\n')
            elif guess_mifare_size_by_sak(dump[0][10:12]) == "1K":
                f.write('Mifare Classic type: 1K\n')
        elif(check_uid_size(dump) == 7):
            f.write('UID: '  + add_spaces_to_hex(dump[0][0:14])  + '\n')
            f.write('ATQA: ' + add_spaces_to_hex(dump[0][16:20]) + '\n')
            f.write('SAK: '  + add_spaces_to_hex(dump[0][14:16])  + '\n')
            if guess_mifare_size_by_sak(dump[0][14:16]) == "4K":
                f.write('Mifare Classic type: 4K\n')
            elif guess_mifare_size_by_sak(dump[0][14:16]) == "1K":
                f.write('Mifare Classic type: 1K\n')
        f.write('Data format version: 2\n')
        f.write('# Mifare Classic blocks, \'??\' means unknown data\n')
        for block in range(0, len(dump)):
            f.write('Block ' + str(block) + ': ' + add_spaces_to_hex(dump[block]) + '\n')

def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-i",
        "--input-path",
        required=True,
        type=pathlib.Path,
        help="File di input, Es. nfc_convert.py -i file.dump -o file.nfc",
    )
    parser.add_argument(
        "-o",
        "--output-path",
        required=True,
        type=pathlib.Path,
        help="File di output, Es. nfc_convert.py -i file.dump -o file.nfc",
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
    print("Conversione in corso")
    time.sleep(0.5)
    print("Completed Completata")
