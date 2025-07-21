# FlipperConvertMCT
Tool able to convert Mifare CLassic (mini, 1k, 4k) (uid 4/7 byte) and ST25TB 4k MCT, DUMP, or binary DMP files to flipper zero .nfc files.

## Usage:

### MFCbin2nfc.py:
Accepted input files: bin, dump, dmp, hex and without extension (must be binaries)
```
python3 MFCbin2nfc.py [-h] -i INPUT -o OUTPUT [--uid UID]

Convert a Mifare Classic dump to a .nfc file for Flipper Zero

options:
  -h, --help            show this help message and exit
  -i INPUT, --input INPUT
                        Path to the .dmp file
  -o OUTPUT, --output OUTPUT
                        Output path for the .nfc file
  --uid UID             Custom UID (e.g. FE:3B:17:86)
```

### mct2_nfc.py:
Accepted input files: mct, dump, mfd
```
python3 mct2nfc.py [-h] -i INPUT_PATH -o OUTPUT_PATH

Convert Mifare Classic dump (.mct/.dump) to .nfc file for Flipper Zero

options:
  -h, --help            show this help message and exit
  -i INPUT_PATH,
                        Input dump file (.mct or .dump)
  -o OUTPUT_PATH,
                        Output .nfc file
```

### mikai2nfc.py:
Accepted input files: bin, dump, dmp, hex and without extension (must be binaries)
```
python3: mikai2nfc.py [-h] -i INPUT -o OUTPUT

Binary Mikai dump converter to Flipper Zero .nfc

options:
  -h, --help            show this help message and exit
  -i INPUT, --input INPUT
                        Input binary dump file
  -o OUTPUT, --output OUTPUT
                        Output .nfc file
```

### nfc2mikai.py:
Accepted input files: bin, dump, dmp, hex and without extension (must be binaries)
```
python3: nfc2mikai.py [-h] -i INPUT -o OUTPUT

Binary Mikai dump converter to Flipper Zero .nfc

options:
  -h, --help            show this help message and exit
  -i INPUT, --input INPUT
                        Input binary dump file
  -o OUTPUT, --output OUTPUT
                        Output .nfc file
```
