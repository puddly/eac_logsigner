# EAC Log Signer

This is a transparent implementation of the Exact Audio Copy log checksum algorithm in Python 3.6+. Includes an option to fix those pesky edited logs.

# Installation

Only depends on `pprp` (for an implementation of Rijndael-256 with variable block sizes):

    $ pip install pprp
    $ curl https://raw.githubusercontent.com/puddly/eac_logsigner/master/eac.py > eac_logsigner
    $ chmod +x eac_logsigner

# Usage

    usage: eac.py [-h] {verify,sign} ...

    Verifies and resigns EAC logs

    positional arguments:
      {verify,sign}
        verify       verify a log
        sign         sign or fix an existing log

    optional arguments:
      -h, --help     show this help message and exit

# Example

    $ python3 eac.py sign bad.log good.log
    $ python3 eac.py verify *.log
    log1.log:  OK
    log2.log:  OK
    log3.log:  Malformed


# Algorithm

 1. Strip the log file of newlines and BOMs.
 2. Cut off the existing signature block and (re-)encode the log text back into little-endian UTF-16
 3. Encrypt the log file with Rijndael-256:
    - in CBC mode
    - with a 256-bit block size (most AES implementations hard-code a 128-bit block size)
    - all-zeroes IV
    - zero-padding
    - the hex key `9378716cf13e4265ae55338e940b376184da389e50647726b35f6f341ee3efd9`
 4. XOR together all of the resulting 256-bit ciphertext blocks. You can do it byte-by-byte, it doesn't matter in the end.
 5. Output the little-endian representation of the above number, in uppercase hex.
