# EAC Log Signer

This is a transparent implementation of the Exact Audio Copy log checksum algorithm in Python 3.6+. Includes an option to fix those pesky edited logs.

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


# Overview

The algorithm internally uses UTF-16 strings and XORs a refilling 32-byte buffer of characters with the internal state of what looks to be part of AES-256. The code is pretty short, go read it for more info. Open a pull request if you can figure out a way to simplify it.
