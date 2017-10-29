# EAC Log Signer

This is a transparent implementation of the EAC log checksum algorithm in Python 3.6+. Includes an option to fix those pesky edited logs.

# Usage

    usage: eac.py [-h] (--verify | --sign) FILE

    Verifies and resigns EAC logs

    positional arguments:
      FILE        path to the log file

    optional arguments:
      -h, --help  show this help message and exit
      --verify    verify a log
      --sign      sign or fix an existing log

# Overview

The algorithm internally uses UTF-16 strings and XORs a refilling 32-byte buffer of characters with the internal state of an AES-256 process. The code is pretty short, go read it for more info. Open a pull request if you can figure out a way to simplify the AES-256 stuff.
