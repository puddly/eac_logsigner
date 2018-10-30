#!/usr/bin/python

import sys
import argparse
import contextlib

import pprp

CHECKSUM_MIN_VERSION = ('V1.0', 'beta', '1')


def eac_checksum(text):
    # Ignore newlines
    text = text.replace('\r', '').replace('\n', '')

    # Fuzzing reveals BOMs are also ignored
    text = text.replace('\ufeff', '').replace('\ufffe', '')

    # Setup Rijndael-256 with a 256-bit blocksize
    cipher = pprp.crypto_3.rijndael(
        # Probably SHA256('super secret password') but it doesn't actually matter
        key=bytes.fromhex('9378716cf13e4265ae55338e940b376184da389e50647726b35f6f341ee3efd9'),
        block_size=256 // 8
    )

    # Encode the text as UTF-16-LE
    plaintext = text.encode('utf-16-le')

    # The IV is all zeroes so we don't have to handle it
    signature = b'\x00' * 32

    # Process it block-by-block
    for i in range(0, len(plaintext), 32):
        # Zero-pad the last block, if necessary
        plaintext_block = plaintext[i:i + 32].ljust(32, b'\x00')

        # CBC mode (XOR the previous ciphertext block into the plaintext)
        cbc_plaintext = bytes(a ^ b for a, b in zip(signature, plaintext_block))

        # New signature is the ciphertext.
        signature = cipher.encrypt(cbc_plaintext)

    # Textual signature is just the hex representation
    return signature.hex().upper()


def extract_info(text):
    version = text.splitlines()[0]

    if not version.startswith('Exact Audio Copy'):
        version = None
    else:
        version = tuple(version.split()[3:6])

    if '\r\n\r\n==== Log checksum' not in text:
        signature = None
    else:
        text, signature_parts = text.split('\r\n\r\n==== Log checksum', 1)
        signature = signature_parts.split()[0].strip()

    return text, version, signature


def eac_verify(data):
    # Log is encoded as Little Endian UTF-16
    text = data.decode('utf-16-le')

    # Strip off the BOM
    if text.startswith('\ufeff'):
        text = text[1:]

    # Null bytes screw it up
    if '\x00' in text:
        text = text[:text.index('\x00')]

    # EAC crashes if there are more than 2^14 bytes in a line
    if any(len(l) + 1 > 2**13 for l in text.split('\n')):
        raise RuntimeError('EAC cannot handle lines longer than 2^13 chars')

    unsigned_text, version, old_signature = extract_info(text)

    return unsigned_text, version, old_signature, eac_checksum(unsigned_text)


class FixedFileType(argparse.FileType):
    def __call__(self, string):
        file = super().__call__(string)

        # Properly handle stdin/stdout with 'b' mode
        if 'b' in self._mode and file in (sys.stdin, sys.stdout):
            return file.buffer

        return file


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Verifies and resigns EAC logs')

    subparsers = parser.add_subparsers(dest='command', required=True)

    verify_parser = subparsers.add_parser('verify', help='verify a log')
    verify_parser.add_argument('files', type=FixedFileType(mode='rb'), nargs='+', help='input log file(s)')

    sign_parser = subparsers.add_parser('sign', help='sign or fix an existing log')
    sign_parser.add_argument('--force', action='store_true', help='forces signing even if EAC version is too old')
    sign_parser.add_argument('input_file', type=FixedFileType(mode='rb'), help='input log file')
    sign_parser.add_argument('output_file', type=FixedFileType(mode='wb'), help='output log file')

    args = parser.parse_args()

    if args.command == 'sign':
        with contextlib.closing(args.input_file) as handle:
            try:
                data, version, old_signature, actual_signature = eac_verify(handle.read())
            except ValueError as e:
                print(args.input_file, ': ', e, sep='')
                sys.exit(1)

        if not args.force and (version is None or version <= CHECKSUM_MIN_VERSION):
            raise ValueError('EAC version is too old to be signed')

        data += f'\r\n\r\n==== Log checksum {actual_signature} ====\r\n'

        with contextlib.closing(args.output_file or args.input_file) as handle:
            handle.write(b'\xff\xfe' + data.encode('utf-16le'))
    elif args.command == 'verify':
        max_length = max(len(f.name) for f in args.files)

        for file in args.files:
            prefix = (file.name + ':').ljust(max_length + 2)

            with contextlib.closing(file) as handle:
                try:
                    data, version, old_signature, actual_signature = eac_verify(handle.read())
                except RuntimeError as e:
                    print(prefix, e)
                    continue
                except ValueError as e:
                    print(prefix, 'Not a log file')
                    continue

            if version is None:
                print(prefix, 'Not a log file')
            elif old_signature is None:
                print(prefix, 'Log file without a signature')
            elif old_signature != actual_signature:
                print(prefix, 'Malformed')
            elif version <= CHECKSUM_MIN_VERSION:
                print(prefix, 'Forged')
            else:
                print(prefix, 'OK')
