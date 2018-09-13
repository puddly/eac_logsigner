#!/usr/bin/python

import sys
import argparse
import contextlib

CHECKSUM_MIN_VERSION = ('V1.0', 'beta', '1')


def BYTE4(n):
    return (n & 0xFF000000) >> 24

def BYTE3(n):
    return (n & 0x00FF0000) >> 16

def BYTE2(n):
    return (n & 0x0000FF00) >> 8

def BYTE1(n):
    return (n & 0x000000FF) >> 0

def rotate_right(n):
    return ((n & 0x000000FF) << 24) | (n >> 8)


UNKNOWNS = [0x6C717893, 0x65423EF1, 0x8E3355AE, 0x61370B94, 0x9E38DA84, 0x26776450, 0x346F5FB3, 0xD9EFE31E, 0x1E44A783, 0x7B069972, 0xF535CCDC, 0x9402C748, 0xBC4F1CD6, 0x9A387886, 0xAE572735, 0x77B8C42B, 0xEFB1CB9D, 0x94B752EF, 0x61829E33, 0xF580597B, 0x5A82D7F7, 0xC0BAAF71, 0x6EED8844, 0x19554C6F, 0x476537B0, 0xD3D2655F, 0xB250FB6C, 0x47D0A217, 0xFAF2ED07, 0x3A484276, 0x54A5CA32, 0x4DF0865D, 0x0B86BBFC, 0xD854DEA3, 0x6A0425CF, 0x2DD487D8, 0x22BAFA66, 0x18F2B810, 0x4C577222, 0x01A7F47F, 0xD9FAE753, 0x01AE39F0, 0x6BAA1C3F, 0x467E9BE7, 0x7849EEF2, 0x60BB56E2, 0x2CEC24C0, 0x2D4BD0BF, 0xD1225403, 0xD08C6DF3, 0xBB2671CC, 0xFD58EA2B, 0x2C236903, 0x4C983FE1, 0x60741B21, 0x4D3FCB9E, 0xDAC1215C, 0x0A4D4CAF, 0xB16B3D63, 0x4C33D748, 0x05E06751, 0x497858B0, 0x290C4391, 0x6433880F, 0xAC82E218, 0xA6CFAEB7, 0x17A493D4, 0x5B97449C, 0x3C687C8F, 0x7510243F, 0x5C1C67AE, 0x382FEFA1, 0x9E85F7DC, 0x384A596B, 0x2FEECABF, 0x74798E23, 0xAEDE65A9, 0xDBCE4196, 0x87D22638, 0xBFFDC999, 0x708DA337, 0x48C7FA5C, 0x672930E3, 0x1350BEC0, 0xD38DCB13, 0x08438A85, 0x8F91ACBD, 0x306C6524, 0x4689F316, 0x0E4E094A, 0x696739A9, 0x7A378769, 0x0917DCEA, 0x0154566F, 0x8EC5FAD2, 0xBEA99FF6, 0x04272015, 0x0A69295F, 0x630E10F6, 0x1939979F, 0xDD055431, 0xDC51025E, 0x5294F88C, 0xEC3D677A, 0xDEE9073B, 0xD4802E64, 0xB78E3E92, 0xAEB7A90D, 0x39AC87E6, 0xE5FD85B8, 0xB7697D34, 0x5B541A4E, 0xF1D027D4, 0x255009B0, 0x92DE3722, 0x3C699E2F, 0xD2558CF3, 0x37A8094B, 0x80C1747F, 0xDB956E31]
S_BOX = [0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76, 0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0, 0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15, 0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75, 0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84, 0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF, 0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8, 0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2, 0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73, 0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB, 0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79, 0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08, 0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A, 0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E, 0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF, 0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16]

T1 = [0xC6A56363, 0xF8847C7C, 0xEE997777, 0xF68D7B7B, 0xFF0DF2F2, 0xD6BD6B6B, 0xDEB16F6F, 0x9154C5C5, 0x60503030, 0x02030101, 0xCEA96767, 0x567D2B2B, 0xE719FEFE, 0xB562D7D7, 0x4DE6ABAB, 0xEC9A7676, 0x8F45CACA, 0x1F9D8282, 0x8940C9C9, 0xFA877D7D, 0xEF15FAFA, 0xB2EB5959, 0x8EC94747, 0xFB0BF0F0, 0x41ECADAD, 0xB367D4D4, 0x5FFDA2A2, 0x45EAAFAF, 0x23BF9C9C, 0x53F7A4A4, 0xE4967272, 0x9B5BC0C0, 0x75C2B7B7, 0xE11CFDFD, 0x3DAE9393, 0x4C6A2626, 0x6C5A3636, 0x7E413F3F, 0xF502F7F7, 0x834FCCCC, 0x685C3434, 0x51F4A5A5, 0xD134E5E5, 0xF908F1F1, 0xE2937171, 0xAB73D8D8, 0x62533131, 0x2A3F1515, 0x080C0404, 0x9552C7C7, 0x46652323, 0x9D5EC3C3, 0x30281818, 0x37A19696, 0x0A0F0505, 0x2FB59A9A, 0x0E090707, 0x24361212, 0x1B9B8080, 0xDF3DE2E2, 0xCD26EBEB, 0x4E692727, 0x7FCDB2B2, 0xEA9F7575, 0x121B0909, 0x1D9E8383, 0x58742C2C, 0x342E1A1A, 0x362D1B1B, 0xDCB26E6E, 0xB4EE5A5A, 0x5BFBA0A0, 0xA4F65252, 0x764D3B3B, 0xB761D6D6, 0x7DCEB3B3, 0x527B2929, 0xDD3EE3E3, 0x5E712F2F, 0x13978484, 0xA6F55353, 0xB968D1D1, 0x0, 0xC12CEDED, 0x40602020, 0xE31FFCFC, 0x79C8B1B1, 0xB6ED5B5B, 0xD4BE6A6A, 0x8D46CBCB, 0x67D9BEBE, 0x724B3939, 0x94DE4A4A, 0x98D44C4C, 0xB0E85858, 0x854ACFCF, 0xBB6BD0D0, 0xC52AEFEF, 0x4FE5AAAA, 0xED16FBFB, 0x86C54343, 0x9AD74D4D, 0x66553333, 0x11948585, 0x8ACF4545, 0xE910F9F9, 0x04060202, 0xFE817F7F, 0xA0F05050, 0x78443C3C, 0x25BA9F9F, 0x4BE3A8A8, 0xA2F35151, 0x5DFEA3A3, 0x80C04040, 0x058A8F8F, 0x3FAD9292, 0x21BC9D9D, 0x70483838, 0xF104F5F5, 0x63DFBCBC, 0x77C1B6B6, 0xAF75DADA, 0x42632121, 0x20301010, 0xE51AFFFF, 0xFD0EF3F3, 0xBF6DD2D2, 0x814CCDCD, 0x18140C0C, 0x26351313, 0xC32FECEC, 0xBEE15F5F, 0x35A29797, 0x88CC4444, 0x2E391717, 0x9357C4C4, 0x55F2A7A7, 0xFC827E7E, 0x7A473D3D, 0xC8AC6464, 0xBAE75D5D, 0x322B1919, 0xE6957373, 0xC0A06060, 0x19988181, 0x9ED14F4F, 0xA37FDCDC, 0x44662222, 0x547E2A2A, 0x3BAB9090, 0x0B838888, 0x8CCA4646, 0xC729EEEE, 0x6BD3B8B8, 0x283C1414, 0xA779DEDE, 0xBCE25E5E, 0x161D0B0B, 0xAD76DBDB, 0xDB3BE0E0, 0x64563232, 0x744E3A3A, 0x141E0A0A, 0x92DB4949, 0x0C0A0606, 0x486C2424, 0xB8E45C5C, 0x9F5DC2C2, 0xBD6ED3D3, 0x43EFACAC, 0xC4A66262, 0x39A89191, 0x31A49595, 0xD337E4E4, 0xF28B7979, 0xD532E7E7, 0x8B43C8C8, 0x6E593737, 0xDAB76D6D, 0x018C8D8D, 0xB164D5D5, 0x9CD24E4E, 0x49E0A9A9, 0xD8B46C6C, 0xACFA5656, 0xF307F4F4, 0xCF25EAEA, 0xCAAF6565, 0xF48E7A7A, 0x47E9AEAE, 0x10180808, 0x6FD5BABA, 0xF0887878, 0x4A6F2525, 0x5C722E2E, 0x38241C1C, 0x57F1A6A6, 0x73C7B4B4, 0x9751C6C6, 0xCB23E8E8, 0xA17CDDDD, 0xE89C7474, 0x3E211F1F, 0x96DD4B4B, 0x61DCBDBD, 0x0D868B8B, 0x0F858A8A, 0xE0907070, 0x7C423E3E, 0x71C4B5B5, 0xCCAA6666, 0x90D84848, 0x06050303, 0xF701F6F6, 0x1C120E0E, 0xC2A36161, 0x6A5F3535, 0xAEF95757, 0x69D0B9B9, 0x17918686, 0x9958C1C1, 0x3A271D1D, 0x27B99E9E, 0xD938E1E1, 0xEB13F8F8, 0x2BB39898, 0x22331111, 0xD2BB6969, 0xA970D9D9, 0x07898E8E, 0x33A79494, 0x2DB69B9B, 0x3C221E1E, 0x15928787, 0xC920E9E9, 0x8749CECE, 0xAAFF5555, 0x50782828, 0xA57ADFDF, 0x038F8C8C, 0x59F8A1A1, 0x09808989, 0x1A170D0D, 0x65DABFBF, 0xD731E6E6, 0x84C64242, 0xD0B86868, 0x82C34141, 0x29B09999, 0x5A772D2D, 0x1E110F0F, 0x7BCBB0B0, 0xA8FC5454, 0x6DD6BBBB, 0x2C3A1616]
T2 = list(map(rotate_right, T1))
T3 = list(map(rotate_right, T2))
T4 = list(map(rotate_right, T3))


def eac_checksum(text):
    # Ignore newlines
    text = text.replace('\r', '').replace('\n', '')

    # Fuzzing reveals BOMs are ignored
    text = text.replace('\ufeff', '').replace('\ufffe', '')

    # Initialize the "AES" state
    aes_state = [0, 0, 0, 0, 0, 0, 0, 0]

    # Read the text in chunks of 16
    for i in range(0, len(text), 16):
        # Pad the final chunk with zero bytes
        chunk = text[i:i + 16].ljust(16, '\x00')

        # Mix pairs of characters into the AES state
        for i, offset in enumerate(range(0, 16, 2)):
            aes_state[i] ^= int.from_bytes(chunk[offset:offset + 2].encode('utf-16le'), 'little')

        # Perform one "AES" round
        a1 = UNKNOWNS[0] ^ aes_state[0]
        a2 = UNKNOWNS[1] ^ aes_state[1]
        a3 = UNKNOWNS[2] ^ aes_state[2]
        a4 = UNKNOWNS[3] ^ aes_state[3]
        a5 = UNKNOWNS[4] ^ aes_state[4]
        a6 = UNKNOWNS[5] ^ aes_state[5]
        a7 = UNKNOWNS[6] ^ aes_state[6]
        a8 = UNKNOWNS[7] ^ aes_state[7]

        for i in range(0, 13):
            b1 = UNKNOWNS[ 8 + 8 * i] ^ (T1[BYTE4(a5)] ^ T2[BYTE3(a4)] ^ T3[BYTE2(a2)] ^ T4[BYTE1(a1)])
            b2 = UNKNOWNS[ 9 + 8 * i] ^ (T1[BYTE4(a6)] ^ T2[BYTE3(a5)] ^ T3[BYTE2(a3)] ^ T4[BYTE1(a2)])
            b3 = UNKNOWNS[10 + 8 * i] ^ (T1[BYTE4(a7)] ^ T2[BYTE3(a6)] ^ T3[BYTE2(a4)] ^ T4[BYTE1(a3)])
            b4 = UNKNOWNS[11 + 8 * i] ^ (T1[BYTE4(a8)] ^ T2[BYTE3(a7)] ^ T3[BYTE2(a5)] ^ T4[BYTE1(a4)])
            b5 = UNKNOWNS[12 + 8 * i] ^ (T1[BYTE4(a1)] ^ T2[BYTE3(a8)] ^ T3[BYTE2(a6)] ^ T4[BYTE1(a5)])
            b6 = UNKNOWNS[13 + 8 * i] ^ (T1[BYTE4(a2)] ^ T2[BYTE3(a1)] ^ T3[BYTE2(a7)] ^ T4[BYTE1(a6)])
            b7 = UNKNOWNS[14 + 8 * i] ^ (T1[BYTE4(a3)] ^ T2[BYTE3(a2)] ^ T3[BYTE2(a8)] ^ T4[BYTE1(a7)])
            b8 = UNKNOWNS[15 + 8 * i] ^ (T1[BYTE4(a4)] ^ T2[BYTE3(a3)] ^ T3[BYTE2(a1)] ^ T4[BYTE1(a8)])

            a1 = b1
            a2 = b2
            a3 = b3
            a4 = b4
            a5 = b5
            a6 = b6
            a7 = b7
            a8 = b8

        aes_state[0] = UNKNOWNS[112] ^ ((S_BOX[BYTE4(a5)] << 24) | (S_BOX[BYTE3(a4)] << 16) | (S_BOX[BYTE2(a2)] << 8) | S_BOX[BYTE1(a1)])
        aes_state[1] = UNKNOWNS[113] ^ ((S_BOX[BYTE4(a6)] << 24) | (S_BOX[BYTE3(a5)] << 16) | (S_BOX[BYTE2(a3)] << 8) | S_BOX[BYTE1(a2)])
        aes_state[2] = UNKNOWNS[114] ^ ((S_BOX[BYTE4(a7)] << 24) | (S_BOX[BYTE3(a6)] << 16) | (S_BOX[BYTE2(a4)] << 8) | S_BOX[BYTE1(a3)])
        aes_state[3] = UNKNOWNS[115] ^ ((S_BOX[BYTE4(a8)] << 24) | (S_BOX[BYTE3(a7)] << 16) | (S_BOX[BYTE2(a5)] << 8) | S_BOX[BYTE1(a4)])
        aes_state[4] = UNKNOWNS[116] ^ ((S_BOX[BYTE4(a1)] << 24) | (S_BOX[BYTE3(a8)] << 16) | (S_BOX[BYTE2(a6)] << 8) | S_BOX[BYTE1(a5)])
        aes_state[5] = UNKNOWNS[117] ^ ((S_BOX[BYTE4(a2)] << 24) | (S_BOX[BYTE3(a1)] << 16) | (S_BOX[BYTE2(a7)] << 8) | S_BOX[BYTE1(a6)])
        aes_state[6] = UNKNOWNS[118] ^ ((S_BOX[BYTE4(a3)] << 24) | (S_BOX[BYTE3(a2)] << 16) | (S_BOX[BYTE2(a8)] << 8) | S_BOX[BYTE1(a7)])
        aes_state[7] = UNKNOWNS[119] ^ ((S_BOX[BYTE4(a4)] << 24) | (S_BOX[BYTE3(a3)] << 16) | (S_BOX[BYTE2(a1)] << 8) | S_BOX[BYTE1(a8)])

    # Dump out the "AES" state as hex
    return b''.join(n.to_bytes(4, 'little') for n in aes_state).hex().upper()


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
