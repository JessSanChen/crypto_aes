# Quest SRI
# Jessica Chen
# 7/19/2020

"""
Fixed hex() functions so that they didn't exclude the beginning '0x.'
Modified each method to work on a single block.
Only includes AES encryption for 128-bit.
Adds padding starting with 0x80 followed by necessary zeroes.
If input password is not 128 bits, it's either truncated or elongated by PBKDF2.
"""


import sys
import ast
import binascii
from backports.pbkdf2 import pbkdf2_hmac
import numpy


sbox = [0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67,
        0x2b, 0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59,
        0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7,
        0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1,
        0x71, 0xd8, 0x31, 0x15, 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05,
        0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83,
        0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29,
        0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
        0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 0xd0, 0xef, 0xaa,
        0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c,
        0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc,
        0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec,
        0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19,
        0x73, 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee,
        0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49,
        0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4,
        0xea, 0x65, 0x7a, 0xae, 0x08, 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6,
        0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 0x70,
        0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9,
        0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e,
        0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, 0x8c, 0xa1,
        0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0,
        0x54, 0xbb, 0x16]

rcon = [
    0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a,
    0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39,
    0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a,
    0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8,
    0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef,
    0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc,
    0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b,
    0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3,
    0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94,
    0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20,
    0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35,
    0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f,
    0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04,
    0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63,
    0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd,
    0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb]

mix_multiplier = [2, 3, 1, 1, 1, 2, 3, 1, 1, 1, 2, 3, 3, 1, 1, 2]


def make_hexstring(plaintext: str):
    hex_rep = str(binascii.hexlify(plaintext.encode("utf8")))[2:]
    return hex_rep


def make_blocks(hexstring: str):  # assumes plaintext already converted to hex string
    hexstring = hexstring + '80'   # padding
    while len(hexstring) % 32 != 0:
        hexstring = hexstring + '00'
    all_blocks = []
    for num in range(0, len(hexstring), 2):
        if num % 32 == 0:
            all_blocks.append([[0 for x in range(4)] for x in range(4)])
        block_num = int(num / 32)
        (all_blocks[block_num])[int((num % 8) / 2)][int((num % 32) / 8)] = hexstring[num: num + 2]
    return all_blocks


def sub_bytes(state: list):  # subs entire state
    new_state = [ele[:] for ele in state]
    for col in range(4):
        for row in range(4):
            if state[row][col] != 0:
                temp = hex(int(state[row][col], 16))
                length = len(temp)
                if length < 4:
                    row_sbox = 0
                else:
                    row_sbox = int(temp[length - 2], 16)
                col_sbox = int(temp[length - 1], 16)
                new_state[row][col] = hex(sbox[row_sbox * 16 + col_sbox])
            else:
                new_state[row][col] = hex(99)
    return new_state


def shift(array: list, num: int):  # shifts an array by given iteration
    new_array = array[:]
    for x in range(num):
        first_temp = new_array[0]
        for pos in range(3):
            new_array[pos] = new_array[pos + 1]
        new_array[3] = first_temp
    return new_array


def shift_rows(state: list):  # shifts rows of a state
    new_state = [[] for num in range(4)]
    new_state[0] = state[0]
    for col in range(1, 4):
        new_state[col] = shift(state[col], col)
    return new_state


def galois_mult(num1: str, num2: str):  # galois multiplication
    a = int(num1, 16)
    b = int(num2, 16)
    product = 0
    for num in range(8):
        if b & 1 == 1: # if low bit of b is set
            product ^= a
        highbit = a & 0x80
        a <<= 1
        if highbit == 0x80: # if high bit of a is set
            a ^= 0x1b
        b >>= 1
    return product % 256


def mix_columns(state: list):  # galois multiplies each column of state with given matrix
    new_state = [[] for num in range(4)]
    for col in range(4):
        for row in range(4):
            product = 0
            for y in range(4):
                product ^= galois_mult(state[y][col], str(mix_multiplier[row * 4 + y]))
            new_state[row].append(hex(product))
    return new_state


def add_roundkey(state: list, key: list):  # XORs a state with a given key
    new_state = [[0 for num in range(4)] for num in range(4)]
    for col in range(4):
        for row in range(4):
            new_state[row][col] = hex(int(str(state[row][col]), 16) ^ int(str(key[row][col]), 16))
    return new_state


def elongate_key(input_password: str):  # doesn't have to be hex string
    salt = binascii.unhexlify('aaef2d3f4d77ac66e9c5a6c3d8f921d1')
    password = input_password.encode("utf8")
    key = pbkdf2_hmac("sha256", password, salt, 50000, 16)
    output = str(binascii.hexlify(key))
    return output[2:34]


def key_block(plainkey: str):  # assumes plainkey is already a 128-bit hex string
    key_array = []
    for col in range(4):
        key_array.append([])
        for num in range(col * 8, (col + 1) * 8, 2):
            key_array[col].append(hex(int(plainkey[num: num + 2], 16)))
    return key_array


def sub_word(key_word: list):  # only one word sub
    new_keyword = []
    for num in range(len(key_word)):
        length = len(key_word[num])
        if length < 4:
            row_sbox = 0
        else:
            row_sbox = int(key_word[num][length - 2], 16)
        col_sbox = int(key_word[num][length - 1], 16)
        new_keyword.append(hex(sbox[row_sbox * 16 + col_sbox]))
    return new_keyword


def rot_word(key_word: list):
    new_keyword = [[] for num in range(4)]
    first_temp = key_word[0]
    for pos in range(3):
        new_keyword[pos] = key_word[pos + 1]
    new_keyword[3] = first_temp
    return new_keyword


def key_expansion(plainkey: str):  # modify to account for user input error?
    schedule = [key_block(plainkey)]
    for key_num in range(1, 11):
        schedule.append([])
        word1 = sub_word(rot_word(schedule[key_num - 1][3]))
        rcon1 = [rcon[key_num], 0, 0, 0]
        for num in range(4):
            byte = hex(int((schedule[key_num - 1][0][num]), 16) ^ int(word1[num], 16) ^ rcon1[num])
            word1[num] = byte
        schedule[key_num].append(word1)
        for col in range(1, 4):
            word = []
            for num in range(4):
                byte = hex(int(schedule[key_num - 1][col][num], 16) ^ int(schedule[key_num][col - 1][num], 16))
                word.append(byte)
            schedule[key_num].append(word)
    return schedule


def transpose(key_array: list):   # because i'm an idiot
    temp = [ele[:] for ele in key_array]
    for row in range(4):
        for col in range(4):
            temp[row][col] = key_array[col][row]
    return temp


def aes_encrypt(plaintext: str, key: str):  # input plaintext and key must already be hex string. key must be 128 bits
    state = make_blocks(plaintext)
    new_state = [ele[:] for ele in state]
    key_schedule = key_expansion(key)
    for num in range(len(key_schedule)):
        key_schedule[num] = transpose(key_schedule[num])
    for block in range(len(new_state)):
        new_state[block] = add_roundkey(state[block], key_schedule[0])    # preliminary round
        for round in range(1, 10):
            new_state[block] = add_roundkey(mix_columns(shift_rows(sub_bytes(new_state[block]))), key_schedule[round])
        new_state[block] = add_roundkey(shift_rows(sub_bytes(new_state[block])), key_schedule[10])  # last round
    return new_state


def make_key(password: str):
    hex_rep = make_hexstring(password)
    if len(hex_rep) < 32:
        hex_rep = elongate_key(hex_rep)
    elif len(hex_rep) > 32:
        hex_rep = hex_rep[:32]
    return hex_rep


if __name__ == '__main__':
    aes_encrypt("3243f6a8885a308d313198a2e0370734", "2b7e151628aed2a6abf7158809cf4f3c")
    print(make_key('wertyuioplkjhgfdsxcvbnm,kjuytrewazsxcvbnjkjuhytgfrdxcvbnm,'))

