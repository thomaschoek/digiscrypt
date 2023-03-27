# Generate a custom hash function based on a user's passphrase
# Initially I am limiting the shift operations to adding, subtracting, rotating and xors of bytes
# Maybe later implement other shifts like divide, multiply, exponentiate

import math
import sys
from random import *
from enum import Enum
import re
import numpy as np

np.seterr(all='raise')


def add(a: int, b: int, m=256):
    return (a + b) % m


def subtract(a: int, b: int, m=256):
    return (a - b) % m


def left_rotate(a: int, d: int, sizeof_a=8):
    sizeof_a = sys.getsizeof(a)
    d %= sizeof_a
    b = a << d
    c = a >> (sizeof_a - d)
    b |= c
    b &= int('1' * sizeof_a, 2)
    return b & int('1' * sizeof_a, 2)


def right_rotate(a: int, d: int, sizeof_a=8):
    sizeof_a = sys.getsizeof(a)
    d %= sizeof_a
    b = a >> d
    c = a << (sizeof_a - d)
    c &= int('1' * sizeof_a, 2)
    return b | c


def exclusive_or(a, b):
    return a ^ b


shift = [(add, subtract),
         (subtract, add),
         (left_rotate, right_rotate),
         (right_rotate, left_rotate),
         (exclusive_or, exclusive_or)]


class ByteCipher:

    @staticmethod
    def get_seed(_input: str, d=1):
        s_bytes = bytes(_input, 'utf-8')
        _seed = np.frombuffer(s_bytes, dtype=np.uint8)
        _reference = np.roll(_seed, d)
        return _seed, _reference

    @staticmethod
    def get_block_length(_input: str | int):
        # use percentage of total input size or fixed length in bits?
        if _input is int:
            return _input
        else:
            digits = re.findall(r'\d', _input)
            if digits:
                block_len = 0
                k = len(digits) - 1
                for d in digits:
                    block_len += int(d) * 10 ** k
                    k -= 1
                return block_len
            else:
                return 10

    @staticmethod
    def shift_byte(a: int, k: int, b: int = 2, phase: int = 0, invert: bool = False):
        return shift[(k + phase) % 5][invert](a, b)

    def shift_byte_array(self, data: np.array, passphrase: str, invert: bool = False):
        _seed = self.get_seed(passphrase)
        block_len = self.get_block_length(passphrase)
        key = _seed[0]
        reference = _seed[1]
        key_length = len(key)
        encrypted_data = np.array(data, int)
        for i, a in enumerate(data):
            i_mod_l = i % key_length
            phase = i // block_len
            encrypted_data[i] = self.shift_byte(int(a), int(key[i_mod_l]), int(reference[i_mod_l]), phase, invert)
        return encrypted_data

    def shift_string(self, s: str, key, invert: bool = False):
        s_bytes = bytes(s, 'utf-8')
        s_bytes_array = np.frombuffer(s_bytes, np.uint8)
        print(f"Original unencrypted s_bytes_array: \n", s_bytes_array)
        shifted_bytes = self.shift_byte_array(s_bytes_array, key, invert)
        return shifted_bytes


def test_cipher():
    s = "Type a password, sentence or short story consisting of letters followed by a number between 10 and 1000. The\
     longer your input, the more secure, but the less fast encryption will be12345"
    print("s: ", s)
    pw = "password1234"
    print("pw: ", pw)
    cipher = ByteCipher()
    shifted_bytes = cipher.shift_string(s, pw)
    print(f"Encrypted data: \n", shifted_bytes)
    decrypted_data = cipher.shift_byte_array(shifted_bytes, pw, True)
    print(f"Decrypted data: \n", decrypted_data)
    print(f"Decrypted string: \n", decrypted_data.tobytes().decode())


if __name__ == '__main__':
    test_cipher()
    _data = input("Enter the data you wish to encrypt\n")
    _key = input("Type a password, sentence or short story consisting of letters followed by\
     a number between 10 and 1000. The longer your input, the more secure, but the less fast encryption will be\n")
    _cipher = ByteCipher()
    _encrypted_data = _cipher.shift_string(_data, _key)
    print(_encrypted_data)
    _decrypted_data = _cipher.shift_byte_array(_encrypted_data, _key, True)
