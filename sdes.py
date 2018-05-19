#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import division, print_function, absolute_import
from functools import reduce
from multiprocessing import Pool, Manager
from collections import OrderedDict
from functools import partial
import sys, os, logging, ctypes, gc, string, random

__author__ = "Ricardo Oliveira"
__copyright__ = "Ricardo Oliveira"
__license__ = "mit"

_logger = logging.getLogger(__name__)

# Load shared library
try:
    # ctypes exports the cdll, and on Windows windll and oledll objects, for loading dynamic link libraries.
    # You load libraries by accessing them as attributes of these objects.
    # cdll loads libraries which export functions using the standard cdecl calling convention, while windll libraries call functions using the stdcall calling convention.
    # oledll also uses the stdcall calling convention, and assumes the functions return a Windows HRESULT error code.
    # The error code is used to automatically raise a WindowsError exception when the function call fails.
    _sdes = ctypes.CDLL('_sdes.so')
except Exception as error:
    _logger.error(error)
    exit(1)

#############################################################
# UTILS
#############################################################
class text_colors:
    MAGENTA = '\033[95m'
    BLUE= '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    UNDERLINE = '\033[4m'

def string_generator(size = 16, chars = string.ascii_uppercase + string.digits):
    return ''.join(random.choice(chars) for _ in range(size))

#############################################################
# SDES WRAPPED FUNCTIONS
#############################################################
def debug_num(desc, num, bits):
   _sdes.dbg_num(ctypes.c_char_p(desc.encode('utf-8')), ctypes.c_int(num), ctypes.c_int(bits))

def generate_sub_keys(key, s1 = '', s2 = ''):
    key = ctypes.c_int(key)
    sk1 = ctypes.c_wchar_p(s1)
    sk2 = ctypes.c_wchar_p(s2)
    _sdes.generate_sub_keys(key, sk1, sk2)
    a = ctypes.cast(sk1,ctypes.POINTER(ctypes.c_int)).contents
    b = ctypes.cast(sk2,ctypes.POINTER(ctypes.c_int)).contents
    return a, b

def fk(char, sk1, sk2):
    return _sdes.fk(ctypes.c_char(char), ctypes.c_char(sk1), ctypes.c_char(sk2))

def ip(char):
    return _sdes.ip(ctypes.c_char(char))

def ip_inverse(char):
    return _sdes.ip_inverse(ctypes.c_char(char))

#############################################################
# CBC MODE
#############################################################
def sdes_encrypt_cbc(key, plaintext):
    # Because the first character of the message is used as the iv
    # the message must have at least two blocks
    if len(plaintext)<2:
        raise Exception('Plaintext must have at least two blocks, because the first character is used as the IV.')
    # generate sub keys
    sk1, sk2 = generate_sub_keys(key = key)
    ciphertext = []
    iv = plaintext[:1]
    ciphertext.append(ord(iv))
    for ch in plaintext[1:]:
        ch = ord(ch) ^ ord(iv)
        # initial permutation
        ch = ip(char = ch)
        # apply function Fk
        ch = fk(char = ch, sk1 = sk1.value, sk2 = sk2.value)
        # inverse initial permutation
        ch = ip_inverse(char = ch)
        iv = chr(ch)
        ciphertext.append(ch)
    return ciphertext

def sdes_decrypt_cbc(key, ciphertext):
    # Because the first character of the message is used as the iv
    # the message must have at least two blocks
    if len(ciphertext)<2:
        raise Exception('Plaintext must have at least two blocks')
    # generate sub keys
    sk1, sk2 = generate_sub_keys(key = key)
    plaintext = []
    iv = ciphertext[:1][0]
    plaintext.append(iv)
    for ch in ciphertext[1:]:
        tmp = ch
        # initial permutation
        ch = ip(char = ch)
        # apply function Fk
        ch = fk(char = ch, sk1 = sk2.value, sk2 = sk1.value)
        # inverse initial permutation
        ch = ip_inverse(char = ch)
        # exclusive or ch with iv
        ch = ch ^ iv
        # iv becomes the previous ciphertext
        iv = tmp
        plaintext.append(ch)
    return plaintext


#############################################################
# SDES
#############################################################
# ENCRYPT
def sdes_encrypt(key, plaintext = ''):
    # generate sub keys
    sk1, sk2 = generate_sub_keys(key = key)
    ciphertext = []
    for ch in plaintext:
        # initial permutation
        ch = ip(char = ch)
        # apply function Fk
        ch = fk(char = ch, sk1 = sk1.value, sk2 = sk2.value)
        # inverse initial permutation
        ch = ip_inverse(char = ch)
        ciphertext.append(ch)
    return ciphertext

def sdes_encrypt_multi(key, results, plaintext = ''):
    # generate sub keys
    sk1, sk2 = generate_sub_keys(key = key)
    ciphertext = []
    for ch in plaintext:
        # initial permutation
        ch = ip(char = ch)
        # apply function Fk
        ch = fk(char = ch, sk1 = sk1.value, sk2 = sk2.value)
        # inverse initial permutation
        ch = ip_inverse(char = ch)
        ciphertext.append(ch)
    results[''.join(hex(i).replace('0x','') for i in ciphertext)] = key

# DECRYPT
def sdes_decrypt(ciphertext = [], key = 18):
    # generate sub keys
    sk1, sk2 = generate_sub_keys(key = key)
    plaintext = []
    for ch in ciphertext:
        # initial permutation
        ch = ip(char = ch)
        # apply function Fk
        ch = fk(char = ch, sk1 = sk2.value, sk2 = sk1.value)
        # inverse initial permutation
        ch = ip_inverse(char = ch)
        plaintext.append(ch)
    return plaintext

def sdes_decrypt_multi(key, ciphertext, results):
    # generate sub keys
    sk1, sk2 = generate_sub_keys(key = key)
    plaintext = []
    for ch in ciphertext:
        # initial permutation
        ch = ip(char = ch)
        # apply function Fk
        ch = fk(char = ch, sk1 = sk2.value, sk2 = sk1.value)
        # inverse initial permutation
        ch = ip_inverse(char = ch)
        plaintext.append(ch)
    results[''.join(hex(i).replace('0x','') for i in plaintext)] = key

#############################################################
# S2DES
#############################################################
def s2des_encrypt(plaintext, key_1, key_2):
    temp = sdes_encrypt(plaintext = plaintext, key = key_1)
    ciphertext = sdes_encrypt(plaintext = temp, key = key_2)
    if temp == ciphertext:
        _logger.error('You can not use these pair of keys: {0}{1}'.format(text_colors.RED,key_1, key_2, text_colors.ENDC))
        exit(1)
    del temp
    gc.collect()
    return ciphertext

def s2des_decrypt(ciphertext, key_1, key_2):
    temp = sdes_decrypt(ciphertext = ciphertext, key = key_1)
    plaintext = sdes_decrypt(ciphertext = temp, key = key_2)
    return plaintext

#############################################################
# BRUTE FORCE ATTACK
#############################################################
def brute_force_multi(key_2, results, cipher, known_word = 'beira'):
    for j in range (2**10):
        plaintext = s2des_decrypt(ciphertext = cipher,
                                    key_1 = j,
                                    key_2 = key_2)

        if known_word in ''.join(chr(i) for i in plaintext):
            results.append((key_2, j, ''.join(chr(i) for i in plaintext)))

#############################################################
# MEET IN THE MIDDLE ATTACK
#############################################################
def meet_in_middle_encrypt(plaintext):
    # Create a multiprocessing Pool
    with Pool(os.cpu_count()) as pool:
        shared_dict_encrypt = Manager().dict()
        pool.map(partial(sdes_encrypt_multi,
                            plaintext = plaintext.encode(),
                            results = shared_dict_encrypt
                        ),
                    iterable = range(2**10),
                    # chops the iterable into a number of chunks which
                    # it submits to the process pool as separate tasks.
                    # The (approximate) size of these chunks can be
                    # specified by setting chunksize to a positive integer.
                    chunksize = os.cpu_count()
                )
    # sort the dictionary
    return OrderedDict(sorted(shared_dict_encrypt.items(), key=lambda t: t[0]))
    # unsort result 
    # return shared_dict_encrypt

def meet_in_middle_decrypt(ciphertext):
    # Create a multiprocessing Pool
    with Pool(os.cpu_count()) as pool:
        shared_dict_decrypt = Manager().dict()
        pool.map(partial(sdes_decrypt_multi,
                        ciphertext = ciphertext,
                        results = shared_dict_decrypt
                        ),
                iterable = range(2**10),
                # chops the iterable into a number of chunks which
                # it submits to the process pool as separate tasks.
                # The (approximate) size of these chunks can be
                # specified by setting chunksize to a positive integer.
                chunksize = os.cpu_count()
                )
    return shared_dict_decrypt
