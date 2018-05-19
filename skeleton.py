#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import division, print_function, absolute_import

from multiprocessing import Pool, Manager
from collections import OrderedDict
import argparse, timeit, math, codecs
import sys, os
import logging
import numpy as np
from sdes import *
from functools import partial

__author__ = "Ricardo Oliveira"
__copyright__ = "Ricardo Oliveira"
__license__ = "mit"

_logger = logging.getLogger(__name__)

def parse_args(args):
    """
    Parse command line parameters

    Args:
      args ([str]): command line parameters as list of strings

    Returns:
      :obj:`argparse.Namespace`: command line parameters namespace
    """
    parser = argparse.ArgumentParser(
        description="Homework 2 - Encryption Modes and Meet in the Middle")
    parser.add_argument(
        '-p',
        '--plaintext',
        dest="plaintext",
        help="Plaintext to be encrypted",
        default = 'xxxbeira',
        type=str,
        metavar="STRING")
    parser.add_argument(
        '-k',
        '--key',
        dest = 'key',
        help = 'Key used for encryption/decryption',
        action = 'append',
        type = int,
        nargs = 1,
        metavar = 'INT'
    )
    cipher_group = parser.add_mutually_exclusive_group(required = False)
    cipher_group.add_argument(
        '-sdes',
        '--sdes',
        dest = 'sdes',
        help = 'Simplified Data Encryption Standard',
        action = 'store_true',
        default = False
    )
    cipher_group.add_argument(
        '-s2des',
        '--s2des',
        dest = 's2des',
        help = 'Simplified Double Data Encryption Standard',
        action = 'store_true',
        default = False
    )
    p_group = parser.add_mutually_exclusive_group(required = False)
    p_group.add_argument(
        '-b',
        '--bruteforce',
        dest = 'brute_force',
        help = 'Execute a brute force attack on the entire cypher text',
        action = 'store_true',
        default = False
    )
    p_group.add_argument(
        '-m',
        '--mim',
        dest = 'meet_middle',
        help = 'Execute a meet in the middle attack on the first character (block) of the cypher text',
        action = 'store_true',
        default = False
    )
    p_group.add_argument(
        '-c',
        '--cbc',
        dest = 'cbc',
        help = 'S-DES in mode CBC',
        action = 'store_true',
        default = False
    )
    parser.add_argument(
        '-v',
        '--verbose',
        dest="loglevel",
        help="set loglevel to INFO",
        action='store_const',
        const=logging.INFO)
    parser.add_argument(
        '-vv',
        '--very-verbose',
        dest="loglevel",
        help="set loglevel to DEBUG",
        action='store_const',
        const=logging.DEBUG)
    return parser.parse_args(args)


def setup_logging(loglevel):
    """
    Setup basic logging
    :param loglevel (int): minimum loglevel for emitting messages
    """
    logformat = '[%(asctime)s] %(levelname)s:%(name)s:%(message)s'
    logging.basicConfig(level=loglevel, stream=sys.stdout,
                        format=logformat, datefmt='%Y-%m-%d %H:%M:%S')

    # create file handler which logs even Error messages
    fh = logging.FileHandler('app.log')
    fh.setLevel(logging.ERROR)

def main(args):
    """
    Main entry point allowing external calls
    Args:
      args ([str]): command line parameter list
    """
    args = parse_args(args)
    setup_logging(args.loglevel)
    _logger.info("Starting crazy calculations...")
    start_time = timeit.default_timer()

    plaintext, ciphertext = [], []

    # SIMPLES DES
    if args.sdes and args.key is not None:
        # encrypt
        ciphertext = sdes_encrypt(plaintext = args.plaintext.encode(),
                                  key = args.key[0][0])
        # decrypt
        plaintext = sdes_decrypt(ciphertext = ciphertext,
                                 key = args.key[0][0])

    # SIMPLE DOUBLE DES
    if args.s2des and args.key is not None:
        try:
            if len(args.key) < 2:
                raise Exception('{0}{1}{2}'.format(text_colors.RED,'What are you trying to do? I need another key.', text_colors.ENDC))
            # encrypt
            ciphertext = s2des_encrypt(plaintext = args.plaintext.encode(),
                                       key_1 = args.key[0][0],
                                       key_2 = args.key[1][0])
            # decrypt
            plaintext = s2des_decrypt(ciphertext = ciphertext,
                                      key_1 = args.key[1][0],
                                      key_2 = args.key[0][0])
        except Exception as error:
            _logger.error(error)
            exit(2)

        _logger.info('plaintext:  '+''.join(chr(i) for i in plaintext))
        _logger.info('ciphertext: '+''.join(chr(i) for i in ciphertext))

    # BRUTE FORCE ATTACK
    if args.brute_force:
        # Create a multiprocessing Pool
        with Pool(os.cpu_count()) as pool:
            shared_list = Manager().list()
            pool.map(partial(brute_force_multi,
                             cipher = ciphertext,
                             known_word = args.plaintext,
                             results = shared_list),
                     iterable = range(2**10),
                     # chops the iterable into a number of chunks which
                     # it submits to the process pool as separate tasks.
                     # The (approximate) size of these chunks can be
                     # specified by setting chunksize to a positive integer.
                     chunksize = os.cpu_count()
                    )
        print('{0}{1}{2}'.format(text_colors.YELLOW, shared_list, text_colors.ENDC))

    if args.meet_middle:
        # encrypt
        ciphertext_1 = s2des_encrypt(plaintext = args.plaintext.encode(),
                                     key_1 = args.key[0][0],
                                     key_2 = args.key[1][0])
        # encrypt plaintext with all 2**10 keys
        shared_dict_encrypt = meet_in_middle_encrypt(args.plaintext)
        # decrypt the ciphertext with all 2**10 keys
        shared_dict_decrypt = meet_in_middle_decrypt(ciphertext_1)

        keys_a, keys_b = set(shared_dict_encrypt.keys()), set(shared_dict_decrypt.keys())
        intersection = keys_a & keys_b
        _logger.info('intersection: {}'.format(intersection))

        # if there is more than one possible key
        # then use another pair of (P,C)
        if len(intersection)>1:
            random_string = string_generator()
            ciphertext_2 = s2des_encrypt(plaintext = random_string.encode(),
                                        key_1 = args.key[0][0],
                                        key_2 = args.key[1][0])
            for element in intersection.copy():
                ciphertext_x = s2des_encrypt(plaintext = random_string.encode(),
                                            key_1 = shared_dict_encrypt[element],
                                            key_2 = shared_dict_decrypt[element])
                _logger.info('more than one key, trying another pair of (P,C): {}'.format(random_string))
                if ciphertext_x == ciphertext_2:
                    print(codecs.decode(r'{0}K\u2081: {1:<4} K\u2082: {2:<4}{3}'\
                                        .format(text_colors.YELLOW,
                                                shared_dict_encrypt[element],
                                                shared_dict_decrypt[element],
                                                text_colors.ENDC),
                                        'unicode_escape'))
                else:
                    del shared_dict_decrypt[element], shared_dict_encrypt[element]
                    intersection.pop()

        else:
            element = intersection.pop()
            print(codecs.decode(r'{0}K\u2081: {1:<4} K\u2082: {2:<4}{3}'\
                                .format(text_colors.YELLOW,
                                        shared_dict_encrypt[element],
                                        shared_dict_decrypt[element],
                                        text_colors.ENDC),
                                'unicode_escape'))

    # CBC MODE
    if args.cbc:
        try:
            ciphertext = sdes_encrypt_cbc(key = args.key[0][0], plaintext = args.plaintext)
            plaintext = sdes_decrypt_cbc(key = args.key[0][0], ciphertext = ciphertext)
            print('plaintext:  '+''.join(chr(i) for i in plaintext))
            print('ciphertext: '+''.join(hex(i).replace('0x','') for i in ciphertext))
        except Exception as error:
            print('{0}{1}{2}'.format(text_colors.RED,error, text_colors.ENDC))
            exit (1)

    # assure D(k,E(k,m)) = m
    assert args.plaintext == ''.join(chr(i) for i in plaintext)

    # duration in milliseconds
    _logger.info('Time taken: ' + str(math.ceil(1000*(timeit.default_timer()-start_time))) + ' ms')


def run():
    """
    Entry point for console_scripts
    """
    main(sys.argv[1:])

if __name__ == "__main__":
    run()
