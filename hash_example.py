# -*- coding: utf-8 -*-
"""
@author: Eric PEREIRA DE AMORIM

Let's print some examples and verify them with the MD5 function from hashlib.
"""

import hash, hashlib

plaintexts = ["hello", "I will be hashed soon enough!", "testing", "Riga Technical University", "Eric PEREIRA DE AMORIM", ""]

for plaintext in plaintexts:
    m = hashlib.md5()
    m.update(bytearray(plaintext, 'ascii'))
    hashedtext = hash.md5(plaintext)
    print("Plaintext message     : '{}'".format(plaintext))
    print("    hashlib version   : '{}'".format(m.hexdigest()))
    print("   hash (own) version : '{}'".format(hashedtext))
    print("        Match         ? {}".format(m.hexdigest() == hashedtext))
    print()