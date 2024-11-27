"""
@author: Eric PEREIRA DE AMORIM

How to use:
    
    >> import hash
    >> plaintext = "I will be hashed soon enough!"
    >> hashedtext = hash.md5(plaintext)
    >> print(hashedtext)
    
    >>>> 7b6bc1e4eafc6fcc44f747ca379baa61
    (from https://www.md5hashgenerator.com/)
 
 Pseudocode from https://en.wikipedia.org/wiki/MD5   
 
"""

import math

def MD_to_hex(digest_parts):
    """
    Transforms MD5 digest to readable form
    """
    return ''.join(part.to_bytes(4, byteorder='little').hex() for part in digest_parts)

def leftRotate(num, rot):
    num &= 0xFFFFFFFF
    return (num << rot | num >> (32 - rot)) & 0xFFFFFFFF

def md5(plaintext = ""):
    
    shift = [7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
             5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
             4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
             6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21]
    
    
    K = [math.floor(4294967296 * abs(math.sin(i + 1))) & 0xFFFFFFFF for i in range(64)]
    # 2**32 = 4294967296
   
    
    plaintext_bytes = bytearray(plaintext, 'ascii')
    orig_len_in_bits = (len(plaintext_bytes) * 8) & 0xFFFFFFFFFFFFFFFF
    
    plaintext_bytes.append(0x80)
    
    
    while len(plaintext_bytes) % 64 != 56:
        plaintext_bytes.append(0)
        
    
    plaintext_bytes += orig_len_in_bits.to_bytes(8, byteorder='little')
   
    
    a0, b0, c0, d0 = 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476
    
    for i in range(0, len(plaintext_bytes), 64):
        chunk = plaintext_bytes[i:i+64]
        
        M = [int.from_bytes(chunk[j:j + 4], byteorder='little') for j in range(0, 64, 4)]

        A, B, C, D = a0, b0, c0, d0

        for i in range(64):
            if 0 <= i <= 15:
                F = (B & C) | (~B & D)
                g = i
            elif 16 <= i <= 31:
                F = (D & B) | (~D & C)
                g = (5*i + 1) % 16
            elif 32 <= i <= 47:
                F = B ^ C ^ D
                g = (3*i + 5) % 16
            elif 48 <= i <= 63:
                F = C ^ (B | ~D)
                g = (7*i) % 16
            
            F = (F + A + K[i] + M[g]) & 0xFFFFFFFF
            A, D, C, B = D, C, B, (B + leftRotate(F, shift[i])) & 0xFFFFFFFF
        
        a0 = (a0 + A) & 0xFFFFFFFF
        b0 = (b0 + B) & 0xFFFFFFFF
        c0 = (c0 + C) & 0xFFFFFFFF
        d0 = (d0 + D) & 0xFFFFFFFF
    
    
    return MD_to_hex([a0, b0, c0, d0])


