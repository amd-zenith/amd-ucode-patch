#!/usr/bin/env python
# SPDX-License-Identifier: GPL-2.0-or-later

"""
General number-theory helpers.
"""


def prime_table(limit: int = 100000) -> list[int]:
    """
    Return all primes up to ``limit`` via a sieve of Eratosthenes.
    """
    sieve = bytearray(b"\x01") * (limit + 1)
    sieve[0:2] = b"\x00\x00"
    for i in range(2, int(limit ** 0.5) + 1):
        if sieve[i]:
            start = i * i
            step = i
            sieve[start:limit + 1:step] = b"\x00" * (((limit - start) // step) + 1)
    return [i for i in range(2, limit + 1) if sieve[i]]
