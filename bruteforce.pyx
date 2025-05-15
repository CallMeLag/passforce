from libc.stdlib cimport malloc, free
from libc.string cimport strlen
import hashlib
from time import time

cpdef crack(bytes target_hash):
    # Combined charset: lowercase + uppercase + digits + symbols
    cdef char* full_charset = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_-+=<>?/.,"
    cdef int base = strlen(full_charset)
    cdef int length = 1
    cdef long long total, count
    cdef char* attempt
    cdef int i, idx
    cdef bytes hashed, result
    cdef double start = time()

    while True:
        total = 1
        for _ in range(length):
            total *= base

        attempt = <char*>malloc(length + 1)
        if not attempt:
            print("Memory allocation failed")
            return

        for count in range(total):
            idx = count
            for i in range(length - 1, -1, -1):
                attempt[i] = full_charset[idx % base]
                idx //= base
            attempt[length] = b'\0'

            hashed = hashlib.sha256(attempt[:length]).digest()
            if hashed == target_hash:
                result = bytes(attempt[:length])
                print("Found:", result.decode())
                print("Hash: ", hashed.hex())
                print("Time: {:.2f} seconds".format(time() - start))
                free(attempt)
                return

        free(attempt)
        length += 1
