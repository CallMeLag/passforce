from libc.stdlib cimport malloc, free
from libc.string cimport strlen
import hashlib
from time import time


cpdef crack(bytes target_hash):
    # Charset starts with lowercase letters and expands later
    cdef char* charset_lower = b"abcdefghijklmnopqrstuvwxyz"
    cdef char* charset_upper = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    cdef char* charset_digits = b"0123456789"
    cdef char* charset_symbols = b"!@#$%^&*()_-+=<>?/.,"

    cdef int base_lower = strlen(charset_lower)
    cdef int base_upper = strlen(charset_upper)
    cdef int base_digits = strlen(charset_digits)
    cdef int base_symbols = strlen(charset_symbols)

    cdef int length = 1  # Start with a 1-character password length
    cdef long long total, count
    cdef char* attempt
    cdef int i, idx
    cdef bytes hashed, result
    cdef double start = time()

    while True:
        total = 1
        for _ in range(length):
            total *= base_lower  # Start with lowercase only, will expand later

        attempt = <char*>malloc(length + 1)
        if not attempt:
            print("Memory allocation failed")
            return

        # First try lowercase characters
        for count in range(total):
            idx = count
            for i in range(length - 1, -1, -1):
                attempt[i] = charset_lower[idx % base_lower]
                idx //= base_lower
            attempt[length] = b'\0'

            hashed = hashlib.sha256(attempt[:length]).digest()
            if hashed == target_hash:
                result = bytes(attempt[:length])
                print("Found:", result.decode())
                print("Hash: ", hashed.hex())
                print("Time: {:.2f} seconds".format(time() - start))
                free(attempt)
                return

        # If not found, try adding uppercase characters
        for count in range(total):
            idx = count
            for i in range(length - 1, -1, -1):
                attempt[i] = charset_upper[idx % base_upper]
                idx //= base_upper
            attempt[length] = b'\0'

            hashed = hashlib.sha256(attempt[:length]).digest()
            if hashed == target_hash:
                result = bytes(attempt[:length])
                print("Found:", result.decode())
                print("Hash: ", hashed.hex())
                print("Time: {:.2f} seconds".format(time() - start))
                free(attempt)
                return

        # Now try digits
        for count in range(total):
            idx = count
            for i in range(length - 1, -1, -1):
                attempt[i] = charset_digits[idx % base_digits]
                idx //= base_digits
            attempt[length] = b'\0'

            hashed = hashlib.sha256(attempt[:length]).digest()
            if hashed == target_hash:
                result = bytes(attempt[:length])
                print("Found:", result.decode())
                print("Hash: ", hashed.hex())
                print("Time: {:.2f} seconds".format(time() - start))
                free(attempt)
                return

        # Finally, try symbols
        for count in range(total):
            idx = count
            for i in range(length - 1, -1, -1):
                attempt[i] = charset_symbols[idx % base_symbols]
                idx //= base_symbols
            attempt[length] = b'\0'

            hashed = hashlib.sha256(attempt[:length]).digest()
            if hashed == target_hash:
                result = bytes(attempt[:length])
                print("Found:", result.decode())
                print("Hash: ", hashed.hex())
                print("Time: {:.2f} seconds".format(time() - start))
                free(attempt)
                return

        length += 1  # If not found, increase the password length and retry
        free(attempt)
