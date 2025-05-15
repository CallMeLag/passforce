import hashlib
import sys
import argparse
from bruteforce import crack
from time import time


def hash_password(password: str) -> bytes:
    return hashlib.sha256(password.encode()).digest()

def main():
    parser = argparse.ArgumentParser(description="Brute-force SHA-256 password cracker.")
    parser.add_argument("-p", "--password", help="Password to crack (optional). If not provided, input will be prompted.")
    args = parser.parse_args()

    if args.password:
        target_password = args.password
    else:
        target_password = input("Enter the password to crack: ")

    target_hash = hash_password(target_password)

    print(f"Target password to crack: {target_password}")
    print(f"Target hash (SHA-256): {target_hash.hex()}")

    # Start crackers
    start_time = time()
    crack(target_hash)  # Call the Cython-based brute force cracker

    total_time = time() - start_time
    print(f"Cracking completed in {total_time:.2f} seconds.")

if __name__ == "__main__":
    main()
