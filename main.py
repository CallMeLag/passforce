import hashlib
from bruteforce import crack
from time import time

def hash_password(password: str) -> bytes:
    """
    Hashes the input password using SHA-256.
    """
    return hashlib.sha256(password.encode()).digest()

def main():
    # Input for the password to crack
    target_password = input("Enter the password to crack: ")
    
    # Hash the input password
    target_hash = hash_password(target_password)
    
    print(f"Target password to crack: {target_password}")
    print(f"Target hash (SHA-256): {target_hash.hex()}")
    
    # Start cracking
    start_time = time()
    crack(target_hash)  # Call the Cython-based brute force cracker
    
    total_time = time() - start_time
    print(f"Cracking completed in {total_time:.2f} seconds.")

if __name__ == "__main__":
    main()
