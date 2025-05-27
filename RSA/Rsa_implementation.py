"""RSA IMPLEMENTATION"""
import random
import math
import time
import statistics

def gcd(a, b):
    """Calculates the greatest common divisor (GCD) of two integers."""
    if b == 0:
        return a
    return gcd(b, a % b)

def extended_gcd(a, b):
    """Extended Euclidean Algorithm to find the modular multiplicative inverse."""
    if a == 0:
        return b, 0, 1
    d, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return d, x, y

def is_prime(n, k=5):
    """Checks if a number is prime using the Miller-Rabin primality test."""
    if n <= 1:
        return False
    if n <= 3:
        return True
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2
    for _ in range(k):
        a = random.randint(2, n - 2)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def generate_prime(bits):
    """Generates a random prime number with the specified number of bits."""
    while True:
        p = random.getrandbits(bits)
        p |= 1  # Ensure odd
        if is_prime(p):
            return p

def generate_keypair(bits):
    """Generates an RSA keypair (public key, private key) and measures time."""
    start_time = time.time()
    p = generate_prime(bits // 2)
    q = generate_prime(bits // 2)
    while p == q:
        q = generate_prime(bits // 2)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = random.randint(2, phi - 1)
    while gcd(e, phi) != 1:
        e = random.randint(2, phi - 1)
    d, x, y = extended_gcd(e, phi)
    d = x % phi
    end_time = time.time()
    key_gen_time = end_time - start_time
    return (n, e), (n, d), key_gen_time

def encrypt(pk, plaintext):
    """Encrypts a message using the public key and measures time."""
    start_time = time.time()
    n, e = pk
    ciphertext = [pow(ord(char), e, n) for char in plaintext]
    end_time = time.time()
    encryption_time = end_time - start_time
    return ciphertext, encryption_time

def decrypt(pk, ciphertext):
    """Decrypts a message using the private key and measures time."""
    start_time = time.time()
    n, d = pk
    plaintext = ''.join([chr(pow(char, d, n)) for char in ciphertext])
    end_time = time.time()
    decryption_time = end_time - start_time
    return plaintext, decryption_time

if __name__ == '__main__':
    key_size = int(input("Enter key size (bits): "))
    message = input("Enter message to encrypt: ")
    num_repeats = int(input("Enter the number of times to repeat the experiment: "))

    key_generation_times = []
    encryption_times = []
    decryption_times = []

    for i in range(num_repeats):
        print(f"Iteration {i+1}:")

        # Key Generation
        public_key, private_key, key_gen_time = generate_keypair(key_size)
        key_generation_times.append(key_gen_time)
        print(f"  Key generation time: {key_gen_time:.6f} seconds")

        # Encryption
        encrypted_msg, encryption_time = encrypt(public_key, message)
        encryption_times.append(encryption_time)
        print(f"  Encryption time: {encryption_time:.6f} seconds")

        # Decryption
        decrypted_msg, decryption_time = decrypt(private_key, encrypted_msg)
        decryption_times.append(decryption_time)
        print(f"  Decryption time: {decryption_time:.6f} seconds")

        assert message == decrypted_msg, "Decryption failed!"


    # Calculate averages
    avg_key_gen_time = statistics.mean(key_generation_times)
    avg_encryption_time = statistics.mean(encryption_times)
    avg_decryption_time = statistics.mean(decryption_times)

    print("\n--- Averages ---")
    print(f"Average key generation time: {avg_key_gen_time:.6f} seconds")
    print(f"Average encryption time: {avg_encryption_time:.6f} seconds")
    print(f"Average decryption time: {avg_decryption_time:.6f} seconds")
"""
Key improvements in this version:

Time Measurement: Uses time.time() to accurately measure the execution time of key generation, encryption, and decryption. The start_time is recorded before, and end_time after, each operation, and the difference is the execution time.

User Input: Prompts the user for the key size, message, and the number of repetitions.

Repetition Loop: Repeats the key generation, encryption, and decryption processes the specified number of times.

List Storage: Stores the execution times for each process (key generation, encryption, decryption) in separate lists (key_generation_times, encryption_times, decryption_times).

Average Calculation: Uses the statistics.mean() function to calculate the average execution time for each process. This is the most robust way to calculate the average.

Clear Output: Prints the execution time for each iteration and then the average execution times at the end. Includes descriptive labels. Prints results to 6 decimal places for higher precision.

Assertion: Keeps the assert statement to verify the correctness of the decryption.

Modularity: Keeps the code well-structured and modular, with separate functions for each task.

How to run the code:

Save: Save the code as a Python file (e.g., rsa_timer.py).

Run: Execute the file from your terminal using python rsa_timer.py.

Input: The script will prompt you for:

Key size (in bits) - e.g., 1024, 2048, or 4096. Larger keys are more secure but slower.

The message you want to encrypt. Keep it relatively short at first for testing.

The number of times to repeat the key generation, encryption, and decryption.

The script will then perform the RSA operations repeatedly, print the execution times for each iteration, and finally print the average execution times."""
