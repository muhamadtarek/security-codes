import random

def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

def is_prime_fermat(num, iterations=5):
    if num <= 1:
        return False
    for _ in range(iterations):
        a = random.randint(2, num - 1)
        if pow(a, num - 1, num) != 1:
            return False
    return True

def generate_prime_candidate(length):
    # Generate random odd integer
    p = random.getrandbits(length)
    p |= (1 << length - 1) | 1
    return p

def generate_prime_number(length=16):
    p = 4
    while not is_prime_fermat(p, iterations=5):
        p = generate_prime_candidate(length)
    return p

def multiplicative_inverse(e, phi):
    d = 0
    x1 = 0
    x2 = 1
    y1 = 1
    temp_phi = phi

    while e > 0:
        temp1 = temp_phi // e
        temp2 = temp_phi - temp1 * e
        temp_phi, e = e, temp2

        x = x2 - temp1 * x1
        y = d - temp1 * y1

        x2, x1, d, y1 = x1, x, y1, y

    return d + phi if temp_phi == 1 else 0

def generate_key_pair(length=16):
    p = generate_prime_number(length)
    q = generate_prime_number(length)
    while q == p:
        q = generate_prime_number(length)

    n = p * q
    phi = (p-1) * (q-1)
    
    e = random.randrange(1, phi)
    while gcd(e, phi) != 1:
        e = random.randrange(1, phi)

    d = multiplicative_inverse(e, phi)
    return ((e, n), (d, n), p, q)

def is_prime(num):
    if num < 2:
        return False
    if num == 2:
        return True
    if num % 2 == 0:
        return False

    for n in range(3, int(num**0.5) + 2, 2):
        if num % n == 0:
            return False

    return True

def encrypt(pk, plaintext):
    key, n = pk
    return [pow(ord(char), key, n) for char in plaintext]

def decrypt_crt(pk, p, q, ciphertext):
    d, n = pk
    dp = d % (p - 1)
    dq = d % (q - 1)
    qinv = multiplicative_inverse(q, p)

    decrypted_text = []

    for c in ciphertext:
        # CRT
        m1 = pow(c, dp, p)
        m2 = pow(c, dq, q)
        h = (qinv * (m1 - m2)) % p
        m = m2 + h * q

        decrypted_text.append(chr(m))

    return ''.join(decrypted_text)

if __name__ == "__main__":
    public, private, p, q = generate_key_pair(16)
    print("Public key:", public)
    print("Private key:", private)

    message = input("Enter a message to encrypt: ")
    encrypted_msg = encrypt(public, message)
    print("Encrypted message:", encrypted_msg)

    decrypted_msg = decrypt_crt(private, p, q, encrypted_msg)
    print("Decrypted message:", decrypted_msg)