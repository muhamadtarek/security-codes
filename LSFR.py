import numpy as np

def string_to_binary(input_string):
    """Convert a string to its binary representation."""
    return ''.join(format(ord(char), '08b') for char in input_string)

def binary_to_string(input_binary):
    """Convert a binary string to its ASCII representation."""
    chars = [chr(int(input_binary[i:i+8], 2)) for i in range(0, len(input_binary), 8)]
    return ''.join(chars)

def polynomial_to_taps(polynomial):
    """Convert a polynomial given as a string to tap positions for the LFSR."""
    terms = polynomial.split(' + ')
    tap_positions = []
    for term in terms:
        if term == '1':
            tap_positions.append(0)
        else:
            power = int(term.split('^')[1])
            tap_positions.append(power)
    return tap_positions

# Define polynomial analysis functions
def binary_poly_div(dividend, divisor):
    """Perform binary polynomial division."""
    dividend, divisor = np.poly1d(dividend), np.poly1d(divisor)
    quotient, remainder = np.polydiv(dividend, divisor)
    quotient, remainder = np.mod(quotient.coef, 2), np.mod(remainder.coef, 2)
    return np.poly1d(quotient), np.poly1d(remainder)

def is_irreducible(poly):
    """Check if a binary polynomial is irreducible."""
    n = len(poly) - 1
    for i in range(1, n):
        divisor = [1] + [0] * (i - 1) + [1]
        _, remainder = binary_poly_div(poly, divisor)
        if np.all(remainder == 0):
            return False
    return True

def is_primitive(poly):
    """Check if a binary polynomial is primitive."""
    if not is_irreducible(poly):
        return False
    
    n = len(poly) - 1
    m = 2**n - 1
    x = np.poly1d([1, 0])

    result = x
    for _ in range(m - 1):
        result = binary_poly_div(np.polymul(result, x), poly)[1]
    
    return np.all(result.coef == [1])

# Modify the LFSR initialization to include polynomial analysis
class LFSR:
    def __init__(self, taps, state):
        self.taps = np.array(taps)
        self.state = np.array(state)
        self.initial_state = np.array(state)
        self.clock_cycles = []

        # Analyze the polynomial
        poly = [0] * (max(taps) + 1)
        for tap in taps:
            poly[tap] = 1
        poly = poly[::-1]  # Reverse to match polynomial format

        print("Polynomial is Irreducible:", is_irreducible(poly))
        print("Polynomial is Primitive:", is_primitive(poly))
        print("Polynomial is reducible:", not is_irreducible(poly))

    def step(self):
        feedback = np.sum(self.state[self.taps]) % 2
        self.clock_cycles.append((self.state.copy(), feedback))
        self.state = np.roll(self.state, -1)
        self.state[-1] = feedback
        return feedback

    def generate_keystream(self, n):
        return [self.step() for _ in range(n)]
    
    def reset(self):
        # Reset the LFSR to the initial state
        self.state = self.initial_state.copy()
        self.clock_cycles = []

    def encrypt(self, plaintext):
        binary_plaintext = string_to_binary(plaintext)
        keystream = self.generate_keystream(len(binary_plaintext))
        encrypted = np.bitwise_xor(np.array(list(map(int, binary_plaintext))), keystream)
        return ''.join(map(str, encrypted))

    def decrypt(self, ciphertext):
        binary_ciphertext = np.array(list(map(int, ciphertext)))
        self.state = self.initial_state.copy()
        self.clock_cycles = []
        keystream = self.generate_keystream(len(binary_ciphertext))
        decrypted = np.bitwise_xor(binary_ciphertext, keystream)
        return binary_to_string(''.join(map(str, decrypted)))

    def print_clock_cycles(self):
        print("Clock\tState Before\tFeedback\tState After")
        for i, (state_before, feedback) in enumerate(self.clock_cycles):
            state_after = np.roll(state_before, -1)
            state_after[-1] = feedback
            print(f"{i+1}\t{state_before}\t{feedback}\t\t{state_after}")


input_polynomial = input("Enter the polynomial, e.g., '1 + x^1 + x^3': ")
input_initial_state = input("Enter the initial state as a binary string, e.g., '10101': ")

# Convert user input into taps and initial state
taps = polynomial_to_taps(input_polynomial)
initial_state = [int(bit) for bit in input_initial_state]

# Initialize the LFSR with the user input
lfsr = LFSR(taps, initial_state)

# Encrypt a message
message_to_encrypt = "Mohamed"
encrypted_message = lfsr.encrypt(message_to_encrypt)
print("Encrypted message:", encrypted_message)

# Decrypt the message
lfsr.reset()  # Reset the LFSR to the initial state for decryption
decrypted_message = lfsr.decrypt(encrypted_message)
print("Decrypted message:", decrypted_message)

# Print the LFSR clock cycles
lfsr.print_clock_cycles()
