import secrets
import tempfile
import gnupg
import binascii
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes, aead
from Crypto.Protocol.SecretSharing import Shamir


class CryptoManager:
    def __init__(self):
        temp_dir = tempfile.mkdtemp()
        self.gpg = gnupg.GPG(gnupghome=temp_dir)

    def generate_random_key_bytes(self, key_size):
        if key_size % 8 != 0:
            raise ValueError("Number of bits must be a multiple of 8")
        bytes = int(key_size / 8)
        return secrets.token_bytes(bytes)

    def generate_random_key_hex(self, key_size):
        if key_size % 8 != 0:
            raise ValueError("Number of bits must be a multiple of 8")
        bytes = int(key_size / 8)
        return secrets.token_hex(bytes)

    def bytes_to_hex(self, byte_data):
        return binascii.hexlify(byte_data).decode("utf-8")

    def hex_to_bytes(self, hex_string):
        return binascii.unhexlify(hex_string)

    def generate_pgp_key(self, name_email):
        input_data = self.gpg.gen_key_input(name_email=name_email)
        return self.gpg.gen_key(input_data)

    def encrypt_with_pgp(self, data, recipient_key):
        return self.gpg.encrypt(data, recipient_key)

    def decrypt_with_pgp(self, encrypted_data, passphrase):
        return self.gpg.decrypt(encrypted_data, passphrase=passphrase)

    def encrypt_with_aes(self, key, data):
        iv = secrets.token_bytes(16)
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
        encryptor = cipher.encryptor()
        return iv + encryptor.update(data) + encryptor.finalize()

    def decrypt_with_aes(self, key, encrypted_data):
        iv = encrypted_data[:16]
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
        decryptor = cipher.decryptor()
        return decryptor.update(encrypted_data[16:]) + decryptor.finalize()

    def shamir_split_secret(self, secret, total_shares, threshold_shares):
        # Convert secret to hexadecimal for compatibility with Shamir's Secret Sharing
        pass

    def shamir_reconstruct_secret(self, shares):
        pass

    def xor_split_secret(self, secret_key, key_size, num_shares):
        """
        Split the secret key into num_shares using bitwise XOR.

        :param secret_key: The original secret key (bytes)
        :param num_shares: The number of shares to generate
        :return: A list of key shares (each a bytes object)
        """
        if num_shares < 2:
            raise ValueError("Number of shares must be at least 2")
        shares = [
            self.generate_random_key_bytes(key_size) for _ in range(num_shares - 1)
        ]
        last_share = secret_key
        for share in shares:
            last_share = bytes(a ^ b for a, b in zip(last_share, share))
        shares.append(last_share)
        return shares

    def xor_reconstruct_secret(self, shares):
        """
        Reconstruct the secret key from the provided key shares using bitwise XOR.

        :param shares: A list of key shares (each a bytes object)
        :return: The reconstructed secret key (bytes)
        """
        if len(shares) < 2:
            raise ValueError("At least two shares are required to reconstruct the key")
        secret_key = shares[0]
        for share in shares[:1]:
            secret_key = bytes(a ^ b for a, b in zip(secret_key, share))
        return secret_key

    def generate_kcv(self, secret_key):
        # Prepare a block of zeroes (16 bytes for AES)
        zero_block = bytes(16)

        # Initialize AES encryption in ECB mode (typically used for KCV calculation)
        cipher = Cipher(algorithms.AES(secret_key), modes.ECB())
        encryptor = cipher.encryptor()

        # Encrypt the zero block with the key
        encrypted = encryptor.update(zero_block) + encryptor.finalize()

        # Return the first 3 bytes (6 hex characters) of the encrypted block as the KCV
        return encrypted[:3].hex()

    def store_key(self, key, storage_location):
        # Logic to store the key securely
        pass

    def gd_text_format(self, key_share, kcv, key_type, key_size, key_index):
        data = f"Key Name: {key_type.title()}\n\nKey ID/Index: {key_index}\n\nKey Component {key_index} ({int(key_size/8)} bytes):\n{key_share.upper()}\n\nKey Component {key_index} KCV (AES ECB):\n{kcv.upper()}"
        return data.encode("utf-8")


# Large prime number (for 256-bit security level)
_PRIME = 2**256 - 189


def _secure_random_int(prime):
    """Generates a secure random integer in the range [0, prime-1]"""
    return secrets.randbelow(prime)


def _eval_at(poly, x, prime):
    """Evaluates the polynomial (represented as a list of coefficients) at x modulo prime."""
    result = 0
    for coefficient in reversed(poly):
        result = (result * x + coefficient) % prime
    return result


def make_random_shares(secret, minimum, shares, prime=_PRIME):
    """
    Generates a Shamir's Secret Sharing scheme for the given secret.
    Returns share points (x, y).
    """
    if minimum > shares:
        raise ValueError(
            "The number of shares must be greater than or equal to the threshold."
        )

    # Secret is the constant term of the polynomial
    poly = [secret] + [_secure_random_int(prime) for _ in range(minimum - 1)]

    points = [(i, _eval_at(poly, i, prime)) for i in range(1, shares + 1)]
    return points


def _extended_gcd(a, b):
    """Extended Euclidean Algorithm to find modular inverse"""
    x, last_x = 0, 1
    y, last_y = 1, 0
    while b:
        q = a // b
        a, b = b, a % b
        x, last_x = last_x - q * x, x
        y, last_y = last_y - q * y, y
    return last_x


def _mod_inverse(x, prime):
    """Returns modular inverse of x under prime using the extended Euclidean algorithm"""
    return _extended_gcd(x, prime) % prime


def _lagrange_interpolate(x, x_s, y_s, prime):
    """
    Lagrange interpolation to reconstruct the secret from shares (x_s, y_s).
    Returns the polynomial evaluated at x.
    """
    k = len(x_s)
    assert k == len(set(x_s)), "Share x-coordinates must be distinct."

    def product(vals):
        result = 1
        for v in vals:
            result *= v
        return result

    numerator = 0
    for i in range(k):
        others = list(x_s)
        current = others.pop(i)

        # Numerator: (x - x_j) for all j != i
        num_product = product(x - o for o in others) % prime

        # Denominator: (x_i - x_j) for all j != i
        den_product = product(current - o for o in others) % prime

        # Add the contribution from y_i
        numerator += y_s[i] * num_product * _mod_inverse(den_product, prime)
        numerator %= prime

    return numerator


def recover_secret(shares, prime=_PRIME):
    """
    Recovers the secret from share points (x, y).
    """
    if len(shares) < 2:
        raise ValueError("At least two shares are needed to recover the secret.")

    x_s, y_s = zip(*shares)
    return _lagrange_interpolate(0, x_s, y_s, prime)


# Example usage:
if __name__ == "__main__":
    # Secret to share (as an integer)
    secret = _secure_random_int(_PRIME)

    # Generate 5 shares with a threshold of 3
    shares = make_random_shares(secret, 3, 5)
    print("Generated Shares:", shares)

    # Recover the secret using 3 shares
    recovered_secret = recover_secret(shares[:3])
    print("Recovered Secret:", recovered_secret)

    # Verify that the original and recovered secrets are the same
    assert secret == recovered_secret, "The secret was not recovered correctly!"
