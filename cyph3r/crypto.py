import secrets
import tempfile
import gnupg
import logging
import binascii
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes, aead
from cryptography.hazmat.primitives import padding
from cryptography import exceptions as crypto_exceptions
from Crypto.Protocol.SecretSharing import Shamir

"""
This module provides a CryptoManager class that encapsulates cryptographic operations.
The class provides methods to generate random keys, encrypt and decrypt data using AES-GCM and AES-CFB, key splitting etc.
"""

# Define the logger for the module
logger = logging.getLogger(__name__)


class CryptoManager:
    def __init__(self, homedir=None):
        if homedir is None:
            homedir = tempfile.mkdtemp()
        self.homedir = homedir
        self.gpg = gnupg.GPG(gnupghome=self.homedir)

    def generate_random_key_bytes(self, key_size: int) -> bytes:
        if key_size % 8 != 0:
            raise ValueError("Number of bits must be a multiple of 8")
        bytes_length = int(key_size / 8)
        return secrets.token_bytes(bytes_length)

    def generate_random_key_hex(self, key_size: int) -> str:
        if key_size % 8 != 0:
            raise ValueError("Number of bits must be a multiple of 8")
        bytes_length = int(key_size / 8)
        return secrets.token_hex(bytes_length)

    def bytes_to_hex(self, byte_data: bytes) -> str:
        return binascii.hexlify(byte_data).decode("utf-8")

    def hex_to_bytes(self, hex_string: str) -> bytes:
        return binascii.unhexlify(hex_string)

    def bytes_to_utf8(self, data: bytes) -> str:
        try:
            return data.decode("utf-8")
        except UnicodeDecodeError:
            return self.bytes_to_hex(data)

    def generate_pgp_key(self, name_email):
        input_data = self.gpg.gen_key_input(name_email=name_email)
        return self.gpg.gen_key(input_data)

    def encrypt_with_pgp(self, data, recipient_key):
        return self.gpg.encrypt(data, recipient_key)

    def decrypt_with_pgp(self, encrypted_data, passphrase):
        return self.gpg.decrypt(encrypted_data, passphrase=passphrase)

    def encrypt_with_aes_gcm(
        self, key: bytes, nonce: bytes, plaintext: bytes, aad: bytes = None
    ) -> bytes:
        """Encrypts data using AES-GCM."""
        aesgcm = aead.AESGCM(key)
        try:
            ct = aesgcm.encrypt(nonce, plaintext, aad)
            return ct
        except crypto_exceptions.OverflowError as err:
            logger.error(f"Encryption failed: {err}", exc_info=True)

    def decrypt_with_aes_gcm(
        self, key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes = None
    ) -> bytes:
        """Decrypts data using AES-GCM."""
        aesgcm = aead.AESGCM(key)
        try:
            pt = aesgcm.decrypt(nonce, ciphertext, aad)
            return pt
        except crypto_exceptions.InvalidTag as err:
            logger.error(f"Decryption failed: {err}", exc_info=True)

    def encrypt_with_aes_cbc(self, key: bytes, iv: bytes, plaintext: bytes) -> bytes:
        """Encrypts data using AES-CBC."""
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(plaintext) + padder.finalize()
        ct = encryptor.update(padded_data) + encryptor.finalize()
        return ct

    def decrypt_with_aes_cbc(self, key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
        """Decrypts data using AES-CBC."""
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        decrypted_padded_data = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        pt = unpadder.update(decrypted_padded_data) + unpadder.finalize()
        return pt

    def shamir_split_secret(
        self, threshold_shares: int, total_shares: int, secret: bytes
    ) -> list:
        """Splits 128 bits secret into shares using Shamir's Secret Sharing."""
        return Shamir.split(threshold_shares, total_shares, secret)

    def shamir_reconstruct_secret(self, shares: list) -> bytes:
        """Reconstructs the secret from shares using Shamir's Secret Sharing.
        :param shares: A list of tuples (key share number, key share in bytes) to reconstruct the secret
        """
        return Shamir.combine(shares)

    def xor_split_secret(
        self, secret_key: bytes, key_size: int, num_shares: int
    ) -> list:
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

    def xor_reconstruct_secret(self, shares: list) -> bytes:
        """
        Reconstruct the secret key from the provided key shares using bitwise XOR.

        :param shares: A list of key shares (each a bytes object)
        :return: The reconstructed secret key (bytes)
        """
        if len(shares) < 2:
            raise ValueError("At least two shares are required to reconstruct the key")
        secret_key = shares[0]
        for share in shares[1:]:
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
        # Prepare the data in the requested text format
        data = f"Key Name: {key_type.title()}\n\nKey ID/Index: {key_index}\n\nKey Component {key_index} ({int(key_size/8)} bytes):\n{key_share.upper()}\n\nKey Component {key_index} KCV (AES ECB):\n{kcv.upper()}"
        return data.encode("utf-8")

    def so_text_format(self, key_share, protocol, key_type, key_index):
        # Prepare the data to be written into file in this format
        data = f"Protocol: {protocol.title()}\n\nKey Type: {key_type.title()}\n\nKey ID/Index: {key_index}\n\nWrap Key Share:\n{key_share.upper()}"
        return data.encode("utf-8")

    def wrapped_key_text_format(self, protocol, key_type, wrapped_key):
        # Prepare the data to be written into file in this format
        data = f"Protocol: {protocol.title()}\n\nKey Type: {key_type.title()}\n\nWrapped Key:\n{wrapped_key.upper()}"
        return data.encode("utf-8")

    def data_protection_text_format(self, mode, nonce, text, aad=None):
        # Prepare the data to be written into file in this format
        data = f"AES Mode: {mode.upper()}\n\nNonce/IV: {nonce.upper()}\n\nAAD: {aad}\n\nText: {text}"
        return data.encode("utf-8")
