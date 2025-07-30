import pytest
from cyph3r.crypto import CryptoManager


@pytest.mark.unit
def test_encrypt_decrypt_aes_gcm():
    cm = CryptoManager()

    # Prepare input data
    secret = b"This is a top secret key"
    key = cm.generate_random_key_bytes(128)
    nonce = cm.generate_random_key_bytes(96)

    # Encrypt
    ciphertext = cm.encrypt_with_aes_gcm(key, nonce, secret)

    # Decrypt
    decrypted = cm.decrypt_with_aes_gcm(key, nonce, ciphertext)

    # Validate
    assert decrypted == secret
