import os
from .crypto import CryptoManager
from django.conf import settings
from django import forms

# Constants for file extensions
GPG_FILE_EXTENSION = ".txt.gpg"


##########################################
# Helper Functions for File Manipulation #
##########################################


def create_directory_if_not_exists(directory_path: str):
    """Creates a directory if it doesn't already exist."""
    if not os.path.exists(directory_path):
        os.makedirs(directory_path)


def save_encrypted_data_to_file(file_path: str, encrypted_data: bytes):
    """Saves encrypted data to a file."""
    with open(file_path, "wb") as fp:
        fp.write(encrypted_data)


def import_pgp_key_from_file(cm: CryptoManager, file):
    """Imports PGP key from a file into the CryptoManager."""
    file.seek(0)
    cm.gpg.import_keys(file.read())
    imported_key = cm.gpg.list_keys()[-1]
    return imported_key["fingerprint"], imported_key["keyid"]


##########################################
# Wireless Module File Creation Functions #
##########################################


def create_wireless_wrapped_secret_key_file(
    cm: CryptoManager, wrapped_data: bytes, protocol: str, key_type: str
) -> str:
    """Writes Encrypted key to a file for download."""
    wrapped_data_file_name = f"{protocol}-{key_type}-wrapped-secret.txt"
    save_path = os.path.join(settings.MEDIA_ROOT, wrapped_data_file_name)

    with open(save_path, "wb") as fp:
        data = cm.wrapped_key_text_format(
            protocol, key_type, cm.bytes_to_hex(wrapped_data)
        )
        fp.write(data)

    return wrapped_data_file_name


def create_wireless_provider_encrypted_key_files(
    form: forms.Form,
    cm: CryptoManager,
    secret_key: bytes,
    key_size: int,
    key_type: str,
    protocol: str,
    number_of_shares: int,
) -> list:
    """Creates XOR key shares encrypted with Provider PGP keys and saves them to files."""
    shares = cm.xor_split_secret(secret_key, key_size, number_of_shares)
    provider_files = []

    for key_index, file in enumerate(
        form.cleaned_data["provider_public_keys"], start=1
    ):
        fingerprint, keyid = import_pgp_key_from_file(cm, file)
        kcv = cm.generate_kcv(shares[key_index - 1])
        xor_key_share_hex = cm.bytes_to_hex(shares[key_index - 1])
        provider_file_name = (
            f"G+D-{protocol}-{key_type}-key-{key_index}-{keyid}{GPG_FILE_EXTENSION}"
        )
        save_path = os.path.join(settings.MEDIA_ROOT, provider_file_name)
        provider_files.append(provider_file_name)

        gd_key_share_data = cm.gd_text_format(
            xor_key_share_hex, kcv, key_type, key_size, key_index
        )
        encrypted_data = cm.gpg.encrypt(
            gd_key_share_data, fingerprint, always_trust=True, armor=False
        )
        save_encrypted_data_to_file(save_path, encrypted_data.data)

    return provider_files


def create_wireless_security_officers_encrypted_key_files(
    form: forms.Form, cm: CryptoManager, key_type: str, protocol: str, shares: list
) -> list:
    """Encrypts files containing the Shamir wrap key share with security officer (SO) PGP keys."""
    security_officer_file_names = []

    for key_index, file in enumerate(
        form.cleaned_data["security_officers_public_keys"], start=1
    ):
        fingerprint, keyid = import_pgp_key_from_file(cm, file)
        security_officer_file_name = (
            f"SO-{protocol}-{key_type}-wrap-key-{key_index}-{keyid}{GPG_FILE_EXTENSION}"
        )
        save_path = os.path.join(settings.MEDIA_ROOT, security_officer_file_name)
        security_officer_file_names.append(security_officer_file_name)

        wrap_key_share_hex = cm.bytes_to_hex(shares[key_index - 1][1])
        so_wrap_key_share_data = cm.so_text_format(
            wrap_key_share_hex, protocol, key_type, key_index
        )
        encrypted_so_wrap_key_share_data = cm.gpg.encrypt(
            so_wrap_key_share_data, fingerprint, always_trust=True, armor=False
        )
        save_encrypted_data_to_file(save_path, encrypted_so_wrap_key_share_data.data)

    return security_officer_file_names


def create_wireless_milenage_encrypted_file(
    form: forms.Form, cm: CryptoManager, secret_key: bytes, key_type: str
) -> str:
    """Wraps the secret key with PGP public key of engineer entering milenage keys in provider terminal and saves it to file."""
    file = form.cleaned_data["milenage_public_key"]
    fingerprint, keyid = import_pgp_key_from_file(cm, file)

    secret_key_hex = cm.bytes_to_hex(secret_key)
    milenage_file_name = f"milenage-{key_type}-key-{keyid}{GPG_FILE_EXTENSION}"
    save_path = os.path.join(settings.MEDIA_ROOT, milenage_file_name)

    encrypted_data = cm.gpg.encrypt(
        secret_key_hex, fingerprint, always_trust=True, armor=False
    )
    save_encrypted_data_to_file(save_path, encrypted_data.data)

    return milenage_file_name


############################################
# Key Share Module File Creation Functions #
############################################


def write_key_share_so_public_keys_to_disk(
    form: forms.Form, user_directory: str
) -> list:
    """Writes the Security Officer's public keys to a file to encrypt key or key-share."""
    path = os.path.join(settings.MEDIA_ROOT, user_directory)
    create_directory_if_not_exists(path)

    key_share_public_key_files = []

    for file in form.cleaned_data["key_share_public_keys"]:
        save_path = os.path.join(path, file.name)
        with open(save_path, "wb") as fp:
            for chunk in file.chunks():
                fp.write(chunk)

        key_share_public_key_files.append(save_path)

    return key_share_public_key_files


def create_key_share_reconstruct_secret_file(
    cm: CryptoManager, secret_key: bytes, user_directory: str, public_key_files: list
) -> list:
    """Wraps the reconstructed secret key with PGP public key."""
    path = os.path.join(settings.MEDIA_ROOT, user_directory)
    create_directory_if_not_exists(path)

    key_share_files_names = []

    for file in public_key_files:
        with open(file, "rb") as fp:
            cm.gpg.import_keys(fp.read())

        imported_key = cm.gpg.list_keys()[-1]
        fingerprint, keyid = imported_key["fingerprint"], imported_key["keyid"]
        file_name = f"key-share-reconstructed-secret-{keyid}{GPG_FILE_EXTENSION}"
        save_path = os.path.join(path, file_name)
        key_share_files_names.append(file_name)

        encrypted_data = cm.gpg.encrypt(
            cm.bytes_to_hex(secret_key), fingerprint, always_trust=True, armor=False
        )
        save_encrypted_data_to_file(save_path, encrypted_data.data)

    return key_share_files_names


def create_key_share_split_secret_files(
    cm: CryptoManager, shares: list, user_directory: str, public_key_files: list
) -> list:
    """Splits the secret key into shares and encrypts each share."""
    path = os.path.join(settings.MEDIA_ROOT, user_directory)
    create_directory_if_not_exists(path)

    key_share_files_names = []

    for idx, file in enumerate(public_key_files, start=1):
        with open(file, "rb") as fp:
            cm.gpg.import_keys(fp.read())

        imported_key = cm.gpg.list_keys()[-1]
        fingerprint, keyid = imported_key["fingerprint"], imported_key["keyid"]
        file_name = f"key-share-split-secret-index-{idx}-{keyid}{GPG_FILE_EXTENSION}"
        save_path = os.path.join(path, file_name)
        key_share_files_names.append(file_name)

        share_data = (
            shares[idx - 1][1]
            if isinstance(shares[idx - 1], tuple)
            else shares[idx - 1]
        )
        encrypted_data = cm.gpg.encrypt(
            cm.bytes_to_hex(share_data), fingerprint, always_trust=True, armor=False
        )
        save_encrypted_data_to_file(save_path, encrypted_data.data)

    return key_share_files_names
