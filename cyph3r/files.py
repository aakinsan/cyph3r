from .crypto import CryptoManager
from django.conf import settings
from django import forms
import os

"""
Helper functions to create files containing encrypted secret keys and key shares.

"""
###########################################
# Wireless Module File Creation Functions #
###########################################


def create_wireless_wrapped_secret_key_file(
    cm: CryptoManager, wrapped_data: bytes, protocol: str, key_type: str
) -> str:
    # Write Encrypted key to file for download.
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

    # Split the secret key into shares using XOR splitting
    shares = cm.xor_split_secret(secret_key, key_size, number_of_shares)

    # Initialize the list to store the filenames of the encrypted keys (or shares) for download
    provider_files = []

    # Loop through each uploaded provider's public key file
    for key_index, file in enumerate(
        form.cleaned_data["provider_public_keys"], start=1
    ):
        # Reset the file pointer to the beginning of the file
        file.seek(0)

        # Import the Provider's PGP public keys from the uploaded file
        cm.gpg.import_keys(file.read())

        # Retrieve the latest imported key's fingerprint and keyid
        imported_key = cm.gpg.list_keys()[-1]
        fingerprint = imported_key["fingerprint"]
        keyid = imported_key["keyid"]

        # Generate Key Check Value (KCV) for the current key share
        kcv = cm.generate_kcv(shares[key_index - 1])

        # Convert the key share to a hex string format
        xor_key_share_hex = cm.bytes_to_hex(shares[key_index - 1])

        # Create the filename for the encrypted key component and append filename to provider_files list for download
        provider_file_name = (
            f"G+D-{protocol}-{key_type}-key-{key_index}-{keyid}.txt.gpg"
        )
        save_path = os.path.join(settings.MEDIA_ROOT, provider_file_name)
        provider_files.append(provider_file_name)

        # Prepare provider key share data in the requested text format
        gd_key_share_data = cm.gd_text_format(
            xor_key_share_hex, kcv, key_type, key_size, key_index
        )

        # Encrypt the key share data using the provider's public key
        encrypted_data = cm.gpg.encrypt(
            gd_key_share_data, fingerprint, always_trust=True, armor=False
        )

        # Save the encrypted key share to the designated file
        with open(save_path, "wb") as fp:
            fp.write(encrypted_data.data)

    # Return Provider files list for download
    return provider_files


def create_wireless_security_officers_encrypted_key_files(
    form: forms.Form,
    cm: CryptoManager,
    key_type: str,
    protocol: str,
    shares: list,
) -> list:
    """Encrypts files containing the Shamir wrap key share with security officer (SO) PGP keys."""
    # Initialize the list to store the file names of the encrypted shares for download
    security_officer_file_names = []

    # Loop through each uploaded SO's public key file
    for key_index, file in enumerate(
        form.cleaned_data["security_officers_public_keys"], start=1
    ):
        # Reset the file pointer to the beginning of the file
        file.seek(0)

        # Import the SO's PGP public keys from the uploaded file
        cm.gpg.import_keys(file.read())

        # Retrieve the latest imported key's fingerprint and keyid
        imported_key = cm.gpg.list_keys()[-1]
        fingerprint = imported_key["fingerprint"]
        keyid = imported_key["keyid"]

        # Create the filename for the encrypted key component and append filename to security_officer_files list for download
        security_officer_file_name = (
            f"SO-{protocol}-{key_type}-wrap-key-{key_index}-{keyid}.txt.gpg"
        )
        save_path = os.path.join(settings.MEDIA_ROOT, security_officer_file_name)
        security_officer_file_names.append(security_officer_file_name)

        # Extract wrap key share from the list of shares and convert share from bytes to human readable hex string
        # Allows Security officer to easily reconstruct the wrap key but care should be taken as it is human readable
        wrap_key_share_hex = cm.bytes_to_hex(shares[key_index - 1][1])

        # Prepare security officer file content
        so_wrap_key_share_data = cm.so_text_format(
            wrap_key_share_hex, protocol, key_type, key_index
        )

        # Encrypt the key share data using the provider's public key
        encrypted_so_wrap_key_share_data = cm.gpg.encrypt(
            so_wrap_key_share_data, fingerprint, always_trust=True, armor=False
        )

        # Save the encrypted key share to the designated file
        with open(save_path, "wb") as fp:
            fp.write(encrypted_so_wrap_key_share_data.data)

    # Return Provider files list for download
    return security_officer_file_names


def create_wireless_milenage_encrypted_file(
    form: forms.Form,
    cm: CryptoManager,
    secret_key: bytes,
    key_type: str,
):
    """Wraps the secret key with PGP public key of engineer entering milenage keys in provider terminal and saves it to gile."""

    file = form.cleaned_data["milenage_public_key"]

    # Reset the file pointer to the beginning of the file
    file.seek(0)

    # Import the engineer's PGP public keys from the uploaded file
    cm.gpg.import_keys(file.read())

    # Retrieve the latest imported key's fingerprint and keyid
    imported_key = cm.gpg.list_keys()[-1]
    fingerprint = imported_key["fingerprint"]
    keyid = imported_key["keyid"]

    # Convert the secret key to a hex string format
    secret_key_hex = cm.bytes_to_hex(secret_key)

    # Create the filename for the encrypted key and append filename to security_officer_files list for download
    milenage_file_name = f"milenage-{key_type}-key-{keyid}.txt.gpg"
    save_path = os.path.join(settings.MEDIA_ROOT, milenage_file_name)

    # Encrypt the key share data using the provider's public key
    encrypted_data = cm.gpg.encrypt(
        secret_key_hex, fingerprint, always_trust=True, armor=False
    )

    # Save the encrypted secret key to the designated file
    with open(save_path, "wb") as fp:
        fp.write(encrypted_data.data)

    # Return the filename of the encrypted milenage keys for download
    return milenage_file_name


############################################
# Key Share Module File Creation Functions #
############################################


def write_key_share_so_public_keys_to_disk(
    form: forms.Form, user_directory: str
) -> list:
    """Writes the Security Officer's public keys to a file to encrypt key or key-share."""

    # Create the directory if it doesn't exist
    path = settings.MEDIA_ROOT / user_directory
    if not os.path.exists(path):
        os.makedirs(path)

    # Initialize the list to store the file names of the public keys
    key_share_public_key_files = []

    # Write uploaded public keys to disk
    for file in form.cleaned_data["key_share_public_keys"]:
        # Reset the file pointer to the beginning of the file
        file.seek(0)
        save_path = os.path.join(path, file.name)

        with open(save_path, "wb") as fp:
            for chunk in file.chunks():
                fp.write(chunk)

        # Append file name to list of public key files
        key_share_public_key_files.append(save_path)

    # Return the list of file paths to the public key files
    return key_share_public_key_files


def create_key_share_shamir_secret_file(
    cm: CryptoManager,
    secret_key: bytes,
    user_directory: str,
    public_key_files: list,
):
    """Wraps the reconstructed secret key with PGP public key."""
    # Create the directory if it doesn't exist
    path = settings.MEDIA_ROOT / user_directory
    if not os.path.exists(path):
        os.makedirs(path)

    # Initialize the list to store the file names of the encrypted secret
    key_share_files_names = []

    for file in public_key_files:
        with open(file, "rb") as fp:

            # Import the PGP public key from the uploaded file
            cm.gpg.import_keys(fp.read())

        # Retrieve the latest imported key's fingerprint and keyid
        imported_key = cm.gpg.list_keys()[-1]
        fingerprint = imported_key["fingerprint"]
        keyid = imported_key["keyid"]

        # Create the filename for the encrypted key and append filename to keys_share_files list for download
        file_name = f"key-share-secret-{keyid}.txt.gpg"
        save_path = os.path.join(path, file_name)
        key_share_files_names.append(file_name)

        # Encrypt the secret with PGP public key
        encrypted_data = cm.gpg.encrypt(
            cm.bytes_to_hex(secret_key), fingerprint, always_trust=True, armor=False
        )

        # Save the encrypted secret key to the designated file save path
        with open(save_path, "wb") as fp:
            fp.write(encrypted_data.data)

    # Return the filename of the encrypted milenage keys for download
    return key_share_files_names


def create_key_share_reconstruct_secret_file(
    cm: CryptoManager,
    secret_key: bytes,
    user_directory: str,
    public_key_files: list,
):
    """Wraps the reconstructed secret key with PGP public key."""
    # Create the directory if it doesn't exist
    path = settings.MEDIA_ROOT / user_directory
    if not os.path.exists(path):
        os.makedirs(path)

    # Initialize the list to store the file names of the encrypted secret
    key_share_files_names = []

    for file in public_key_files:
        with open(file, "rb") as fp:

            # Import the PGP public key from the uploaded file
            cm.gpg.import_keys(fp.read())

        # Retrieve the latest imported key's fingerprint and keyid
        imported_key = cm.gpg.list_keys()[-1]
        fingerprint = imported_key["fingerprint"]
        keyid = imported_key["keyid"]

        # Create the filename for the encrypted key and append filename to keys_share_files list for download
        file_name = f"key-share-secret-{keyid}.txt.gpg"
        save_path = os.path.join(path, file_name)
        key_share_files_names.append(file_name)

        # Encrypt the secret with PGP public key
        encrypted_data = cm.gpg.encrypt(
            cm.bytes_to_hex(secret_key), fingerprint, always_trust=True, armor=False
        )

        # Save the encrypted secret key to the designated file save path
        with open(save_path, "wb") as fp:
            fp.write(encrypted_data.data)

    # Return the filename of the encrypted milenage keys for download
    return key_share_files_names
