from django.shortcuts import render, redirect
from django.conf import settings
import os
from django.contrib import messages
from .forms import WirelessKeyInfoForm, WirelessProtectionStorageForm
from .crypto import CryptoManager
from pprint import pprint


def index(request):
    print(request.session)
    return render(request, "cyph3r/index.html")


def wireless(request):
    return render(request, "cyph3r/wireless.html")


##############
# HTMX Views #
##############


def wireless_ceremony_intro(request):
    return render(request, "cyph3r/wireless-ceremony-intro.html")


def wireless_key_info_form(request):
    """
    Renders Key Information form
    """
    return render(
        request, "cyph3r/wireless-key-info.html", {"form": WirelessKeyInfoForm()}
    )


def wireless_key_protection_storage_form(request):
    """
    Stores key information into session and renders the PGP file upload form.
    """
    form = WirelessKeyInfoForm()

    # Check if the request is a POST request and includes HTMX headers
    if request.method == "POST" and request.htmx:
        print(request.POST)

        # Bind the form with POST data for the key information
        form = WirelessKeyInfoForm(request.POST)

        # Validate the form data
        if form.is_valid():
            # Store key information into the session
            request.session.update(
                {
                    "key_identifier": form.cleaned_data["key_identifier"],
                    "key_type": form.cleaned_data["key_type"],
                    "protocol": form.cleaned_data["protocol"],
                    "key_size": form.cleaned_data["key_size"],
                }
            )

            # Render the PGP file upload form on successful form submission
            return render(
                request,
                "cyph3r/wireless-key-protection-storage.html",
                {"form": WirelessProtectionStorageForm()},
            )
        else:
            # Render the key info form if form validation fails
            return render(request, "cyph3r/wireless-key-info.html", {"form": form})


def wireless_generate_keys(request):
    """
    Validates PGP public keys, generates secrets/shares, encrypts with PGP key.
    """

    # Initialize the form for file upload
    form = WirelessProtectionStorageForm()

    # Check if the request is a POST request and includes HTMX headers
    if request.method == "POST" and request.htmx:
        # Populate the form with POST data and PGP public key files
        form = WirelessProtectionStorageForm(request.POST, request.FILES)

        # Validate the form data
        if form.is_valid():
            # Initialize CryptoManager for cryptographic operations
            cm = CryptoManager()

            # Retrieve key size and type from the session
            key_size = int(request.session["key_size"])
            key_type = request.session["key_type"]

            # Generate the secret key as a random byte string of the given key size
            secret_key = cm.generate_random_key_bytes(key_size)

            # Split the secret key into shares using XOR splitting, creating 3 shares
            shares = cm.xor_split_secret(secret_key, key_size, 3)

            print(f"secret key: {secret_key}")
            print(f"shares = {shares}")

            # Initialize the lists to store the filenames of the encrypted keys (or shares) for download
            provider_files = []
            security_officer_files = []

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
                key_share_hex = cm.bytes_to_hex(shares[key_index - 1])

                # Create the filename for the encrypted key component and append filename to provider_files list for download
                provider_file_name = (
                    f"provider-{key_type}-key-component-{key_index}-{keyid}.txt.gpg"
                )
                save_path = os.path.join(settings.MEDIA_ROOT, provider_file_name)
                provider_files.append(provider_file_name)

                # Format the key share, KCV, key type, and size into a structured text format for provider
                key_share_data = cm.gd_text_format(
                    key_share_hex, kcv, key_type, key_size, key_index
                )

                # Encrypt the key share data using the provider's public key
                encrypted_data = cm.gpg.encrypt(
                    key_share_data, fingerprint, always_trust=True, armor=False
                )

                # Save the encrypted key share to the designated file
                with open(save_path, "wb") as fp:
                    fp.write(encrypted_data.data)

            # Check if an Engineer's public key was uploaded
            if form.cleaned_data["engineer_public_key"]:
                file = form.cleaned_data["engineer_public_key"]

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
                security_officer_file_name = (
                    f"security-officer-{key_type}-key-{keyid}.txt.gpg"
                )
                save_path = os.path.join(
                    settings.MEDIA_ROOT, security_officer_file_name
                )
                security_officer_files.append(security_officer_file_name)

                # Encrypt the key share data using the provider's public key
                encrypted_data = cm.gpg.encrypt(
                    secret_key_hex, fingerprint, always_trust=True, armor=False
                )

                # Save the encrypted secret key to the designated file
                with open(save_path, "wb") as fp:
                    fp.write(encrypted_data.data)

            # Render the success page upon successful key generation and encryption
            return render(
                request,
                "cyph3r/wireless-generate-keys.html",
                {
                    "provider_files": provider_files,
                    "security_officer_files": security_officer_files,
                },
            )
        else:
            # Render the PGP Upload form again with validation errors if the form is invalid
            return render(request, "cyph3r/wireless-pgp-upload.html", {"form": form})
