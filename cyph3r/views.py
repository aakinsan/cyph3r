from django.shortcuts import render, redirect
from django.conf import settings
import os
from django.contrib import messages
from .forms import (
    WirelessKeyInfoForm,
    WirelessGCPStorageForm,
    WirelessPGPUploadForm,
)
from .create_files import (
    create_provider_encrypted_key_files,
    create_milenage_encrypted_file,
    create_security_officers_encrypted_key_files,
)
from .crypto import CryptoManager


def index(request):
    return render(request, "cyph3r/index.html")


def wireless(request):
    return render(request, "cyph3r/wireless.html")


def wireless_test(request):
    return render(request, "cyph3r/wirelessx.html")


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


def wireless_gcp_storage_form(request):
    """
    Renders GCP Storage form
    """
    # Check if the request is a POST request and includes HTMX headers
    if request.method == "POST" and request.htmx:

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

            # Render the GCP Storage form on successful form submission
            return render(
                request,
                "cyph3r/wireless-gcp-storage.html",
                {"form": WirelessGCPStorageForm()},
            )
        else:
            # Render the key info form if form validation fails
            return render(request, "cyph3r/wireless-key-info.html", {"form": form})
    else:
        return render(
            request,
            "cyph3r/wireless-gcp-storage.html",
            {"form": WirelessGCPStorageForm()},
        )


def wireless_pgp_upload_form(request):
    """
    Stores key information into session and renders the PGP file upload form.
    """
    # Check if the request is a POST request and includes HTMX headers
    if request.method == "POST" and request.htmx:

        # Bind the form with POST data for the key information
        form = WirelessGCPStorageForm(request.POST)

        # Validate the form data
        if form.is_valid():
            # Store key information into the session
            request.session.update(
                {
                    "gcp_project_id": form.cleaned_data["gcp_project_id"],
                    "gcp_kms_keyring": form.cleaned_data["gcp_kms_keyring"],
                    "gcp_kms_key": form.cleaned_data["gcp_kms_key"],
                }
            )

            # Render the PGP file upload form on successful form submission
            return render(
                request,
                "cyph3r/wireless-pgp-upload.html",
                {"form": WirelessPGPUploadForm()},
            )
        else:
            # Render the key info form if form validation fails
            return render(request, "cyph3r/wireless-gcp-storage.html", {"form": form})


def wireless_generate_keys(request):
    """
    Validates PGP public keys, generates secrets/shares, encrypts with PGP key.
    """

    # Check if the request is a POST request and includes HTMX headers
    if request.method == "POST" and request.htmx:
        # Populate the form with POST data and PGP public key files
        form = WirelessPGPUploadForm(request.POST, request.FILES)

        # Retrieve key size, protocol and type from the session
        key_size = int(request.session["key_size"])
        key_type = request.session["key_type"]
        protocol = request.session["protocol"]

        # Validate the form data
        if form.is_valid():
            # Initialize CryptoManager for cryptographic operations
            cm = CryptoManager()

            # Generate the secret key as a random byte string of the given key size
            secret_key = cm.generate_random_key_bytes(key_size)
            print(f"secret key = {secret_key}")

            provider_files = create_provider_encrypted_key_files(
                form,
                cm,
                secret_key,
                key_size,
                key_type,
                protocol,
                number_of_shares=3,
            )

            # Check if protocol is milenage and an Engineer's PGP public key was uploaded
            if form.cleaned_data["milenage_public_key"] and protocol == "milenage":
                # Create the encrypted milenage key file
                milenage_file = create_milenage_encrypted_file(
                    form, cm, secret_key, key_type
                )

            # Check if security officers' PGP public keys were uploaded
            if form.cleaned_data["security_officers_public_keys"]:

                # Generate key that will be shared among security officers
                sss_key = cm.generate_random_key_bytes(128)
                print(f"sss_key = {sss_key}")

                # Generate 12 bytes nonce for secret encryption using AES-GCM
                nonce = cm.generate_random_key_bytes(96)
                print(f"nonce = {nonce}")

                # Split the secret key into shares using shamir secret sharing
                shares = cm.shamir_split_secret(3, 5, sss_key)

                # Encrypt the secret key with using the sss key and nonce
                encrypted_secret_key = cm.encrypt_with_aes_gcm(
                    sss_key, nonce, secret_key
                )

                # Append 12 bytes nonce to encrypted secret key
                encrypted_data = nonce + encrypted_secret_key
                print(f"data = {encrypted_data}")

                # Create security officers encrypted key files
                security_officer_files = create_security_officers_encrypted_key_files(
                    form,
                    cm,
                    key_type,
                    protocol,
                    shares,
                )
                # Write Encrypted data to file for test.
                save_path = os.path.join(settings.MEDIA_ROOT, "encrypted_data")
                with open(save_path, "wb") as fp:
                    fp.write(encrypted_data)

            # Render the success page upon successful key generation and encryption if protocol is milenage
            if milenage_file:
                return render(
                    request,
                    "cyph3r/wireless-generate-keys.html",
                    {
                        "provider_files": provider_files,
                        "milenage_file": milenage_file,
                        "security_officer_files": security_officer_files,
                    },
                )
            else:
                # Render the success page upon successful key generation and encryption if protocol is tuak
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
