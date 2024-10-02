from django.shortcuts import render, redirect
from cryptography.fernet import Fernet
from django.core.cache import cache
from django.contrib import messages
from .forms import (
    WirelessKeyInfoForm,
    WirelessGCPStorageForm,
    WirelessPGPUploadForm,
    KeyShareInfoForm,
    KeyShareReconstructForm,
    KeyShareSplitForm,
)
from .files import (
    create_wireless_provider_encrypted_key_files,
    create_wireless_milenage_encrypted_file,
    create_wireless_security_officers_encrypted_key_files,
    create_wireless_wrapped_secret_key_file,
    write_key_share_so_public_keys_to_disk,
    create_key_share_reconstruct_secret_file,
    create_key_share_split_secret_files,
)
from .crypto import CryptoManager
from .gcp import GCPManager


"""
This module contains the views for the cyph3r app.

"""


def index(request):
    """
    Returns the Home Page
    """
    return render(request, "cyph3r/index.html")


def wireless(request):
    """
    Returns Wireless Key Ceremony Page
    """
    return render(request, "cyph3r/wireless.html")


def key_share_download(request):
    """
    Returns Key Share Download Page
    """
    # Get download links from session
    secret_files = request.session.get("secret_files")
    return render(
        request,
        "cyph3r/key_share_templates/key-share-download.html",
        {"secret_files": secret_files},
    )


def key_share_info(request):
    """
    Returns Key Share Info Page
    """
    # Clear the session entirely and create a new session
    # This is to ensure that the session is clean and does not contain any stale data
    request.session.flush()

    # Check if the request is a POST request
    if request.method == "POST":

        # Populate the form with POST data and PGP public key files
        form = KeyShareInfoForm(request.POST, request.FILES)

        # Validate the form data
        if form.is_valid():

            # Ensure that the session is created.
            # Session-key is used as folder name for storing the public keys & downloadable encrypted secret
            if not request.session.session_key:
                request.session.create()

            # Get the session key
            session_id = request.session.session_key

            # Store the form data in the session
            request.session["scheme"] = form.cleaned_data.get("scheme")
            request.session["key_task"] = form.cleaned_data.get("key_task")
            request.session["share_count"] = form.cleaned_data.get("share_count")
            request.session["threshold_count"] = form.cleaned_data.get(
                "threshold_count"
            )

            print(request.session["scheme"])
            print(f"session_id: {session_id}")

            # write uploaded public keys to directory name session_id on the server and get list of file names
            public_key_files = write_key_share_so_public_keys_to_disk(form, session_id)

            # Store the file names in the session
            request.session["public_key_files"] = public_key_files

            # Redirect to the key share reconstruction page if the key task is 'reconstruct'
            if form.cleaned_data.get("key_task") == "reconstruct":
                return redirect("key-share-reconstruct")

            # Redirect to the key share split page if the key task is 'split'
            if form.cleaned_data.get("key_task") == "split":
                return redirect("key-share-split")
        else:
            return render(
                request,
                "cyph3r/key_share_templates/key-share-info.html",
                {"form": form},
            )
    else:
        form = KeyShareInfoForm()
        return render(
            request, "cyph3r/key_share_templates/key-share-info.html", {"form": form}
        )


def key_share_split(request):
    """
    Returns Key Input Page for key splitting
    """
    if request.method == "POST":
        form = KeyShareSplitForm(request.POST)
        # Validate the form data
        if form.is_valid():
            # Check if the scheme is Shamir
            if request.session.get("scheme") == "shamir":
                # Check if the key share size is 128 bits
                if len(form.cleaned_data.get("key")) != 32:
                    form.add_error(
                        "key",
                        "key share size for shamir must be 128 bits.",
                    )
                    # Return the form with the error message
                    return render(
                        request,
                        "cyph3r/key_share_templates/key-share-split.html",
                        {"form": form},
                    )

            # Initialize the CryptoManager
            cm = CryptoManager()

            # Initialize the list to store the encrypted key shares
            if not request.session.get("key_shares"):
                request.session["key_shares"] = []

            # Get the total number of key shares required
            share_count = request.session.get("share_count")

            # Get the secret key from the form and convert to bytes
            secret_key = cm.hex_to_bytes(form.cleaned_data["key"])

            if request.session.get("scheme") == "shamir":
                # Retrieve the threshold number required to restore the secret
                threshold_count = request.session.get("threshold_count")

                # Split the secret key into shares using Shamir Secret Sharing
                shares = cm.shamir_split_secret(
                    threshold_count, share_count, secret_key
                )

            if request.session.get("scheme") == "xor":
                # Determine length of the secret key (bytes) e.g. 16 bytes = 128 bits
                key_size = len(secret_key) * 8
                # Split the secret key into shares using XOR Secret Sharing
                shares = cm.xor_split_secret(secret_key, key_size, share_count)

            secret_files = create_key_share_split_secret_files(
                cm,
                shares,
                request.session.session_key,
                request.session["public_key_files"],
            )

            # Add path to secret files to session
            request.session["secret_files"] = secret_files

            # Return page to download the secret file
            return redirect("key-share-download")

        else:
            return render(
                request,
                "cyph3r/key_share_templates/key-share-split.html",
                {"form": form},
            )
    else:
        form = KeyShareSplitForm()
        return render(
            request,
            "cyph3r/key_share_templates/key-share-split.html",
            {"form": form},
        )


def key_share_reconstruct(request):
    """
    Returns Key Share Input Page for key reconstruction
    """
    if request.method == "POST":
        form = KeyShareReconstructForm(request.POST)
        # Validate the form data
        if form.is_valid():
            # Check if the scheme is Shamir
            if request.session.get("scheme") == "shamir":
                # Check if the key index is provided
                if form.cleaned_data.get("key_index") is None:
                    form.add_error(
                        "key_index", "A key Index is required for Shamir scheme."
                    )
                    # Return the form with the error message
                    return render(
                        request,
                        "cyph3r/key_share_templates/key-share-reconstruct.html",
                        {"form": form},
                    )
                # Check if the key share size is 128 bits
                if len(form.cleaned_data.get("key_share")) != 32:
                    form.add_error(
                        "key_share",
                        "key share size for shamir must be 128 bits.",
                    )
                    # Return the form with the error message
                    return render(
                        request,
                        "cyph3r/key_share_templates/key-share-reconstruct.html",
                        {"form": form},
                    )
            # Retrieve or generate the Fernet key and store in cache
            encryption_key = cache.get(f"encryption_key_{request.session.session_key}")
            if not encryption_key:
                encryption_key = Fernet.generate_key()
                cache.set(
                    f"encryption_key_{request.session.session_key}",
                    encryption_key,
                    None,
                )

            # Initialize the CryptoManager and Fernet object
            cm = CryptoManager()
            f = Fernet(encryption_key)

            # Initialize the list to store the encrypted key shares
            if not request.session.get("key_shares"):
                request.session["key_shares"] = []

            if request.session.get("scheme") == "shamir":
                # Retrieve the threshold number required to restore the secret
                count = request.session.get("threshold_count")

                # Retrieve the key index from the form
                key_index = form.cleaned_data.get("key_index")

                # Encrypt the key share using the Fernet key and store in the session
                token = f.encrypt(cm.hex_to_bytes(form.cleaned_data["key_share"]))
                request.session["key_shares"].append(
                    (key_index, cm.bytes_to_hex(token))
                )  # Only JSON serializable data can be stored in session/ Bytes are not / converting to hex

            if request.session.get("scheme") == "xor":
                # Retrieve the share count required to restore the secret
                count = request.session.get("share_count")

                # Encrypt the key share using the Fernet key and store in the session
                token = f.encrypt(cm.hex_to_bytes(form.cleaned_data["key_share"]))
                request.session["key_shares"].append(
                    (cm.bytes_to_hex(token))
                )  # Only JSON serializable data can be stored in session/ Bytes are not / converting to hex

            # Increment the count of Security officers that have submitted their key shares
            request.session["submitted_officer_count"] += 1

            # Check if the threshold number of key shares have been submitted
            if request.session["submitted_officer_count"] > count:
                # Initialize the list to store the key shares
                shares = []

                if request.session.get("scheme") == "shamir":
                    # Decrypt the encrypted key shares and store in the list
                    for idx, encrypted_share in request.session["key_shares"]:
                        share = f.decrypt(cm.hex_to_bytes(encrypted_share))
                        shares.append((idx, share))

                    # Reconstruct the secret using the Shamir key shares
                    secret = cm.shamir_reconstruct_secret(shares)

                if request.session.get("scheme") == "xor":
                    # Decrypt the encrypted key shares and store in the list
                    for encrypted_share in request.session["key_shares"]:
                        share = f.decrypt(cm.hex_to_bytes(encrypted_share))
                        shares.append((share))

                    # Reconstruct the secret using the Shamir key shares
                    secret = cm.xor_reconstruct_secret(shares)

                # Write the secret to a file and encrypt with PGP public keys
                secret_files = create_key_share_reconstruct_secret_file(
                    cm,
                    secret,
                    request.session.session_key,
                    request.session["public_key_files"],
                )

                # Add path to secret files to session
                request.session["secret_files"] = secret_files

                # Clear cache data and relevant request session keys
                del request.session["submitted_officer_count"]
                del request.session["key_shares"]
                del request.session["scheme"]
                del request.session["key_task"]
                del request.session["share_count"]
                del request.session["threshold_count"]
                cache.delete(f"encryption_key_{request.session.session_key}")

                # Return page to download the secret file
                return redirect("key-share-download")
            else:
                return redirect("key-share-reconstruct")

        else:
            return render(
                request,
                "cyph3r/key_share_templates/key-share-reconstruct.html",
                {"form": form},
            )
    else:
        form = KeyShareReconstructForm()

        # Initialize the number of Security officers that have submitted their key shares
        if not request.session.get("submitted_officer_count"):
            request.session["submitted_officer_count"] = 1

        return render(
            request,
            "cyph3r/key_share_templates/key-share-reconstruct.html",
            {"form": form},
        )


################################
# HTMX Wireless Ceremony Views #
################################


def wireless_ceremony_intro(request):
    """
    Returns partial template for the Wireless Key Ceremony Introduction
    """
    return render(request, "cyph3r/wireless_templates/wireless-ceremony-intro.html")


def wireless_key_info_form(request):
    """
    Returns partial template for the Wireless Key Information form
    """
    return render(
        request,
        "cyph3r/wireless_templates/wireless-key-info.html",
        {"form": WirelessKeyInfoForm()},
    )


def wireless_gcp_storage_form(request):
    """
    Validates form POST data from /wireless-key-info.html
    Returns partial template for the GCP Storage info form
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

            # Render the GCP Storage form on successful form validation
            return render(
                request,
                "cyph3r/wireless_templates/wireless-gcp-storage.html",
                {"form": WirelessGCPStorageForm()},
            )
        else:
            # Render the key info form if form validation fails
            return render(
                request,
                "cyph3r/wireless_templates/wireless-key-info.html",
                {"form": form},
            )
    else:
        # Render the GCP Storage form if the request is not a POST request
        return render(
            request,
            "cyph3r/wireless_templates/wireless-gcp-storage.html",
            {"form": WirelessGCPStorageForm()},
        )


def wireless_pgp_upload_form(request):
    """
    Validates form POST data from /wireless-pgp-upload.html
    Returns partial template for the PGP Upload form
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
                "cyph3r/wireless_templates/wireless-pgp-upload.html",
                {"form": WirelessPGPUploadForm()},
            )
        else:
            # Render the gcp stprage form if form validation fails
            return render(
                request,
                "cyph3r/wireless_templates/wireless-gcp-storage.html",
                {"form": form},
            )


def wireless_generate_keys(request):
    """
    Validates uploaded PGP public keys
    Generates the secret key and wrap key
    Splits wrap key into key shares for 3 of 5 scheme
    Generates encrypted files for provider and security officers
    """

    # Check if the request is a POST request and includes HTMX headers
    if request.method == "POST" and request.htmx:

        # Populate the form with POST data and PGP public key files
        form = WirelessPGPUploadForm(request.POST, request.FILES)

        # Validate the form data
        if form.is_valid():
            # Retrieve key identifier, key size, protocol and key type from the session
            key_identifier = request.session["key_identifier"]
            key_size = int(request.session["key_size"])
            key_type = request.session["key_type"]
            protocol = request.session["protocol"]

            # Initialize CryptoManager for cryptographic operations
            cm = CryptoManager()

            # Generate the secret key as a random byte string of the given key size
            secret_key = cm.generate_random_key_bytes(key_size)

            # Generates a 128 bit wrap key
            # Split it into 5 shares using Shamir Secret Sharing (SSS)
            # These will be shared among 5 internal security officers (SO) for a 3 of 5 scheme
            wrap_key = cm.generate_random_key_bytes(128)
            shares = cm.shamir_split_secret(3, 5, wrap_key)

            # Generate 12 bytes nonce for the AES-GCM encryption of the secret key by the wrap key
            nonce = cm.generate_random_key_bytes(96)

            # Encrypt the secret key using the wrap key and nonce
            wrapped_secret_key = cm.encrypt_with_aes_gcm(wrap_key, nonce, secret_key)

            # Concatenate 12 bytes nonce + wrapped secret key
            # Nonce is required for AES GCM decryption
            wrapped_data = nonce + wrapped_secret_key

            # Calling helper function to write the encrypted secret key to a file and return the file name
            wrapped_secret_key_file = create_wireless_wrapped_secret_key_file(
                cm, wrapped_data, protocol, key_type
            )

            # Calling helper function to generate PGP encrypted files for the external provider
            # Each file contains the XOR share of the secret key encrypted with a provider's PGP key
            # This returns a list of the file names of the encrypted provider files for download
            provider_files = create_wireless_provider_encrypted_key_files(
                form,
                cm,
                secret_key,
                key_size,
                key_type,
                protocol,
                number_of_shares=3,
            )

            # Calling helper function to encrypt security officer (SO) files
            # Each file contains the Shamir wrap key share encrypted with a security officer's PGP key
            # This returns a list of the file names of the encrypted SO files for download
            security_officer_files = (
                create_wireless_security_officers_encrypted_key_files(
                    form,
                    cm,
                    key_type,
                    protocol,
                    shares,
                )
            )

            # Check if protocol is milenage
            # Check that the PGP key of the engineer that will be at the terminal was uploaded
            # This check is done to prevent tuak keys from being written using the PGP key of the engineer
            # Tuak keys will not be entered at a terminal and do not need to be exposed by a single person

            milenage_file = None  # Initialize the milenage file name to None
            if form.cleaned_data["milenage_public_key"] and protocol == "milenage":

                # Calling helper function to create the encrypted milenage key file
                # This returns the file name of the encrypted milenage key file for download
                milenage_file = create_wireless_milenage_encrypted_file(
                    form, cm, secret_key, key_type
                )
            """
            # Initialize GCP Manager for GCP operations
            # Wrapped keys will be stored in GCP Secrets Manager and also available for download for backup
            # The use of KMS is optional
            gcp_project_id = request.session["gcp_project_id"]
            gcp_kms_keyring = request.session["gcp_kms_keyring"]
            gcp_kms_key = request.session["gcp_kms_key"]
            secret_id = f"{protocol}-{key_type}-{key_identifier}"

            if gcp_kms_keyring == "":
                gm = GCPManager(gcp_project_id)
            else:
                gm = GCPManager(gcp_project_id, gcp_kms_keyring, gcp_kms_key)

            # Store Encrypted data (nonce + key) in GCP Secrets Manager
            gm.create_secret(secret_id=secret_id, payload=wrapped_data)
            """
            # Render the success page upon successful key generation and encryption if protocol is milenage
            if milenage_file:
                return render(
                    request,
                    "cyph3r/wireless_templates/wireless-generate-keys.html",
                    {
                        "provider_files": provider_files,
                        "milenage_file": milenage_file,
                        "security_officer_files": security_officer_files,
                        "wrapped_secret_key_file": wrapped_secret_key_file,
                    },
                )
            else:
                # Render the success page upon successful key generation and encryption if protocol is tuak
                return render(
                    request,
                    "cyph3r/wireless_templates/wireless-generate-keys.html",
                    {
                        "provider_files": provider_files,
                        "security_officer_files": security_officer_files,
                        "wrapped_secret_key_file": wrapped_secret_key_file,
                    },
                )
        else:
            # Render the PGP Upload form again with validation errors if the form is invalid
            return render(
                request,
                "cyph3r/wireless_templates/wireless-pgp-upload.html",
                {"form": form},
            )
