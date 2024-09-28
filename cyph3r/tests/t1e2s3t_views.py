import pytest
from django.urls import reverse
from django.core.files.uploadedfile import SimpleUploadedFile
from django.conf import settings
from cyph3r.crypto import CryptoManager
import random
import os


def test_index_view(client):
    """
    Test that the index view renders correctly.
    """
    url = reverse("index")  # Get the URL for the index view
    response = client.get(url)
    assert response.status_code == 200
    assert "cyph3r/index.html" in [t.name for t in response.templates]


def test_wireless_view(client):
    """
    Test that the wireless intro view renders correctly.
    """
    url = reverse("wireless")
    response = client.get(url)
    assert response.status_code == 200
    assert "cyph3r/wireless.html" in [t.name for t in response.templates]


@pytest.mark.django_db
def test_wireless_key_generation(
    cleanup_generated_files,
    client,
    pgp_public_keys,
    key_info_milenage_op,
    key_gcp_storage_data,
):
    """
    Test that the wireless_gcp_storage_form view renders correctly and validates data.
    Test that the wireless_pgp_upload_form view renders correctly and validates data.
    Test that all session data is stored correctly.
    Test that the secret key is the same for the provider, security officers and the terminal engineer.
    """
    # Get the URL for the wireless_gcp_storage_form view
    url = reverse("wireless_gcp_storage_form")

    # Post the key information data to the view
    response = client.post(url, key_info_milenage_op, HTTP_HX_REQUEST="true")

    # Check that the view returns a 200 status code and renders the correct template
    assert response.status_code == 200
    assert "cyph3r/wireless-gcp-storage.html" in [t.name for t in response.templates]

    # Check that the key milenage/op information data is stored in the session
    for key, value in key_info_milenage_op.items():
        assert client.session[key] == value

    # Get the URL for the wireless_pgp_upload_form view
    url = reverse("wireless_pgp_upload_form")

    # Post the gcp storage key details to the view
    response = client.post(url, key_gcp_storage_data, HTTP_HX_REQUEST="true")

    # Check that the view returns a 200 status code and renders the correct template
    assert response.status_code == 200
    assert "cyph3r/wireless-pgp-upload.html" in [t.name for t in response.templates]

    # Check that the key gcp storage data is stored in the session
    for key, value in key_gcp_storage_data.items():
        assert client.session[key] == value

    # Get the URL for the wireless_generate_page view
    url = reverse("wireless_generate_keys")

    # Post/upload the public keys to the view
    response = client.post(
        url, pgp_public_keys, HTTP_HX_REQUEST="true", format="multipart"
    )

    # Check that the view returns a 200 status code and renders the correct template
    assert response.status_code == 200
    assert "cyph3r/wireless-generate-keys.html" in [t.name for t in response.templates]

    # Check that context is passed correctly and contains the correct keys
    assert len(response.context["provider_files"]) == 3
    assert len(response.context["security_officer_files"]) == 5
    assert response.context["milenage_file"] is not None

    # Check that files are generated in the media directory
    assert len(os.listdir(settings.MEDIA_ROOT)) == 10

    # Initialize the CryptoManager to commence decryption of generated files
    # Get the path to the test PGP keys
    gnupghome = settings.BASE_DIR / "cyph3r" / "tests" / "pgp_test_keys"
    cm = CryptoManager(gnupghome)

    # Initialize list to store provider key shares
    provider_key_shares = []

    for file_name in response.context["provider_files"]:
        with open(os.path.join(settings.MEDIA_ROOT, file_name), "rb") as f:
            provider_encrypted_data = f.read()
            provider_decrypted_data = cm.gpg.decrypt(provider_encrypted_data)

            # Check that the decryption was successful
            assert provider_decrypted_data.ok == True

            # Retrieve the provider key shares from the decrypted data
            provider_key_share = str(provider_decrypted_data).split("\n")[5]

            # Convert to bytes
            provider_key_share_bytes = cm.hex_to_bytes(provider_key_share)

            # Append the provider key share to the list
            provider_key_shares.append(provider_key_share_bytes)

    # Reconstruct the secret key from the provider key shares
    provider_secret_key = cm.bytes_to_hex(
        cm.xor_reconstruct_secret(provider_key_shares)
    )

    # Retrieve the milenage key to be entered at terminal
    with open(
        os.path.join(settings.MEDIA_ROOT, response.context["milenage_file"]), "rb"
    ) as f:
        milenage_encrypted_data = f.read()
        milenage_decrypted_data = cm.gpg.decrypt(milenage_encrypted_data)

    # Check that the decryption was successful
    assert milenage_decrypted_data.ok == True

    # Retrieve the milenage key from the decrypted data
    milenage_secret_key = str(milenage_decrypted_data)

    # check that the decrypted milenage key and provider key are the same
    assert milenage_secret_key == provider_secret_key

    # Initialize list to store security officer key shares
    # This would be stored as a list of tuples - [(key_index, bytes(key_share))]
    security_officers_key_shares = []

    for key_index, file_name in enumerate(
        response.context["security_officer_files"], start=1
    ):
        with open(os.path.join(settings.MEDIA_ROOT, file_name), "rb") as f:
            encrypted_data = f.read()
            decrypted_data = cm.gpg.decrypt(encrypted_data)

            # Check that the decryption was successful
            assert decrypted_data.ok == True

            # Retrieve the security officer shares from the decrypted data
            key_share = str(decrypted_data).split("\n")[7]

            # Convert to bytes
            key_share_bytes = cm.hex_to_bytes(key_share)
            security_officers_key_shares.append((key_index, key_share_bytes))

    # Randomly select 3 shares to reconstruct the secret key
    random_security_officers_key_shares = random.sample(security_officers_key_shares, 3)

    # Reconstruct the wrap key from the security officer key shares
    wrap_key = cm.shamir_reconstruct_secret(random_security_officers_key_shares)

    # Get the wrapped secret key file
    with open(
        os.path.join(settings.MEDIA_ROOT, response.context["wrapped_secret_key_file"]),
        "rb",
    ) as f:
        wrapped_secret_key = f.read().split(b"\n")[-1]

    # Decrypt the wrapped secret key with the wrap key
    # Get nonce from the first 12 bytes of the wrapped secret key
    nonce = cm.hex_to_bytes(wrapped_secret_key.decode("utf-8"))[:12]

    # Get ciphertext from the rest of the wrapped secret key
    ciphertext = cm.hex_to_bytes(wrapped_secret_key.decode("utf-8"))[12:]

    decrypted_secret_key = cm.decrypt_with_aes_gcm(wrap_key, nonce, ciphertext)

    # Check that the decrypted secret key is the same as the provider secret key and milenage key

    assert decrypted_secret_key == cm.hex_to_bytes(provider_secret_key)
    assert decrypted_secret_key == cm.hex_to_bytes(milenage_secret_key)
